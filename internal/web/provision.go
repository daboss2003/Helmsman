package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/helmsman/helmsman/internal/audit"
	"github.com/helmsman/helmsman/internal/compose"
	"github.com/helmsman/helmsman/internal/dockerexec"
	"github.com/helmsman/helmsman/internal/envstore"
	"github.com/helmsman/helmsman/internal/monitor"
	"github.com/helmsman/helmsman/internal/provision"
	"github.com/helmsman/helmsman/internal/provstore"
	"github.com/helmsman/helmsman/internal/secret"
)

// M8 app provisioning (plan §7, modes 1 & 2). Mode 1 generates a safe compose
// from a typed form; Mode 2 imports a pasted compose through §5.6. Both converge
// on a 0700 staging dir + atomic rename(2) commit, then a §0-gated deploy.

const composeFileName = "docker-compose.yml"

// provisionSlugRe gates the app id BEFORE it is ever used to build a run-dir path
// (the generator validates it for Mode 1, but Mode 2/paste does not — so we
// reject an unsafe slug up front, fail-closed, on every wizard route).
var provisionSlugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

type provisionedView struct {
	Slug     string
	Source   string
	Deployed bool
	UpCount  int
	Total    int
}

func (s *Server) handleProvisionNew(w http.ResponseWriter, r *http.Request) {
	if s.provStore == nil {
		http.Error(w, "provisioning unavailable", http.StatusServiceUnavailable)
		return
	}
	s.render(w, r, "provision.html", tmplData{
		Title:               "New app",
		CSRFToken:           CSRFToken(r.Context()),
		Username:            sessionUser(r),
		WriteDisabledReason: s.writeDisabledReason(),
	})
}

// handleProvisionValidate is a DRY preview (plan §7: no write). It returns the
// candidate compose + the §5.6 result as text/plain for the in-page preview.
func (s *Server) handleProvisionValidate(w http.ResponseWriter, r *http.Request) {
	if s.provStore == nil {
		http.Error(w, "provisioning unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	slug := strings.TrimSpace(r.PostFormValue("slug"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if !provisionSlugRe.MatchString(slug) {
		fmt.Fprint(w, "rejected: app id must match [a-z][a-z0-9-]{1,30}\n")
		return
	}
	composeBytes, _, err := s.buildCandidate(r)
	if err != nil {
		fmt.Fprintf(w, "rejected: %v\n", err)
		return
	}
	// Validate the candidate against the app's prospective run dir (it need not
	// exist yet; §5.6 confinement is purely lexical+symlink-aware).
	runDir := s.appRunDir(slug)
	res := compose.ValidateBytes(composeBytes, s.provEnv(slug), runDir, compose.Options{ProtectedPaths: s.protectedHostPaths()})
	res.SortViolations()
	fmt.Fprintf(w, "# candidate compose for %q\n%s\n", slug, composeBytes)
	if res.OK() {
		fmt.Fprint(w, "\n§5.6: OK — safe to deploy\n")
		return
	}
	fmt.Fprintf(w, "\n§5.6: %d finding(s):\n", len(res.Violations))
	for _, v := range res.Violations {
		fmt.Fprintf(w, "  - %s\n", v.String())
	}
}

func (s *Server) handleProvisionCommit(w http.ResponseWriter, r *http.Request) {
	if s.provStore == nil {
		http.Error(w, "provisioning unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	slug := strings.TrimSpace(r.PostFormValue("slug"))
	if !provisionSlugRe.MatchString(slug) {
		http.Error(w, "app id must match [a-z][a-z0-9-]{1,30}", http.StatusUnprocessableEntity)
		return
	}
	if s.cfg.IsProtectedProject(slug) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	composeBytes, source, err := s.buildCandidate(r)
	if err != nil {
		http.Error(w, "rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	runDir := s.appRunDir(slug)
	// §5.6 is the hard gate on commit (defense in depth — generated is safe by
	// construction; pasted is fully untrusted).
	res := compose.ValidateBytes(composeBytes, s.provEnv(slug), runDir, compose.Options{ProtectedPaths: s.protectedHostPaths()})
	if !res.OK() && s.cfg.ComposeValidation.Mode != "review" {
		res.SortViolations()
		http.Error(w, "compose rejected by the §5.6 validator: "+res.Error(), http.StatusUnprocessableEntity)
		return
	}

	files := []provision.File{{RelPath: composeFileName, Data: composeBytes, Mode: 0o640}}
	if df := []byte(r.PostFormValue("dockerfile")); source == "inline" && len(df) > 0 {
		if _, derr := provision.ScanDockerfile(df); derr != nil {
			http.Error(w, "dockerfile rejected: "+derr.Error(), http.StatusUnprocessableEntity)
			return
		}
		files = append(files, provision.File{RelPath: "Dockerfile", Data: df, Mode: 0o640})
	}
	if err := provision.Commit(s.appsRoot(), runDir, files); err != nil {
		s.log.Error("provision commit failed", "slug", slug, "err", err)
		http.Error(w, "commit failed", http.StatusInternalServerError)
		return
	}

	// Persist env literals (Mode 1) into the encrypted store — never baked in YAML.
	if source == "generated" && s.envStore != nil {
		if entries := parseEnvLiterals(r.PostFormValue("env")); len(entries) > 0 {
			if _, eerr := s.envStore.Save(r.Context(), slug, entries, actor); eerr != nil {
				s.log.Warn("provision: saving env literals failed", "slug", slug, "err", eerr)
			}
		}
	}

	specJSON := ""
	if source == "generated" {
		if spec, _, berr := s.buildMode1Spec(r); berr == nil {
			if b, merr := json.Marshal(spec); merr == nil {
				specJSON = string(b)
			}
		}
	}
	if err := s.provStore.Save(r.Context(), provstore.App{Slug: slug, Source: source, ComposePath: composeFileName, SpecJSON: specJSON}); err != nil {
		// Don't leave an orphan run dir if the registry write fails (confined remove).
		if confinedUnder(runDir, s.appsRoot()) && filepath.Dir(filepath.Clean(runDir)) == filepath.Clean(s.appsRoot()) {
			_ = os.RemoveAll(runDir)
		}
		http.Error(w, "could not register app: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "provision_commit", Target: slug, Outcome: audit.OK, Level: audit.Security, Detail: source})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleProvisionDeploy brings a committed provisioned app up — a §0-gated
// write-plane action: §5.6 the on-disk compose, materialize config files + env,
// then `docker compose up` under the one-docker-child semaphore.
func (s *Server) handleProvisionDeploy(w http.ResponseWriter, r *http.Request) {
	if s.provStore == nil || s.runner == nil {
		http.Error(w, "write plane unavailable", http.StatusServiceUnavailable)
		return
	}
	slug := r.PathValue("project")
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	if s.cfg.IsProtectedProject(slug) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	app, ok, err := s.provStore.Get(slug)
	if err != nil || !ok {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	if allowed, reason := s.runner.WriteAllowed(); !allowed {
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	if !s.gitDeploy.TryAcquire() { // shared single-flight with git deploys
		http.Error(w, "a deploy is already in progress; try again shortly", http.StatusConflict)
		return
	}
	defer s.gitDeploy.Release()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, _ := w.(http.Flusher)
	writeln := func(format string, a ...any) {
		fmt.Fprintf(w, format+"\n", a...)
		if flusher != nil {
			flusher.Flush()
		}
	}

	runDir := s.appRunDir(slug)
	composeAbs := filepath.Join(runDir, filepath.FromSlash(app.ComposePath))
	mapp := &monitor.App{Project: slug, WorkingDir: runDir, ConfigFiles: []string{composeAbs}}
	env := s.composeEnv(mapp)

	writeln("$ deploy %s", slug)
	if res := s.validateAppCompose(mapp, env); !res.OK() {
		if s.cfg.ComposeValidation.Mode != "review" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			writeln("deploy blocked by the §5.6 compose validator:")
			for _, v := range res.Violations {
				writeln("  - %s", v.String())
			}
			_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "provision_deploy", Target: slug, Outcome: audit.Deny, Level: audit.Security, Detail: "compose validation failed"})
			return
		}
		writeln("WARNING (review mode): %d validator finding(s); proceeding.", len(res.Violations))
	}
	if err := s.materializeConfigFiles(mapp, env); err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeln("deploy blocked: %v", err)
		return
	}
	envFile, cleanup, ferr := s.renderEnvFile(mapp, env)
	defer cleanup()
	if ferr != nil {
		writeln("could not render env file")
		return
	}
	depID := s.recordRepoDeployStart(context.Background(), slug, "provision", actor, "deploy")
	writeln("$ docker compose up -d --remove-orphans")
	job := dockerexec.Job{Project: slug, Dir: runDir, ConfigFiles: mapp.ConfigFiles, EnvFile: envFile, Action: []string{"up", "-d", "--remove-orphans"}}
	runErr := s.runner.Run(r.Context(), job, func(line string) { writeln("%s", line) })
	code, outcome := classifyExit(runErr)
	s.recordDeployFinish(context.Background(), depID, code, outcome)
	if runErr != nil {
		writeln("\n[failed: %v]", runErr)
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "provision_deploy", Target: slug, Outcome: audit.Error, Level: audit.Security})
		return
	}
	writeln("\n[done]")
	_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "provision_deploy", Target: slug, Outcome: audit.OK, Level: audit.Security})
}

// handleProvisionDelete tears down a provisioned app: best-effort `compose down`,
// remove the run dir, drop the registry row. (Env/config rows are left for now;
// a full purge lands with backup/restore in M18.)
func (s *Server) handleProvisionDelete(w http.ResponseWriter, r *http.Request) {
	if s.provStore == nil {
		http.Error(w, "provisioning unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	slug := r.PathValue("project")
	if s.cfg.IsProtectedProject(slug) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	app, ok, _ := s.provStore.Get(slug)
	if !ok {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	runDir := s.appRunDir(slug)
	// Best-effort stop (only if the write plane is armed and free).
	if s.runner != nil {
		if allowed, _ := s.runner.WriteAllowed(); allowed && s.gitDeploy.TryAcquire() {
			composeAbs := filepath.Join(runDir, filepath.FromSlash(app.ComposePath))
			job := dockerexec.Job{Project: slug, Dir: runDir, ConfigFiles: []string{composeAbs}, Action: []string{"down", "--remove-orphans"}}
			_ = s.runner.Run(r.Context(), job, func(string) {})
			s.gitDeploy.Release()
		}
	}
	// Remove the run dir, confined under appsRoot (defense-in-depth).
	if confinedUnder(runDir, s.appsRoot()) && filepath.Dir(filepath.Clean(runDir)) == filepath.Clean(s.appsRoot()) {
		_ = os.RemoveAll(runDir)
	}
	_ = s.provStore.Delete(r.Context(), slug)
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "provision_delete", Target: slug, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- candidate building ---

// buildCandidate returns the compose bytes + source ("generated"|"inline") for
// the current form, without writing anything.
func (s *Server) buildCandidate(r *http.Request) (composeBytes []byte, source string, err error) {
	switch r.PostFormValue("mode") {
	case "inline":
		pasted := []byte(r.PostFormValue("compose"))
		if len(pasted) == 0 {
			return nil, "inline", fmt.Errorf("paste a compose file")
		}
		if len(pasted) > provision.MaxPasteBytes {
			return nil, "inline", provision.ErrPasteTooLarge
		}
		return pasted, "inline", nil
	default: // generated (Mode 1)
		spec, _, serr := s.buildMode1Spec(r)
		if serr != nil {
			return nil, "generated", serr
		}
		out, gerr := provision.Generate(spec)
		if gerr != nil {
			return nil, "generated", gerr
		}
		return out, "generated", nil
	}
}

// buildMode1Spec parses the guided form into a single-service Spec (the common
// case). Multi-service apps use Mode 2 (paste). Env literals are returned for the
// encrypted store; only their KEYS go into the generated compose.
func (s *Server) buildMode1Spec(r *http.Request) (provision.Spec, []envstore.Entry, error) {
	slug := strings.TrimSpace(r.PostFormValue("slug"))
	svc := provision.Service{
		Name:    "app",
		Image:   strings.TrimSpace(r.PostFormValue("image")),
		Restart: strings.TrimSpace(r.PostFormValue("restart")),
	}
	publish := r.PostFormValue("publish") == "on"
	public := r.PostFormValue("public") == "on"
	for _, tok := range strings.Split(r.PostFormValue("ports"), ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, perr := strconv.Atoi(tok)
		if perr != nil {
			return provision.Spec{}, nil, fmt.Errorf("port %q is not a number", tok)
		}
		svc.Ports = append(svc.Ports, provision.Port{Internal: n, Publish: publish, Public: public})
	}
	svc.Volumes = parseVolumeLines(r.PostFormValue("volumes"))
	literals := parseEnvLiterals(r.PostFormValue("env"))
	for _, e := range literals {
		svc.EnvKeys = append(svc.EnvKeys, e.Key)
	}
	if hc := strings.Fields(r.PostFormValue("healthcheck")); len(hc) > 0 {
		svc.Healthcheck = hc
	}
	return provision.Spec{Slug: slug, Services: []provision.Service{svc}}, literals, nil
}

// parseVolumeLines parses "source:/target[:ro]" lines into typed volumes. A
// source beginning with "." is a run_dir bind; otherwise a named volume.
func parseVolumeLines(s string) []provision.Volume {
	var out []provision.Volume
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		v := provision.Volume{Target: parts[1]}
		if len(parts) >= 3 && parts[2] == "ro" {
			v.ReadOnly = true
		}
		src := parts[0]
		if strings.HasPrefix(src, ".") {
			v.Source = strings.TrimPrefix(strings.TrimPrefix(src, "./"), ".")
		} else {
			v.Name = src
		}
		out = append(out, v)
	}
	return out
}

// parseEnvLiterals parses KEY=VALUE lines into non-secret env entries.
func parseEnvLiterals(s string) []envstore.Entry {
	var out []envstore.Entry
	for k, v := range compose.ParseEnvFile([]byte(s)) {
		out = append(out, envstore.Entry{Key: k, Value: secret.New(v), Secret: false})
	}
	return out
}

// provEnv builds the env used to validate a candidate (the encrypted store only;
// a not-yet-committed app has no on-disk .env). Resolved to a fixpoint so
// validate == deploy.
func (s *Server) provEnv(slug string) compose.Env {
	env := compose.Env{}
	if s.envStore != nil {
		if rendered, err := s.envStore.Render(slug); err == nil {
			for k, v := range rendered {
				env[k] = v
			}
		}
	}
	return resolveEnvValues(env)
}

// provisionedApps returns the registry rows annotated with live deploy status
// from the snapshot (for the home "Provisioned apps" panel).
func (s *Server) provisionedApps() []provisionedView {
	if s.provStore == nil {
		return nil
	}
	apps, err := s.provStore.List()
	if err != nil {
		return nil
	}
	snap := s.snapshot()
	var out []provisionedView
	for _, a := range apps {
		v := provisionedView{Slug: a.Slug, Source: a.Source}
		if snap != nil {
			if app := snap.AppByProject(a.Slug); app != nil {
				v.Deployed = true
				v.UpCount = app.UpCount()
				v.Total = app.Total()
			}
		}
		out = append(out, v)
	}
	return out
}
