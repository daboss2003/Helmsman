package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/daboss2003/Helmsman/internal/audit"
	"github.com/daboss2003/Helmsman/internal/cfgfile"
	"github.com/daboss2003/Helmsman/internal/cfgstore"
	"github.com/daboss2003/Helmsman/internal/compose"
	"github.com/daboss2003/Helmsman/internal/monitor"
)

type configFileView struct {
	Service       string // canonical: the service this file mounts into ("" for legacy)
	Name          string // display: legacy name, or the mount basename (canonical)
	RelPath       string // legacy rel_path (display)
	Mount         string // canonical container mount
	Source        string // canonical: "(inline)" or the repo path
	Bindings      []bindingView
	SecretBearing bool
	Mode          string
	Drift         string // "", "ok", "host-edited", "not-rendered"
}

// bindingView is the display form of one {{hm.KEY}} binding: "key" + its source
// string ("secret:NAME", "env:NAME", "app:slug", "cert:HOST.field", "literal:VALUE").
type bindingView struct{ Key, Source string }

type certBindingView struct {
	Service     string // canonical: the service the cert mounts into ("" for legacy)
	BindingName string // legacy binding name
	Hostname    string
	SyncDirRel  string // legacy sync dir (display)
	Mount       string // canonical container mount
	Required    bool
}

func (s *Server) handleConfigFilesGet(w http.ResponseWriter, r *http.Request) {
	if s.cfgStore == nil {
		http.Error(w, "config files unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	data := tmplData{
		Title:     "Config files — " + project,
		CSRFToken: CSRFToken(r.Context()),
		Username:  sessionUser(r),
		Project:   project,
		BackURL:   s.appBackURL(project),
	}
	var app *monitor.App
	if snap := s.snapshot(); snap != nil {
		app = snap.AppByProject(project)
	}
	// Canonical-first: an app with a helmsman.yaml authors config files + cert
	// bindings PER SERVICE in the canonical (the source of truth). Legacy
	// provisioned apps (no canonical) keep the app-level cfgStore editor.
	if def := s.currentDef(project); def != nil {
		s.populateCanonicalConfig(&data, def, project)
		s.render(w, r, "config_files.html", data)
		return
	}
	files, _ := s.cfgStore.ConfigFiles(project)
	for _, f := range files {
		v := configFileView{Name: f.Name, RelPath: f.RelPath, Bindings: legacyBindingViews(f.Bindings), SecretBearing: f.SecretBearing, Mode: fmt.Sprintf("%#o", f.Mode)}
		v.Drift = s.configDrift(app, f)
		data.ManagedFiles = append(data.ManagedFiles, v)
	}
	certs, _ := s.cfgStore.CertBindings(project)
	for _, c := range certs {
		data.CertBindings = append(data.CertBindings, certBindingView{BindingName: c.BindingName, Hostname: c.Hostname, SyncDirRel: c.SyncDirRel, Required: c.Required})
	}
	s.render(w, r, "config_files.html", data)
}

// legacyBindingViews renders cfgStore bindings (Key + "kind:arg" Source) for display.
func legacyBindingViews(bs []cfgfile.Binding) []bindingView {
	out := make([]bindingView, 0, len(bs))
	for _, b := range bs {
		out = append(out, bindingView{Key: b.Key, Source: b.Source})
	}
	return out
}

// configDrift compares the on-disk file's sha to the last rendered sha.
func (s *Server) configDrift(app *monitor.App, f cfgstore.ConfigFile) string {
	if app == nil || app.WorkingDir == "" {
		return ""
	}
	if f.RenderedSHA256 == "" {
		return "not-rendered"
	}
	b, err := os.ReadFile(filepath.Join(app.WorkingDir, f.RelPath))
	if err != nil {
		return "missing"
	}
	if sha256Hex(b) == f.RenderedSHA256 {
		return "ok"
	}
	return "host-edited"
}

func (s *Server) handleConfigFileSave(w http.ResponseWriter, r *http.Request) {
	if s.cfgStore == nil {
		http.Error(w, "config files unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	project := r.PathValue("project")
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	// Canonical-first write-back: author the file into its service's config_files in
	// the canonical helmsman.yaml, then reconcile. Falls back to the legacy cfgStore.
	if def := s.currentDef(project); def != nil {
		s.saveCanonicalConfigFile(w, r, def, project)
		return
	}
	in := cfgstore.SaveInput{
		Name:     r.PostFormValue("name"),
		RelPath:  r.PostFormValue("rel_path"),
		Template: r.PostFormValue("template"),
		Bindings: parseBindingsForm(r.PostFormValue("bindings")),
	}
	if err := s.cfgStore.SaveConfigFile(r.Context(), project, in); err != nil {
		if errors.Is(err, cfgstore.ErrInternal) {
			http.Error(w, "internal error", http.StatusInternalServerError)
		} else {
			http.Error(w, "config file rejected: "+err.Error(), http.StatusUnprocessableEntity)
		}
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "config_file_save", Target: project + "/" + in.Name, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
}

func (s *Server) handleConfigFileDelete(w http.ResponseWriter, r *http.Request) {
	if s.cfgStore == nil {
		http.Error(w, "config files unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	if def := s.currentDef(project); def != nil {
		s.deleteCanonicalConfigFile(w, r, def, project)
		return
	}
	_ = s.cfgStore.DeleteConfigFile(r.Context(), project, r.PostFormValue("name"))
	http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
}

// handleConfigFilePreview renders the template with secret bindings shown as
// masked placeholders — the dashboard never transmits a secret byte (plan §7.4).
func (s *Server) handleConfigFilePreview(w http.ResponseWriter, r *http.Request) {
	if s.cfgStore == nil {
		http.Error(w, "config files unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	tmpl := []byte(r.PostFormValue("template"))
	bindings := parseBindingsForm(r.PostFormValue("bindings"))
	if err := cfgfile.ValidateBindings(bindings); err != nil {
		http.Error(w, "binding error: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	byKey := map[string]cfgfile.Binding{}
	for _, b := range bindings {
		byKey[b.Key] = b
	}
	out, _, err := cfgfile.Render(tmpl, func(key string) (string, bool, error) {
		b, ok := byKey[key]
		if !ok {
			return "", false, cfgfile.ErrUnknownBinding
		}
		kind, arg, perr := cfgfile.ParseSource(b.Source)
		if perr != nil {
			return "", false, perr
		}
		// Masked placeholder for secrets; structural stand-in for others.
		return fmt.Sprintf("‹%s:%s›", kind, arg), kind == "secret", nil
	})
	if err != nil {
		http.Error(w, "preview error: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(out)
}

func (s *Server) handleCertBindingSave(w http.ResponseWriter, r *http.Request) {
	if s.cfgStore == nil {
		http.Error(w, "config files unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	if def := s.currentDef(project); def != nil {
		s.saveCanonicalCertBinding(w, r, def, project)
		return
	}
	cb := cfgstore.CertBinding{
		BindingName: r.PostFormValue("binding_name"),
		Hostname:    r.PostFormValue("hostname"),
		SyncDirRel:  r.PostFormValue("sync_dir_rel"),
		Required:    r.PostFormValue("required") == "on",
	}
	if err := s.cfgStore.SaveCertBinding(r.Context(), project, cb); err != nil {
		http.Error(w, "cert binding rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "cert_binding_save", Target: project + "/" + cb.BindingName, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
}

func (s *Server) handleCertBindingDelete(w http.ResponseWriter, r *http.Request) {
	if s.cfgStore == nil {
		http.Error(w, "config files unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	if def := s.currentDef(project); def != nil {
		s.deleteCanonicalCertBinding(w, r, def, project)
		return
	}
	_ = s.cfgStore.DeleteCertBinding(r.Context(), project, r.PostFormValue("binding_name"))
	http.Redirect(w, r, "/apps/"+project+"/config-files", http.StatusSeeOther)
}

// parseBindingsForm parses "key=source" lines into bindings.
func parseBindingsForm(s string) []cfgfile.Binding {
	var out []cfgfile.Binding
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			out = append(out, cfgfile.Binding{Key: strings.TrimSpace(line[:i]), Source: strings.TrimSpace(line[i+1:])})
		}
	}
	return out
}

// --- deploy-time materialization (plan §7.4) ---

// materializeConfigFiles resolves + renders every managed config file for an app
// and writes it atomically under run_dir with forced 0640/0600, recording the
// rendered sha. It also enforces the cert-wait ordering gate. Any missing binding
// key, unsafe value, or missing required cert is a HARD failure before `up`.
func (s *Server) materializeConfigFiles(app *monitor.App, env compose.Env) error {
	if s.cfgStore == nil {
		return nil
	}
	runDir := filepath.Clean(app.WorkingDir)
	// run_dir sanity, independent of compose validation (review #4): refuse a
	// missing/relative/sensitive run_dir even in compose "review" mode.
	if app.WorkingDir == "" || !filepath.IsAbs(runDir) || runDir == "/" || isSensitiveDir(runDir) {
		return fmt.Errorf("app working directory %q is missing or unsafe; refusing to materialize", app.WorkingDir)
	}

	files, err := s.cfgStore.ConfigFiles(app.Project)
	if err != nil {
		return err
	}
	certs, err := s.cfgStore.CertBindings(app.Project)
	if err != nil {
		return err
	}
	certByName := map[string]cfgstore.CertBinding{}
	for _, c := range certs {
		certByName[c.BindingName] = c
	}

	// Cert-wait ordering gate (plan §7.5): required cert files must already exist.
	// Gate the union of {crt,key} and any fields actually referenced by config
	// files (so cert:<b>.ca is gated iff used — review #7). Symlink-safe (review #9).
	for _, cb := range certs {
		if !cb.Required {
			continue
		}
		for _, fn := range gatedCertFiles(cb.BindingName, files) {
			p := filepath.Join(runDir, cb.SyncDirRel, fn)
			if !confinedUnder(p, runDir) {
				return fmt.Errorf("cert binding %q sync dir escapes the app directory", cb.BindingName)
			}
			fi, err := os.Lstat(p) // no-follow: a symlink doesn't satisfy the gate
			if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
				return fmt.Errorf("cert binding %q (%s): required cert %s not present yet; deploy blocked (the managed edge issues it in M11)", cb.BindingName, cb.Hostname, fn)
			}
		}
	}

	for _, f := range files {
		resolver := s.bindingResolver(app, env, f.Bindings, certByName, runDir)
		out, _, rerr := cfgfile.Render([]byte(f.Template.Reveal()), resolver)
		if rerr != nil {
			return fmt.Errorf("config file %q: %w", f.Name, rerr)
		}
		dest := filepath.Join(runDir, f.RelPath)
		// Symlink-resolving confinement (review #1): a parent-symlink can't
		// redirect the write outside run_dir.
		if !confinedUnder(dest, runDir) {
			return fmt.Errorf("config file %q path escapes the app directory", f.Name)
		}
		// Defense-in-depth (review #3): if a non-secret-bearing file's RENDERED
		// output trips the literal-secret lint (e.g. a secret bound via env:),
		// tighten to 0600 rather than leave it group-readable.
		mode := os.FileMode(f.Mode)
		if !f.SecretBearing {
			if _, hit := cfgfile.LiteralSecretLint(out); hit {
				mode = 0o600
			}
		}
		if err := atomicWrite(dest, out, mode, runDir); err != nil {
			return fmt.Errorf("config file %q: %w", f.Name, err)
		}
		s.cfgStore.SetRenderedSHA(context.Background(), app.Project, f.Name, sha256Hex(out))
	}
	return nil
}

// gatedCertFiles returns the cert filenames to gate for a binding: crt+key
// always, plus tls.ca iff a config file references cert:<binding>.ca.
func gatedCertFiles(binding string, files []cfgstore.ConfigFile) []string {
	out := []string{"tls.crt", "tls.key"}
	for _, f := range files {
		for _, b := range f.Bindings {
			if kind, arg, err := cfgfile.ParseSource(b.Source); err == nil && kind == "cert" {
				name, field, _ := strings.Cut(arg, ".")
				if name == binding && field == "ca" {
					return append(out, "tls.ca")
				}
			}
		}
	}
	return out
}

// bindingResolver builds the typed resolver for one file's bindings.
func (s *Server) bindingResolver(app *monitor.App, env compose.Env, bindings []cfgfile.Binding, certByName map[string]cfgstore.CertBinding, runDir string) cfgfile.Resolver {
	byKey := map[string]cfgfile.Binding{}
	for _, b := range bindings {
		byKey[b.Key] = b
	}
	return func(key string) (string, bool, error) {
		b, ok := byKey[key]
		if !ok {
			return "", false, cfgfile.ErrUnknownBinding
		}
		kind, arg, err := cfgfile.ParseSource(b.Source)
		if err != nil {
			return "", false, err
		}
		switch kind {
		case "env":
			v, ok := env[arg]
			if !ok {
				return "", false, fmt.Errorf("env key %q not set", arg)
			}
			return v, false, nil // an empty literal is a legitimate value
		case "secret":
			v, ok := env[arg]
			if !ok || v == "" {
				// A missing OR empty secret fails closed — never silently emit an
				// empty value that could disable auth in the config (review #2).
				return "", false, fmt.Errorf("secret %q is not set (or empty)", arg)
			}
			return v, true, nil // marks the file secret-bearing
		case "app":
			switch arg {
			case "slug":
				return app.Project, false, nil
			default:
				return "", false, fmt.Errorf("app field %q not available yet (edge fields land in M11)", arg)
			}
		case "cert":
			name, field, _ := strings.Cut(arg, ".")
			cb, ok := certByName[name]
			if !ok {
				return "", false, fmt.Errorf("cert binding %q not defined", name)
			}
			fn := map[string]string{"crt": "tls.crt", "key": "tls.key", "ca": "tls.ca"}[field]
			return filepath.Join(runDir, cb.SyncDirRel, fn), false, nil
		}
		return "", false, cfgfile.ErrUnknownBinding
	}
}

// atomicWrite writes data to dest via a temp file + fchmod + rename, confined
// under runDir. After creating the parent chain it re-verifies no component is a
// symlink and the dir still resolves under runDir (TOCTOU guard, review #1).
func atomicWrite(dest string, data []byte, mode os.FileMode, runDir string) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := noSymlinkComponents(dest, runDir); err != nil {
		return err
	}
	if !confinedUnder(dir, runDir) {
		return fmt.Errorf("destination directory escapes the app directory")
	}
	tmp, err := os.CreateTemp(dir, ".hmcfg-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op if the rename succeeded
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, dest)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
