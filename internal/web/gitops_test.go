package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/Helmsman/internal/dockerexec"
	"github.com/daboss2003/Helmsman/internal/envstore"
	"github.com/daboss2003/Helmsman/internal/gitstore"
	"github.com/daboss2003/Helmsman/internal/secret"
)

// repoHelmsmanYAML is a clean generated-stack definition committed into test repos —
// Helmsman generates the compose from this (the repo never supplies a compose).
const repoHelmsmanYAML = `apiVersion: helmsman/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      web:
        image: nginx:1.27
`

// gitObjStoreFixture builds a real git commit (with the given helmsman.yaml) and
// clones it --bare into objDir, pointing refs/helmsman/staged at it.
func gitObjStoreFixture(t *testing.T, objDir, helmsmanYAML string) string {
	return gitObjStoreFixtureFiles(t, objDir, map[string]string{"helmsman.yaml": helmsmanYAML})
}

// gitObjStoreFixtureFiles commits an arbitrary file set, then clones it --bare into
// objDir — mimicking what a fetch would leave. The hardened Repo only READS this store.
func gitObjStoreFixtureFiles(t *testing.T, objDir string, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	run := func(dir string, args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	work := t.TempDir()
	run(work, "init", "-q", "-b", "main")
	for name, content := range files {
		p := filepath.Join(work, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run(work, "add", "-A")
	run(work, "commit", "-q", "-m", "init")
	sha := run(work, "rev-parse", "HEAD")
	if err := os.MkdirAll(filepath.Dir(objDir), 0o700); err != nil {
		t.Fatal(err)
	}
	run(work, "clone", "--bare", "-q", work, objDir)
	run(work, "--git-dir="+objDir, "update-ref", "refs/helmsman/staged", sha)
	return sha
}

func configureRepo(t *testing.T, e *testEnv, slug, sha string) gitstore.Config {
	t.Helper()
	ctx := context.Background()
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{
		Project: slug, RepoURL: "https://nonexistent.invalid/o/r.git",
		Ref: "refs/heads/main", ComposePath: "docker-compose.yml", BuildPolicy: "never",
	}); err != nil {
		t.Fatal(err)
	}
	e.srv.gitStore.SetFetchResult(ctx, slug, sha, 1, "update_available")
	cfg, ok, err := e.srv.gitStore.Get(slug)
	if err != nil || !ok {
		t.Fatalf("get repo cfg: %v ok=%v", err, ok)
	}
	return cfg
}

// The run dir (where app binds live) must be OUTSIDE DataDir so legitimate binds
// under it don't trip the "DataDir is protected" §5.6 defense-in-depth check; the
// object store must be INSIDE DataDir (protected — no app can bind it).
func TestGitRunDirOutsideDataDirObjectStoreInside(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	rd := e.srv.appRunDir("shop")
	od := e.srv.gitObjectDir("shop")
	if pathUnder(rd, e.srv.cfg.DataDir) {
		t.Errorf("run dir %q is under DataDir %q — binds under it would be wrongly rejected", rd, e.srv.cfg.DataDir)
	}
	if !pathUnder(od, e.srv.cfg.DataDir) {
		t.Errorf("object store %q must be under DataDir %q (protected)", od, e.srv.cfg.DataDir)
	}
}

// A deploy is sha-PINNED: if the staged ref moved since the operator reviewed it,
// the promote aborts (no surprise commit goes live).
func TestDeployRejectsMovedStagedSha(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	slug := "shop"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), repoHelmsmanYAML)
	cfg := configureRepo(t, e, slug, sha)

	// Ask to deploy a DIFFERENT (well-formed) sha than the one staged.
	other := "0123456789abcdef0123456789abcdef01234567"
	err := e.srv.deployRepoApp(context.Background(), cfg, other, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("expected staged-moved rejection, got %v", err)
	}
}

// Helmsman OWNS the compose: a repo's own docker-compose.yml is IGNORED — the deploy
// GENERATES the compose from helmsman.yaml, so a dangerous repo compose never reaches
// docker. (Write plane disabled so `up` fails fast AFTER generation.)
func TestDeployIgnoresRepoComposeUsesHelmsmanYAML(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	dangerous := "services:\n  web:\n    image: nginx\n    privileged: true\n"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"helmsman.yaml":      repoHelmsmanYAML,
		"docker-compose.yml": dangerous,
	})
	cfg := configureRepo(t, e, slug, sha)

	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write plane disabled) AFTER generation, got %v", err)
	}
	out, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml"))
	if rerr != nil {
		t.Fatalf("generated compose missing from run dir: %v", rerr)
	}
	if strings.Contains(string(out), "privileged") {
		t.Errorf("the repo's dangerous docker-compose.yml must be IGNORED (Helmsman generates from helmsman.yaml):\n%s", out)
	}
	if !strings.Contains(string(out), "nginx") {
		t.Errorf("generated compose should carry the helmsman.yaml image:\n%s", out)
	}
}

// A valid sha-pinned promote with a clean compose runs steps 1–4 (sha-pin →
// §5.6 → archive-extract → materialize) and lands the pinned tree in the
// Helmsman-owned run dir BEFORE `docker compose up`. We use a write-DISABLED
// runner so `up` fails fast (ErrWritePlaneDisabled) — no real docker is touched.
func TestDeployArchivesBeforeUp(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), repoHelmsmanYAML)
	cfg := configureRepo(t, e, slug, sha)

	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write plane disabled), got %v", err)
	}
	// The pinned tree must have been checked out AND the generated compose written
	// into the run dir before `up`.
	out, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml"))
	if rerr != nil || !strings.Contains(string(out), "image: nginx") {
		t.Errorf("generated compose not written into run dir: %v %q", rerr, out)
	}
}

// A build service in the repo's helmsman.yaml: deploy GENERATES the Dockerfile into
// the run dir and the compose references it (build: + .helmsman/Dockerfile.<svc>).
func TestDeployBuildServiceGeneratesDockerfile(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	yaml := "apiVersion: helmsman/v1\nkind: App\nmetadata: {slug: app}\nspec:\n  compose:\n    source: generated\n    services:\n      api:\n        build: {language: go}\n"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"helmsman.yaml": yaml,
		"go.mod":        "module x\n\ngo 1.23\n",
		"main.go":       "package main\nfunc main(){}\n",
	})
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write disabled) after generation, got %v", err)
	}
	df, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), ".helmsman", "Dockerfile.api"))
	if rerr != nil || !strings.Contains(string(df), "golang:") {
		t.Errorf("generated Dockerfile missing/wrong: %v\n%s", rerr, df)
	}
	cmp, _ := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml"))
	if !strings.Contains(string(cmp), "build:") || !strings.Contains(string(cmp), ".helmsman/Dockerfile.api") {
		t.Errorf("compose must reference the generated Dockerfile:\n%s", cmp)
	}
}

// No helmsman.yaml in the repo → Helmsman scaffolds a default from the detected stack
// (go.mod → a go build service) and generates the Dockerfile.
func TestDeployScaffoldsWhenNoHelmsmanYAML(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"go.mod":  "module x\n\ngo 1.23\n",
		"main.go": "package main\nfunc main(){}\n",
	})
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected scaffold→generate→up-fail, got %v", err)
	}
	df, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), ".helmsman", "Dockerfile.app"))
	if rerr != nil || !strings.Contains(string(df), "golang:") {
		t.Errorf("scaffold should generate a go Dockerfile: %v\n%s", rerr, df)
	}
}

// A bind volume's source dir is pre-created (Helmsman-owned) under the run dir before
// `up`, so Docker doesn't create a missing one as root.
func TestDeployCreatesBindDirs(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	yaml := "apiVersion: helmsman/v1\nkind: App\nmetadata: {slug: app}\nspec:\n  compose:\n    source: generated\n    services:\n      web:\n        image: nginx:1.27\n        volumes:\n          - {source: appdata, target: /var/lib/app}\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), yaml)
	cfg := configureRepo(t, e, slug, sha)
	_ = e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	info, err := os.Stat(filepath.Join(e.srv.appRunDir(slug), "appdata"))
	if err != nil || !info.IsDir() {
		t.Errorf("bind source dir not pre-created: %v", err)
	}
}

// materializeBindDirs must refuse a symlinked bind source (it could be swapped to
// escape the run dir) and create a normal source as a real directory.
func TestMaterializeBindDirsSymlinkSafe(t *testing.T) {
	rd := t.TempDir()
	outside := t.TempDir()
	// symlink pointing OUTSIDE rd → rejected (confinedUnder resolves it).
	if err := os.Symlink(outside, filepath.Join(rd, "evil")); err != nil {
		t.Fatal(err)
	}
	if err := materializeBindDirs(rd, []string{"evil"}); err == nil {
		t.Error("a bind source symlinked outside the run dir must be rejected")
	}
	// symlink pointing INSIDE rd → still rejected (a symlink bind source is refused).
	_ = os.MkdirAll(filepath.Join(rd, "real"), 0o750)
	if err := os.Symlink(filepath.Join(rd, "real"), filepath.Join(rd, "inlink")); err != nil {
		t.Fatal(err)
	}
	if err := materializeBindDirs(rd, []string{"inlink"}); err == nil {
		t.Error("a symlinked bind source must be rejected even when it points inside the run dir")
	}
	// a normal source is created as a real directory.
	if err := materializeBindDirs(rd, []string{"data"}); err != nil {
		t.Fatalf("a normal bind dir should be created: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(rd, "data")); err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("data must be created as a real directory: %v", err)
	}
}

// config_files (from the repo) and secret_files (from the store) are materialized into
// the run dir at the managed paths, and the generated compose carries their RO mounts.
func TestDeployMaterializesConfigAndSecretFiles(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	if _, err := e.srv.envStore.Save(context.Background(), slug,
		[]envstore.Entry{{Key: "jwt", Value: secret.New("SECRETVAL"), Secret: true}}, "op"); err != nil {
		t.Fatal(err)
	}
	yaml := "apiVersion: helmsman/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
		"  compose:\n    source: generated\n    services:\n      web:\n        image: nginx:1.27\n" +
		"        config_files:\n          - {repo: conf/app.conf, mount: /etc/app.conf}\n" +
		"        secret_files: [jwt]\n  secrets: [{name: jwt}]\n"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"helmsman.yaml": yaml,
		"conf/app.conf": "marker-config\n",
	})
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write disabled) AFTER materialization, got %v", err)
	}
	rd := e.srv.appRunDir(slug)
	cf, rerr := os.ReadFile(filepath.Join(rd, ".helmsman", "cfg", "web", "0"))
	if rerr != nil || string(cf) != "marker-config\n" {
		t.Errorf("config file not materialized: %v %q", rerr, cf)
	}
	sf := filepath.Join(rd, ".helmsman", "secrets", "web", "jwt")
	sb, serr := os.ReadFile(sf)
	if serr != nil || string(sb) != "SECRETVAL" {
		t.Errorf("secret file not materialized: %v %q", serr, sb)
	}
	if fi, _ := os.Stat(sf); fi != nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("secret file mode = %v, want 0600", fi.Mode().Perm())
	}
	cmp, _ := os.ReadFile(filepath.Join(rd, "docker-compose.yml"))
	for _, want := range []string{"/etc/app.conf:ro", "/run/secrets/jwt:ro"} {
		if !strings.Contains(string(cmp), want) {
			t.Errorf("generated compose missing managed mount %q:\n%s", want, cmp)
		}
	}
}

// A secret_files reference with no stored value blocks the deploy (fail-closed).
func TestDeploySecretFileWithoutValueBlocks(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	yaml := "apiVersion: helmsman/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
		"  compose:\n    source: generated\n    services:\n      web:\n        image: nginx:1.27\n" +
		"        secret_files: [jwt]\n  secrets: [{name: jwt}]\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), yaml)
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "set it before deploying") {
		t.Fatalf("a secret_files ref with no value must block the deploy, got %v", err)
	}
}

// No helmsman.yaml AND an undetectable stack → rejected with guidance (no deploy).
func TestDeployRejectsUndetectableRepoWithoutHelmsmanYAML(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	slug := "shop"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{"README.md": "hi\n"})
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "helmsman.yaml") {
		t.Fatalf("an undetectable repo without helmsman.yaml must be rejected with guidance, got %v", err)
	}
}

func TestVerifyWebhookSig(t *testing.T) {
	secret := []byte("super-secret-key")
	now := time.Now().Unix()
	ts := strconv.FormatInt(now, 10)
	nonce := "nonce-123"
	sign := func(s []byte, ts, nonce string) string {
		m := hmac.New(sha256.New, s)
		m.Write([]byte(ts + "." + nonce))
		return hex.EncodeToString(m.Sum(nil))
	}
	good := sign(secret, ts, nonce)

	if !verifyWebhookSig(secret, ts, nonce, good) {
		t.Error("valid signature rejected")
	}
	if verifyWebhookSig(secret, ts, nonce, "deadbeef") {
		t.Error("garbage signature accepted")
	}
	if verifyWebhookSig([]byte("wrong-key"), ts, nonce, good) {
		t.Error("signature accepted under the wrong key")
	}
	// Stale timestamp (outside the replay window).
	stale := strconv.FormatInt(now-3600, 10)
	if verifyWebhookSig(secret, stale, nonce, sign(secret, stale, nonce)) {
		t.Error("stale timestamp accepted")
	}
	// A small forward clock skew (within the allowance) is accepted.
	skewOK := strconv.FormatInt(now+int64(webhookForwardSkew/time.Second)-2, 10)
	if !verifyWebhookSig(secret, skewOK, nonce, sign(secret, skewOK, nonce)) {
		t.Error("timestamp within forward-skew allowance rejected")
	}
	// A far-future timestamp is rejected.
	future := strconv.FormatInt(now+3600, 10)
	if verifyWebhookSig(secret, future, nonce, sign(secret, future, nonce)) {
		t.Error("far-future timestamp accepted")
	}
	// Over-long nonce.
	long := strings.Repeat("x", maxWebhookNonceLen+1)
	if verifyWebhookSig(secret, ts, long, sign(secret, ts, long)) {
		t.Error("over-long nonce accepted")
	}
	// Missing fields.
	if verifyWebhookSig(secret, "", nonce, good) || verifyWebhookSig(secret, ts, "", good) || verifyWebhookSig(secret, ts, nonce, "") {
		t.Error("missing field accepted")
	}
}

func TestNonceCacheReplay(t *testing.T) {
	n := newNonceCache(time.Minute)
	if n.seenOrAdd("tok:a") {
		t.Error("first sighting reported as replay")
	}
	if !n.seenOrAdd("tok:a") {
		t.Error("second sighting not reported as replay")
	}
	if n.seenOrAdd("tok:b") {
		t.Error("distinct nonce reported as replay")
	}
}

// Webhook auth at the HTTP boundary: unknown token → 404; bad signature → 401; a
// valid signed call → 202; a replay of it → 409. To stay hermetic (no live `git
// fetch`), we hold the single-flight semaphore so the valid call takes the "busy"
// 202 path WITHOUT spawning the background fetch goroutine — the nonce is still
// recorded before TryAcquire, so the replay path is exercised identically.
func TestWebhookHTTPAuthAndReplay(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	slug := "shop"
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{
		Project: slug, RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main",
		ComposePath: "docker-compose.yml", BuildPolicy: "never",
	}); err != nil {
		t.Fatal(err)
	}
	token, err := e.srv.gitStore.RotateWebhook(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, ok := e.srv.gitStore.WebhookLookup(token)
	if !ok {
		t.Fatal("webhook lookup failed")
	}

	// Use a NON-allowlisted peer (allowlist is 127.0.0.1/32): the webhook is
	// allowlist-exempt, so it must REACH the handler. A bad signature from this
	// peer returning 401 (not a bare allowlist 404) proves the exemption.
	const ciPeer = "8.8.8.8:5000"

	// Unknown token → 404 (handler-level, never reveals).
	if resp := e.req(t, "POST", "/webhook/not-a-real-token", ciPeer, nil, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown token: status %d, want 404", resp.StatusCode)
	}
	// Known token, missing/bad signature → 401 (proves allowlist exemption).
	if resp := e.req(t, "POST", "/webhook/"+token, ciPeer, nil, nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad signature from non-allowlisted peer: status %d, want 401", resp.StatusCode)
	}
	// A path that only LOOKS like a webhook (traversal) must NOT ride the
	// exemption: it cleans outside /webhook/, so the non-allowlisted peer is
	// denied at the allowlist (404), never reaching a non-webhook route.
	if resp := e.req(t, "GET", "/webhook/../events", ciPeer, nil, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("traversal via webhook exemption: status %d, want 404 (allowlist denied)", resp.StatusCode)
	}

	// Hold single-flight so the valid call cannot spawn a live fetch.
	if !e.srv.gitDeploy.TryAcquire() {
		t.Fatal("could not pre-acquire single-flight")
	}
	defer e.srv.gitDeploy.Release()

	// Valid signed call → 202 (busy: another git op is "in progress").
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "abc-123"
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts + "." + nonce))
	sig := hex.EncodeToString(mac.Sum(nil))
	hdr := map[string]string{"X-Helmsman-Timestamp": ts, "X-Helmsman-Nonce": nonce, "X-Helmsman-Signature": sig}
	if resp := e.req(t, "POST", "/webhook/"+token, ciPeer, hdr, nil, nil); resp.StatusCode != http.StatusAccepted {
		t.Errorf("valid webhook: status %d, want 202", resp.StatusCode)
	}

	// Replay the exact same signed call → 409 (nonce already used).
	if resp := e.req(t, "POST", "/webhook/"+token, ciPeer, hdr, nil, nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("replayed webhook: status %d, want 409", resp.StatusCode)
	}
}

func TestTokenFlashSingleUseAndBound(t *testing.T) {
	f := newTokenFlash(time.Minute)
	h := f.put("shop", "secret-token")
	// Wrong project never resolves (and consumes the handle).
	if _, ok := f.take(h, "other"); ok {
		t.Error("flash resolved for the wrong project")
	}
	// And now the handle is gone (single-use, even on a mismatch).
	if _, ok := f.take(h, "shop"); ok {
		t.Error("handle survived a prior take")
	}

	// Correct project resolves exactly once.
	h2 := f.put("shop", "secret-token")
	tok, ok := f.take(h2, "shop")
	if !ok || tok != "secret-token" {
		t.Fatalf("flash take: ok=%v tok=%q", ok, tok)
	}
	if _, ok := f.take(h2, "shop"); ok {
		t.Error("flash resolved twice (must be single-use)")
	}
	// An unknown handle never resolves.
	if _, ok := f.take("nope", "shop"); ok {
		t.Error("unknown handle resolved")
	}
}

func TestIsFullSha40(t *testing.T) {
	if !isFullSha40("0123456789abcdef0123456789abcdef01234567") {
		t.Error("valid sha rejected")
	}
	for _, bad := range []string{"", "abc", "0123456789ABCDEF0123456789abcdef01234567", strings.Repeat("g", 40)} {
		if isFullSha40(bad) {
			t.Errorf("invalid sha %q accepted", bad)
		}
	}
}
