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

	"github.com/helmsman/helmsman/internal/dockerexec"
	"github.com/helmsman/helmsman/internal/gitstore"
)

// gitObjStoreFixture builds a real git commit and clones it --bare into objDir,
// then points refs/helmsman/staged at it — mimicking what a fetch would leave.
// Uses the real git (the hardened Repo only READS this store).
func gitObjStoreFixture(t *testing.T, objDir, composeContent string) string {
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
	if err := os.WriteFile(filepath.Join(work, "docker-compose.yml"), []byte(composeContent), 0o644); err != nil {
		t.Fatal(err)
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
	rd := e.srv.gitRunDir("shop")
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
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), "services:\n  web:\n    image: nginx\n")
	cfg := configureRepo(t, e, slug, sha)

	// Ask to deploy a DIFFERENT (well-formed) sha than the one staged.
	other := "0123456789abcdef0123456789abcdef01234567"
	err := e.srv.deployRepoApp(context.Background(), cfg, other, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("expected staged-moved rejection, got %v", err)
	}
}

// §5.6 runs on the cat-file'd compose bytes from the pinned commit — a dangerous
// key is rejected BEFORE any checkout or `docker compose`.
func TestDeployRejectsDangerousComposeFromPinnedBytes(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	slug := "shop"
	dangerous := "services:\n  web:\n    image: nginx\n    privileged: true\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), dangerous)
	cfg := configureRepo(t, e, slug, sha)

	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("expected §5.6 rejection, got %v", err)
	}
	// FSM should record the block.
	got, _, _ := e.srv.gitStore.Get(slug)
	if got.UpdateState != "update_blocked" {
		t.Errorf("state = %q, want update_blocked", got.UpdateState)
	}
	// The run dir must NOT have been populated (rejected before checkout).
	if _, err := os.Stat(filepath.Join(e.srv.gitRunDir(slug), "docker-compose.yml")); err == nil {
		t.Error("compose was checked out despite validation failure")
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
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), "services:\n  web:\n    image: nginx\n")
	cfg := configureRepo(t, e, slug, sha)

	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write plane disabled), got %v", err)
	}
	// The pinned tree must have been checked out into the run dir, confined.
	out, rerr := os.ReadFile(filepath.Join(e.srv.gitRunDir(slug), "docker-compose.yml"))
	if rerr != nil || !strings.Contains(string(out), "image: nginx") {
		t.Errorf("compose not extracted into run dir: %v %q", rerr, out)
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
