package ops

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/opsclient"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

// resolveBase rewrites a service-name base_url to the backing container's bridge IP
// (port + scheme + path preserved); a literal IP and a nil resolver pass through; an
// unresolvable service errors so the probe reports a clear BASIC failure.
func TestResolveBase(t *testing.T) {
	p := &Prober{resolve: func(_ context.Context, project, service string) (string, bool) {
		if project == "shop" && service == "api" {
			return "172.18.0.5", true
		}
		return "", false
	}}
	if got, err := p.resolveBase(context.Background(), "shop", "http://api:3000/ops"); err != nil || got != "http://172.18.0.5:3000/ops" {
		t.Errorf("service-name rewrite = %q, %v; want http://172.18.0.5:3000/ops", got, err)
	}
	if got, err := p.resolveBase(context.Background(), "shop", "http://10.0.0.9:8081"); err != nil || got != "http://10.0.0.9:8081" {
		t.Errorf("literal IP must pass through unchanged, got %q, %v", got, err)
	}
	if _, err := p.resolveBase(context.Background(), "shop", "http://ghost:3000"); err == nil {
		t.Error("an unresolvable service must error (→ clear BASIC failure)")
	}
	nilResolver := &Prober{}
	if got, err := nilResolver.resolveBase(context.Background(), "shop", "http://api:3000"); err != nil || got != "http://api:3000" {
		t.Errorf("a nil resolver must pass the base_url through, got %q, %v", got, err)
	}
}

// fakeDoer returns canned responses keyed by relative path, and records the
// secret header it was handed so tests can assert it travels server-side.
type fakeDoer struct {
	responses  map[string]*opsclient.Response
	lastSecret string
	lastBase   string // the base URL the doer was last dialed at (asserts resolution)
	postCalls  []string
}

func (f *fakeDoer) Get(ctx context.Context, base, relPath, secretHeader string, sec secret.Redacted) (*opsclient.Response, error) {
	f.lastBase = base
	if secretHeader != "" {
		f.lastSecret = sec.Reveal()
	}
	if r, ok := f.responses[relPath]; ok {
		return r, nil
	}
	return &opsclient.Response{Status: 404, Body: []byte(`{}`)}, nil
}

func (f *fakeDoer) Post(ctx context.Context, base, relPath, secretHeader string, sec secret.Redacted, body []byte) (*opsclient.Response, error) {
	f.postCalls = append(f.postCalls, relPath)
	return &opsclient.Response{Status: 200, Body: []byte(`{"ok":true}`)}, nil
}

func newCipher(t *testing.T) *secret.Cipher {
	t.Helper()
	c, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "ops.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestConfigStoreEncryptsSecret(t *testing.T) {
	db := newTestDB(t)
	cs := NewConfigStore(db, newCipher(t))
	sec := "a-very-secret-value"
	if err := cs.Set("shop", SetInput{Enabled: true, BaseURL: "http://web:8080", SecretHeader: "X-Ops-Secret", NewSecret: &sec, OpsMode: "auto"}); err != nil {
		t.Fatal(err)
	}
	// the raw column must be ciphertext, not the plaintext
	var raw []byte
	_ = db.QueryRow(`SELECT secret_enc FROM app_ops WHERE project='shop'`).Scan(&raw)
	if len(raw) == 0 || string(raw) == sec {
		t.Errorf("secret stored in the clear or missing")
	}
	cfg, ok, err := cs.Get("shop")
	if err != nil || !ok {
		t.Fatalf("get: %v ok=%v", err, ok)
	}
	if cfg.Secret.Reveal() != sec || !cfg.HasSecret {
		t.Errorf("decrypted secret mismatch")
	}
	// keep-secret (NewSecret nil) preserves it
	if err := cs.Set("shop", SetInput{Enabled: true, BaseURL: "http://web:9090", SecretHeader: "X-Ops-Secret", OpsMode: "auto"}); err != nil {
		t.Fatal(err)
	}
	cfg, _, _ = cs.Get("shop")
	if cfg.Secret.Reveal() != sec {
		t.Errorf("keep-secret lost the secret")
	}
}

func TestConfigStoreRejectsLoopbackBase(t *testing.T) {
	cs := NewConfigStore(newTestDB(t), newCipher(t))
	bad := []string{
		"http://127.0.0.1:9000", "http://localhost:8080", "http://web:8080/path", "ftp://x",
		"http://[::ffff:127.0.0.1]:8080",  // IPv4-mapped loopback (review #3)
		"http://10.0.0.5@169.254.169.254", // userinfo confusion → real host is metadata (review #3)
	}
	for _, b := range bad {
		if err := cs.Set("x", SetInput{Enabled: true, BaseURL: b, OpsMode: "auto"}); err == nil {
			t.Errorf("Set accepted bad base URL %q", b)
		}
	}
}

func TestConfigStoreDisableSucceedsWithBlankBase(t *testing.T) {
	cs := NewConfigStore(newTestDB(t), newCipher(t))
	// review #6: disabling must not require a valid base URL.
	if err := cs.Set("x", SetInput{Enabled: false, BaseURL: "", OpsMode: "auto"}); err != nil {
		t.Errorf("disable with blank base URL failed: %v", err)
	}
}

func TestConfigStoreSecretAndHeaderValidation(t *testing.T) {
	cs := NewConfigStore(newTestDB(t), newCipher(t))
	short := "tooshort"
	if err := cs.Set("x", SetInput{Enabled: true, BaseURL: "http://web:8080", NewSecret: &short, OpsMode: "auto"}); err == nil {
		t.Error("accepted a <16-char secret (review #5/#8)")
	}
	if err := cs.Set("x", SetInput{Enabled: true, BaseURL: "http://web:8080", SecretHeader: "X Ops Secret", OpsMode: "auto"}); err == nil {
		t.Error("accepted an invalid secret header name (review #8)")
	}
}

func TestConfigStoreBasePathNormalized(t *testing.T) {
	cs := NewConfigStore(newTestDB(t), newCipher(t))
	if err := cs.Set("x", SetInput{Enabled: true, BaseURL: "http://web:8080", BasePath: "/ops/", OpsMode: "auto"}); err != nil {
		t.Fatal(err)
	}
	cfg, _, _ := cs.Get("x")
	if cfg.BasePath != "/ops" {
		t.Errorf("base_path not normalized: %q", cfg.BasePath)
	}
	if err := cs.Set("x", SetInput{Enabled: true, BaseURL: "http://web:8080", BasePath: "/has space", OpsMode: "auto"}); err == nil {
		t.Error("accepted an invalid base_path (review #4)")
	}
}

func TestQueueActionBasicKillSwitch(t *testing.T) {
	doer := &fakeDoer{}
	sec := "shhhhhhhhhhhhhhhh"
	// enabled but ops_mode=basic → queue actions must be refused (review #7)
	p := proberWith(t, doer, SetInput{Enabled: true, BaseURL: "http://web:8080", SecretHeader: "X-Ops-Secret", NewSecret: &sec, OpsMode: "basic"})
	if err := p.QueueAction(context.Background(), "shop", "emails", "pause"); err != ErrOpsNotEnabled {
		t.Errorf("QueueAction in basic mode = %v, want ErrOpsNotEnabled", err)
	}
	if len(doer.postCalls) != 0 {
		t.Error("queue action proxied to app despite basic kill-switch")
	}
}

func proberWith(t *testing.T, doer Doer, cfg SetInput) *Prober {
	t.Helper()
	db := newTestDB(t)
	cs := NewConfigStore(db, newCipher(t))
	if err := cs.Set("shop", cfg); err != nil {
		t.Fatal(err)
	}
	return NewProber(cs, doer, db, nil)
}

// ProbeTarget (the per-service on-demand path) must resolve a compose-service-name
// base_url to the live bridge IP before dialing — parity with the scheduled Probe.
func TestProbeTargetResolvesBaseURL(t *testing.T) {
	doer := &fakeDoer{responses: map[string]*opsclient.Response{
		"/health/live": {Status: 200, Body: []byte(`{"status":"ok"}`)},
	}}
	db := newTestDB(t)
	p := NewProber(NewConfigStore(db, newCipher(t)), doer, db, func(_ context.Context, project, service string) (string, bool) {
		if project == "shop" && service == "resolver" {
			return "172.18.0.9", true
		}
		return "", false
	})
	// service name → dialed at the resolved bridge IP, port preserved.
	if res := p.ProbeTarget(context.Background(), "shop", Target{BaseURL: "http://resolver:8081"}, "", "rich"); res == nil {
		t.Fatal("nil result")
	}
	if !strings.Contains(doer.lastBase, "172.18.0.9:8081") {
		t.Errorf("ProbeTarget dialed %q, want the resolved IP 172.18.0.9:8081", doer.lastBase)
	}
	// unresolvable service → clear BASIC failure, and NO dial.
	doer.lastBase = ""
	res := p.ProbeTarget(context.Background(), "shop", Target{BaseURL: "http://ghost:9999"}, "", "rich")
	if res == nil || res.Mode != BASIC || res.Err == "" {
		t.Errorf("an unresolvable service must be a clear BASIC failure, got %+v", res)
	}
	if doer.lastBase != "" {
		t.Errorf("must not dial an unresolvable service, dialed %q", doer.lastBase)
	}
}

func TestProbeRichViaDescriptor(t *testing.T) {
	doer := &fakeDoer{responses: map[string]*opsclient.Response{
		"/.well-known/ops": {Status: 200, Body: []byte(`{"opsInterfaceVersion":"1.0","capabilities":["health","queues","alerting"]}`)},
		"/health/live":     {Status: 200, Body: []byte(`{"status":"ok","details":{"db":{"status":"up"},"cache":{"status":"down"}}}`)},
		"/queues":          {Status: 200, Body: []byte(`{"queues":[{"name":"emails","isPaused":false,"counts":{"waiting":3}}]}`)},
	}}
	sec := "shhhhhhhhhhhhhhhh"
	p := proberWith(t, doer, SetInput{Enabled: true, BaseURL: "http://web:8080", SecretHeader: "X-Ops-Secret", NewSecret: &sec, OpsMode: "auto"})

	res, ok := p.Probe(context.Background(), "shop")
	if !ok || res.Mode != RICH {
		t.Fatalf("expected RICH, got ok=%v res=%+v", ok, res)
	}
	if len(res.Indicators) != 2 || !res.AlertingCapable {
		t.Errorf("indicators/alerting wrong: %+v", res)
	}
	if len(res.Queues) != 1 || res.Queues[0].Name != "emails" {
		t.Errorf("queues wrong: %+v", res.Queues)
	}
	if doer.lastSecret != sec {
		t.Errorf("secret not sent on authenticated probe: %q", doer.lastSecret)
	}
	if len(res.Snapshot) == 0 {
		t.Errorf("snapshot ring not populated")
	}
}

func TestProbeBasicWhenNoDescriptor(t *testing.T) {
	doer := &fakeDoer{responses: map[string]*opsclient.Response{
		// no /.well-known/ops, and health/live is not Terminus-shaped
		"/health/live": {Status: 200, Body: []byte(`{"hello":"world"}`)},
	}}
	p := proberWith(t, doer, SetInput{Enabled: true, BaseURL: "http://web:8080", OpsMode: "auto"})
	res, ok := p.Probe(context.Background(), "shop")
	if !ok {
		t.Fatal("ops enabled should return a result")
	}
	if res.Mode != BASIC {
		t.Errorf("expected BASIC fallback, got %s", res.Mode)
	}
}

func TestProbeDisabledReturnsFalse(t *testing.T) {
	p := proberWith(t, &fakeDoer{}, SetInput{Enabled: false, BaseURL: "http://web:8080", OpsMode: "auto"})
	if _, ok := p.Probe(context.Background(), "shop"); ok {
		t.Error("disabled ops should return ok=false")
	}
	// unknown project → false
	if _, ok := p.Probe(context.Background(), "nope"); ok {
		t.Error("unknown project should return ok=false")
	}
}

func TestQueueActionValidation(t *testing.T) {
	doer := &fakeDoer{}
	sec := "shhhhhhhhhhhhhhhh"
	p := proberWith(t, doer, SetInput{Enabled: true, BaseURL: "http://web:8080", SecretHeader: "X-Ops-Secret", NewSecret: &sec, OpsMode: "auto"})
	ctx := context.Background()
	if err := p.QueueAction(ctx, "shop", "emails", "bogus"); err != ErrBadQueueAction {
		t.Errorf("bad action: %v", err)
	}
	if err := p.QueueAction(ctx, "shop", "../etc", "pause"); err != ErrBadQueueName {
		t.Errorf("bad queue name: %v", err)
	}
	if err := p.QueueAction(ctx, "shop", "emails", "pause"); err != nil {
		t.Errorf("valid action failed: %v", err)
	}
	if len(doer.postCalls) != 1 || doer.postCalls[0] != "/queues/emails/pause" {
		t.Errorf("queue POST path wrong: %+v", doer.postCalls)
	}
}
