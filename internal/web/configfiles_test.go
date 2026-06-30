package web

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/cfgfile"
	"github.com/daboss2003/mooring/internal/cfgstore"
	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/monitor"
)

func TestMaterializeRendersChmodsAndPreservesAppPlaceholders(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	if err := e.srv.cfgStore.SaveConfigFile(ctx, "shop", cfgstore.SaveInput{
		Name:     "rabbit.conf",
		RelPath:  "config/rabbit.conf",
		Template: "cookie = {{hm.cookie}}\nuser = ${username}\nhost = {{hm.host}}\n",
		Bindings: []cfgfile.Binding{{Key: "cookie", Source: "secret:NODE_COOKIE"}, {Key: "host", Source: "app:slug"}},
	}); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	app := &monitor.App{Project: "shop", WorkingDir: runDir}
	env := compose.Env{"NODE_COOKIE": "secret-cookie-value"}

	if err := e.srv.materializeConfigFiles(app, env); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	out, err := os.ReadFile(filepath.Join(runDir, "config/rabbit.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := "cookie = secret-cookie-value\nuser = ${username}\nhost = shop\n"
	if string(out) != want {
		t.Errorf("rendered:\n got %q\nwant %q", out, want)
	}
	fi, _ := os.Stat(filepath.Join(runDir, "config/rabbit.conf"))
	// Bind-mounted into a (non-root) container, so it must be container-readable (0644);
	// on-host secrecy comes from the 0700 run dir, not the file mode (same as tls.key).
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644 (container-readable; confined by the 0700 run dir)", fi.Mode().Perm())
	}
}

// A config file with no explicit mode and no secret must materialize 0644 — so a
// non-root container can read the bind mount. Regression for the EACCES where an unset
// mode wrote the file 0o000 (unreadable by anyone, clobbering the first pass's 0644).
func TestMaterializeConfigFileUnsetModeIsReadable(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	if err := e.srv.cfgStore.SaveConfigFile(context.Background(), "shop", cfgstore.SaveInput{
		Name: "plain.conf", RelPath: "config/plain.conf", Template: "hello = world\n",
	}); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	app := &monitor.App{Project: "shop", WorkingDir: runDir}
	if err := e.srv.materializeConfigFiles(app, compose.Env{}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	fi, err := os.Stat(filepath.Join(runDir, "config/plain.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("unset-mode config file = %v, want 0644 (must not be 0000)", fi.Mode().Perm())
	}
}

func TestMaterializeMissingSecretIsHardFailure(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	_ = e.srv.cfgStore.SaveConfigFile(context.Background(), "shop", cfgstore.SaveInput{
		Name: "x", RelPath: "x.conf", Template: "p = {{hm.pw}}\n",
		Bindings: []cfgfile.Binding{{Key: "pw", Source: "secret:MISSING"}},
	})
	app := &monitor.App{Project: "shop", WorkingDir: t.TempDir()}
	if err := e.srv.materializeConfigFiles(app, compose.Env{}); err == nil {
		t.Error("missing secret should be a hard materialize failure (never empty)")
	}
}

// review #1 (HIGH): a parent-symlink under run_dir must not redirect the write
// outside run_dir, even though the lexical path is "under" run_dir.
func TestMaterializeRefusesSymlinkEscape(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	_ = e.srv.cfgStore.SaveConfigFile(context.Background(), "shop", cfgstore.SaveInput{
		Name: "x", RelPath: "data/app.conf", Template: "host = {{hm.h}}\n",
		Bindings: []cfgfile.Binding{{Key: "h", Source: "app:slug"}},
	})
	runDir := t.TempDir()
	outside := t.TempDir()
	// plant run_dir/data -> /outside
	if err := os.Symlink(outside, filepath.Join(runDir, "data")); err != nil {
		t.Fatal(err)
	}
	app := &monitor.App{Project: "shop", WorkingDir: runDir}
	if err := e.srv.materializeConfigFiles(app, compose.Env{}); err == nil {
		t.Fatal("symlink parent did not block the write (path escape)")
	}
	if _, err := os.Stat(filepath.Join(outside, "app.conf")); err == nil {
		t.Error("write escaped run_dir into the symlink target")
	}
}

// review #2 (MED): an empty secret value fails closed, never an empty config line.
func TestMaterializeEmptySecretFailsClosed(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	_ = e.srv.cfgStore.SaveConfigFile(context.Background(), "shop", cfgstore.SaveInput{
		Name: "x", RelPath: "x.conf", Template: "password = {{hm.pw}}\n",
		Bindings: []cfgfile.Binding{{Key: "pw", Source: "secret:EMPTY"}},
	})
	app := &monitor.App{Project: "shop", WorkingDir: t.TempDir()}
	if err := e.srv.materializeConfigFiles(app, compose.Env{"EMPTY": ""}); err == nil {
		t.Error("empty secret should fail closed, not render password=")
	}
}

func TestCertWaitGateBlocksWhenCertMissing(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	_ = e.srv.cfgStore.SaveCertBinding(context.Background(), "shop", cfgstore.CertBinding{
		BindingName: "web", Hostname: "app.example.com", SyncDirRel: "certs/web", Required: true,
	})
	app := &monitor.App{Project: "shop", WorkingDir: t.TempDir()}
	err := e.srv.materializeConfigFiles(app, compose.Env{})
	if err == nil || !strings.Contains(err.Error(), "required cert") {
		t.Errorf("cert-wait gate should block: %v", err)
	}
}
