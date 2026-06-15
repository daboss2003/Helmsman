package cfgstore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/Helmsman/internal/cfgfile"
	"github.com/daboss2003/Helmsman/internal/secret"
	"github.com/daboss2003/Helmsman/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(db, c)
}

func TestSaveSecretBearingForces0600AndEncrypts(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	in := SaveInput{
		Name:     "rabbit.conf",
		RelPath:  "config/rabbit.conf",
		Template: "cookie = {{hm.node_cookie}}\nuser = ${username}\n",
		Bindings: []cfgfile.Binding{{Key: "node_cookie", Source: "secret:NODE_COOKIE"}},
	}
	if err := st.SaveConfigFile(ctx, "shop", in); err != nil {
		t.Fatal(err)
	}
	// template stored encrypted (not plaintext)
	var enc []byte
	_ = st.db.QueryRow(`SELECT template_enc FROM app_config_files WHERE project='shop' AND name='rabbit.conf'`).Scan(&enc)
	if string(enc) == in.Template || len(enc) == 0 {
		t.Error("template stored in the clear")
	}
	files, err := st.ConfigFiles("shop")
	if err != nil || len(files) != 1 {
		t.Fatalf("ConfigFiles: %v n=%d", err, len(files))
	}
	f := files[0]
	if !f.SecretBearing || f.Mode != 0o600 {
		t.Errorf("secret-bearing should force 0600: secret=%v mode=%#o", f.SecretBearing, f.Mode)
	}
}

func TestNonSecretForces0640(t *testing.T) {
	st := newStore(t)
	in := SaveInput{Name: "app.conf", RelPath: "app.conf", Template: "host = {{hm.host}}\n", Bindings: []cfgfile.Binding{{Key: "host", Source: "app:slug"}}}
	if err := st.SaveConfigFile(context.Background(), "shop", in); err != nil {
		t.Fatal(err)
	}
	f, _ := st.ConfigFiles("shop")
	if f[0].SecretBearing || f[0].Mode != 0o640 {
		t.Errorf("non-secret should be 0640: %+v", f[0])
	}
}

func TestRejectsUnboundToken(t *testing.T) {
	st := newStore(t)
	in := SaveInput{Name: "x", RelPath: "x", Template: "a = {{hm.unbound}}\n", Bindings: nil}
	if err := st.SaveConfigFile(context.Background(), "shop", in); err == nil {
		t.Error("accepted a template with an unbound {{hm.}} token")
	}
}

func TestRejectsLiteralSecretInNonSecretBody(t *testing.T) {
	st := newStore(t)
	in := SaveInput{Name: "x", RelPath: "x", Template: "key = -----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----\n", Bindings: nil}
	if err := st.SaveConfigFile(context.Background(), "shop", in); err == nil {
		t.Error("accepted a literal PEM private key in a non-secret-bearing body")
	}
}

func TestRejectsBadRelPath(t *testing.T) {
	st := newStore(t)
	for _, p := range []string{"/abs/path", "../escape", "../../etc/x"} {
		in := SaveInput{Name: "x", RelPath: p, Template: "ok\n"}
		if err := st.SaveConfigFile(context.Background(), "shop", in); err == nil {
			t.Errorf("accepted unsafe rel_path %q", p)
		}
	}
}

func TestCertBindingRoundTrip(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	if err := st.SaveCertBinding(ctx, "shop", CertBinding{BindingName: "web", Hostname: "app.example.com", SyncDirRel: "certs/web", Required: true}); err != nil {
		t.Fatal(err)
	}
	cbs, _ := st.CertBindings("shop")
	if len(cbs) != 1 || cbs[0].Hostname != "app.example.com" || !cbs[0].Required {
		t.Errorf("cert binding round-trip wrong: %+v", cbs)
	}
	// sync dir must be confinable
	if err := st.SaveCertBinding(ctx, "shop", CertBinding{BindingName: "bad", Hostname: "h", SyncDirRel: "../escape"}); err == nil {
		t.Error("accepted a cert sync dir that escapes run_dir")
	}
}
