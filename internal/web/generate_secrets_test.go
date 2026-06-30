package web

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/secret"
)

func genDef(slug string, secrets ...definition.Secret) *definition.Definition {
	return &definition.Definition{
		APIVersion: "mooring/v1",
		Kind:       "App",
		Metadata:   definition.Metadata{Slug: slug},
		Spec:       definition.Spec{Secrets: secrets},
	}
}

func TestEnsureGeneratedSecretsMintsAndIsIdempotent(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	def := genDef("genapp",
		definition.Secret{Name: "WEBHOOK_SECRET", Generate: "hex:32"},
		definition.Secret{Name: "ADMIN_PW", Generate: "password:20"},
		definition.Secret{Name: "JWT_KEY", Generate: "rsa:2048"},
	)

	if err := e.srv.ensureGeneratedSecrets(ctx, "genapp", def, func(string) {}); err != nil {
		t.Fatalf("mint: %v", err)
	}

	// hex:32 → 64 hex chars; password:20 → length 20; keypair → JWT_KEY + JWT_KEY_PUB (b64).
	hexv, ok, _ := e.srv.envStore.Reveal("genapp", "WEBHOOK_SECRET")
	if !ok {
		t.Fatal("WEBHOOK_SECRET not minted")
	}
	if b, err := hex.DecodeString(hexv); err != nil || len(b) != 32 {
		t.Fatalf("WEBHOOK_SECRET not 32 random bytes hex: %v len=%d", err, len(b))
	}
	if pw, _, _ := e.srv.envStore.Reveal("genapp", "ADMIN_PW"); len(pw) != 20 {
		t.Fatalf("ADMIN_PW length = %d, want 20", len(pw))
	}
	priv, ok, _ := e.srv.envStore.Get("genapp", "JWT_KEY")
	if !ok || priv.Enc != "b64" {
		t.Fatalf("JWT_KEY missing or not b64 (ok=%v enc=%q)", ok, priv.Enc)
	}
	pemBytes, err := priv.DecodedValue()
	if err != nil || !strings.Contains(string(pemBytes), "BEGIN PRIVATE KEY") {
		t.Fatalf("JWT_KEY did not decode to a PEM private key: %v", err)
	}
	pub, ok, _ := e.srv.envStore.Get("genapp", "JWT_KEY_PUB")
	if !ok {
		t.Fatal("derived JWT_KEY_PUB not minted")
	}
	if pubPEM, _ := pub.DecodedValue(); !strings.Contains(string(pubPEM), "BEGIN PUBLIC KEY") {
		t.Fatal("JWT_KEY_PUB is not a PEM public key")
	}

	// Idempotency: a second run must NOT rotate any existing value.
	if err := e.srv.ensureGeneratedSecrets(ctx, "genapp", def, func(string) {}); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	if again, _, _ := e.srv.envStore.Reveal("genapp", "WEBHOOK_SECRET"); again != hexv {
		t.Fatal("idempotency broken: WEBHOOK_SECRET was rotated on re-deploy")
	}
}

func TestEnsureGeneratedSecretsPreservesExisting(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	// Pre-set the value the operator already provided.
	if _, err := e.srv.envStore.Save(ctx, "app2",
		[]envstore.Entry{{Key: "MONGO_URI", Value: secret.New("mongodb://live"), Secret: true}}, "operator"); err != nil {
		t.Fatal(err)
	}
	def := genDef("app2", definition.Secret{Name: "MONGO_URI", Generate: "password:32"})
	if err := e.srv.ensureGeneratedSecrets(ctx, "app2", def, func(string) {}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if v, _, _ := e.srv.envStore.Reveal("app2", "MONGO_URI"); v != "mongodb://live" {
		t.Fatalf("generate overwrote a pre-existing secret: got %q", v)
	}
}
