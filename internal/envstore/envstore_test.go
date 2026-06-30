package envstore

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "e.db"))
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

func ent(k, v string, s bool) Entry { return Entry{Key: k, Value: secret.New(v), Secret: s} }

func TestSaveCurrentRenderEncrypted(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	v, err := st.Save(ctx, "shop", []Entry{ent("LOG_LEVEL", "info", false), ent("DB_PASSWORD", "s3cr3t-value", true)}, "operator")
	if err != nil || v != 1 {
		t.Fatalf("save: v=%d err=%v", v, err)
	}
	// ciphertext must not contain the plaintext secret
	var blob []byte
	_ = st.db.QueryRow(`SELECT blob_enc FROM env_blobs WHERE project='shop' AND version=1`).Scan(&blob)
	if contains(blob, "s3cr3t-value") {
		t.Error("secret stored in the clear")
	}
	entries, cur, err := st.Current("shop")
	if err != nil || cur != 1 || len(entries) != 2 {
		t.Fatalf("current: cur=%d n=%d err=%v", cur, len(entries), err)
	}
	// sorted: DB_PASSWORD, LOG_LEVEL
	if entries[0].Key != "DB_PASSWORD" || !entries[0].Secret {
		t.Errorf("entry0 wrong: %+v", entries[0])
	}
	r, _ := st.Render("shop")
	if r["LOG_LEVEL"] != "info" || r["DB_PASSWORD"] != "s3cr3t-value" {
		t.Errorf("render wrong: %+v", r)
	}
	// reveal
	val, ok, _ := st.Reveal("shop", "DB_PASSWORD")
	if !ok || val != "s3cr3t-value" {
		t.Errorf("reveal wrong: %q ok=%v", val, ok)
	}
}

func TestRejectsBadKeysAndValues(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	bad := [][2]string{
		{"1BAD", "x"},          // starts with digit
		{"HAS SPACE", "x"},     // space
		{"HAS=EQ", "x"},        // equals
		{"OK", "line1\nline2"}, // newline → env-file injection
		{"OK2", "nul\x00"},     // NUL
	}
	for _, kv := range bad {
		if _, err := st.Save(ctx, "x", []Entry{ent(kv[0], kv[1], false)}, "op"); err == nil {
			t.Errorf("Save accepted bad entry %q=%q", kv[0], kv[1])
		}
	}
	// duplicate key
	if _, err := st.Save(ctx, "x", []Entry{ent("A", "1", false), ent("A", "2", false)}, "op"); err == nil {
		t.Error("Save accepted duplicate key")
	}
}

func TestVersionsAndRollback(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	st.Save(ctx, "app", []Entry{ent("V", "one", false)}, "op")   // v1
	st.Save(ctx, "app", []Entry{ent("V", "two", false)}, "op")   // v2
	st.Save(ctx, "app", []Entry{ent("V", "three", false)}, "op") // v3
	vs, _ := st.Versions("app")
	if len(vs) != 3 || vs[0].Version != 3 {
		t.Fatalf("versions wrong: %+v", vs)
	}
	// rollback to v1 → creates v4 with v1's content
	nv, err := st.Rollback(ctx, "app", 1, "op")
	if err != nil || nv != 4 {
		t.Fatalf("rollback: nv=%d err=%v", nv, err)
	}
	r, _ := st.Render("app")
	if r["V"] != "one" {
		t.Errorf("rollback content wrong: %q", r["V"])
	}
}

func contains(b []byte, sub string) bool {
	s := string(b)
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// A b64-encoded (Enc) entry — how a generated PEM keypair is stored — must
// round-trip through save/Get and DecodedValue must return the original bytes.
func TestEncRoundTripAndDecode(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	pem := "-----BEGIN PRIVATE KEY-----\nMIIB...multi\nline...==\n-----END PRIVATE KEY-----\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(pem))
	// The raw stored value (b64) has no newlines, so Save accepts it even though
	// the underlying PEM does not.
	if _, err := st.Save(ctx, "app", []Entry{{Key: "JWT_KEY", Value: secret.New(b64), Secret: true, Enc: "b64"}}, "generate"); err != nil {
		t.Fatalf("save b64 entry: %v", err)
	}
	ent, ok, err := st.Get("app", "JWT_KEY")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if ent.Enc != "b64" {
		t.Fatalf("Enc not round-tripped: %q", ent.Enc)
	}
	dec, err := ent.DecodedValue()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(dec) != pem {
		t.Fatalf("decoded value != original PEM\n got: %q", string(dec))
	}
	// A plain entry decodes to itself.
	plain := Entry{Value: secret.New("hello"), Enc: ""}
	if b, _ := plain.DecodedValue(); string(b) != "hello" {
		t.Fatalf("plain DecodedValue = %q", string(b))
	}
}
