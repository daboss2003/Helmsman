package secretgen

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
)

func TestValidateGrammar(t *testing.T) {
	good := []string{"hex:16", "hex:32", "hex:1024", "base64:24", "password:16", "password:64", "rsa:2048", "rsa:3072", "rsa:4096", "ed25519"}
	for _, s := range good {
		if err := Validate(s); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", s, err)
		}
	}
	bad := []string{
		"", "hex", "hex:", "hex:8", "hex:1025", "base64:0", "password:8", "password:300",
		"rsa", "rsa:1024", "rsa:2049", "ed25519:1", "aes:32", "hex:-1", "hex:abc",
	}
	for _, s := range bad {
		if err := Validate(s); err == nil {
			t.Errorf("Validate(%q) = nil, want error", s)
		}
	}
}

func TestMintHexBase64Password(t *testing.T) {
	out, err := Mint("hex:32")
	if err != nil || len(out) != 1 {
		t.Fatalf("hex mint: %v len=%d", err, len(out))
	}
	if b, err := hex.DecodeString(out[0].Value); err != nil || len(b) != 32 {
		t.Fatalf("hex value not 32 bytes hex: %v len=%d", err, len(b))
	}
	if out[0].Enc != "" || out[0].NameSuffix != "" {
		t.Fatalf("hex output should be a plain primary value, got %+v", out[0])
	}

	out, _ = Mint("base64:24")
	if b, err := base64.StdEncoding.DecodeString(out[0].Value); err != nil || len(b) != 24 {
		t.Fatalf("base64 value not 24 bytes: %v len=%d", err, len(b))
	}

	out, _ = Mint("password:20")
	if len(out[0].Value) != 20 {
		t.Fatalf("password length = %d, want 20", len(out[0].Value))
	}
	for _, c := range out[0].Value {
		if !strings.ContainsRune(passwordAlphabet, c) {
			t.Fatalf("password char %q not in alphabet", c)
		}
	}
}

func TestMintIsRandom(t *testing.T) {
	a, _ := Mint("hex:32")
	b, _ := Mint("hex:32")
	if a[0].Value == b[0].Value {
		t.Fatal("two hex:32 mints produced identical values")
	}
}

func TestMintRSAKeypair(t *testing.T) {
	out, err := Mint("rsa:2048")
	if err != nil || len(out) != 2 {
		t.Fatalf("rsa mint: %v len=%d", err, len(out))
	}
	priv, pub := out[0], out[1]
	if priv.NameSuffix != "" || pub.NameSuffix != PubSuffix {
		t.Fatalf("suffixes wrong: %q / %q", priv.NameSuffix, pub.NameSuffix)
	}
	if priv.Enc != "b64" || pub.Enc != "b64" {
		t.Fatalf("keypair outputs must be b64-encoded: %q / %q", priv.Enc, pub.Enc)
	}
	// Decode b64 → PEM → key; confirm both parse and the public matches the private.
	privKey := parsePrivPEM(t, priv.Value)
	rsaPriv, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is %T, want *rsa.PrivateKey", privKey)
	}
	if rsaPriv.N.BitLen() != 2048 {
		t.Fatalf("rsa key is %d bits, want 2048", rsaPriv.N.BitLen())
	}
	pubKey := parsePubPEM(t, pub.Value)
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *rsa.PublicKey", pubKey)
	}
	if rsaPub.N.Cmp(rsaPriv.N) != 0 {
		t.Fatal("derived public key does not match the private key")
	}
}

func TestMintEd25519Keypair(t *testing.T) {
	out, err := Mint("ed25519")
	if err != nil || len(out) != 2 {
		t.Fatalf("ed25519 mint: %v len=%d", err, len(out))
	}
	priv := parsePrivPEM(t, out[0].Value)
	if _, ok := priv.(ed25519.PrivateKey); !ok {
		t.Fatalf("private key is %T, want ed25519.PrivateKey", priv)
	}
	pub := parsePubPEM(t, out[1].Value)
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Fatalf("public key is %T, want ed25519.PublicKey", pub)
	}
}

func TestIsKeypair(t *testing.T) {
	for _, s := range []string{"rsa:2048", "ed25519"} {
		if !IsKeypair(s) {
			t.Errorf("IsKeypair(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"hex:32", "base64:24", "password:16", "bogus"} {
		if IsKeypair(s) {
			t.Errorf("IsKeypair(%q) = true, want false", s)
		}
	}
}

func parsePrivPEM(t *testing.T, b64 string) any {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("b64 decode priv: %v", err)
	}
	blk, _ := pem.Decode(der)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		t.Fatalf("priv PEM decode failed (block=%v)", blk)
	}
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS8 priv: %v", err)
	}
	return key
}

func parsePubPEM(t *testing.T, b64 string) any {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("b64 decode pub: %v", err)
	}
	blk, _ := pem.Decode(der)
	if blk == nil || blk.Type != "PUBLIC KEY" {
		t.Fatalf("pub PEM decode failed (block=%v)", blk)
	}
	key, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatalf("parse PKIX pub: %v", err)
	}
	return key
}
