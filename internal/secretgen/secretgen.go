// Package secretgen mints values for `spec.secrets[].generate` — the declarative
// "auto-generate this secret on first deploy" field. It is the typed, server-side
// replacement for the hand-rolled `openssl rand` / `openssl genrsa` lines in a
// bootstrap script: the operator declares a name + a generate spec in mooring.yaml
// and Mooring mints the value once, stores it encrypted, and never displays it.
//
// Grammar (the `generate:` string):
//
//	hex:N        N random bytes, hex-encoded            (N in [16,1024])
//	base64:N     N random bytes, std-base64 (no pad-newline)  (N in [16,1024])
//	password:N   an N-char password from an unambiguous alnum alphabet (N in [16,256])
//	rsa:BITS     an RSA private key (BITS in {2048,3072,4096}) + derived public key
//	ed25519      an Ed25519 private key + derived public key
//
// Single-value kinds (hex/base64/password) return one Output. Keypair kinds return
// two: the private key (NameSuffix "") and the public key (NameSuffix "_PUB"). PEM
// values are returned base64-encoded with Enc="b64" because the secret store forbids
// newlines; the consumer base64-decodes them back to PEM when it writes the file.
package secretgen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// PubSuffix is appended to a keypair secret's name to hold the derived public key.
const PubSuffix = "_PUB"

// passwordAlphabet excludes visually ambiguous characters (0/O, 1/l/I) so a
// generated password is safe to read aloud or transcribe if it ever must be.
const passwordAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// Output is one minted value. NameSuffix is "" for the primary secret and
// PubSuffix for a keypair's public half. Enc is "" for a plain value or "b64"
// when Value is base64-encoded (PEM keypairs) and must be decoded before use.
type Output struct {
	NameSuffix string
	Value      string
	Enc        string
}

// IsKeypair reports whether spec produces a keypair (a private + public Output).
func IsKeypair(spec string) bool {
	kind, _, err := parse(spec)
	return err == nil && (kind == "rsa" || kind == "ed25519")
}

// Validate checks the generate spec's grammar and floors without minting anything.
func Validate(spec string) error {
	_, _, err := parse(spec)
	return err
}

// parse splits "kind:param" (or bare "ed25519") and validates the floors.
func parse(spec string) (kind string, param int, err error) {
	if spec == "" {
		return "", 0, fmt.Errorf("empty generate spec")
	}
	k, p, hasParam := strings.Cut(spec, ":")
	switch k {
	case "hex", "base64":
		n, perr := strconv.Atoi(p)
		if !hasParam || perr != nil {
			return "", 0, fmt.Errorf("generate %q: expected %s:<bytes>", spec, k)
		}
		if n < 16 || n > 1024 {
			return "", 0, fmt.Errorf("generate %q: byte count must be 16..1024", spec)
		}
		return k, n, nil
	case "password":
		n, perr := strconv.Atoi(p)
		if !hasParam || perr != nil {
			return "", 0, fmt.Errorf("generate %q: expected password:<length>", spec)
		}
		if n < 16 || n > 256 {
			return "", 0, fmt.Errorf("generate %q: password length must be 16..256", spec)
		}
		return k, n, nil
	case "rsa":
		n, perr := strconv.Atoi(p)
		if !hasParam || perr != nil {
			return "", 0, fmt.Errorf("generate %q: expected rsa:<bits>", spec)
		}
		if n != 2048 && n != 3072 && n != 4096 {
			return "", 0, fmt.Errorf("generate %q: rsa bits must be 2048, 3072, or 4096", spec)
		}
		return k, n, nil
	case "ed25519":
		if hasParam {
			return "", 0, fmt.Errorf("generate %q: ed25519 takes no parameter", spec)
		}
		return k, 0, nil
	default:
		return "", 0, fmt.Errorf("generate %q: unknown kind (want hex:/base64:/password:/rsa:/ed25519)", spec)
	}
}

// Mint generates the value(s) for spec. Output values are always newline-free
// (PEM keypairs are base64-encoded with Enc="b64"), so they are safe to store.
func Mint(spec string) ([]Output, error) {
	kind, param, err := parse(spec)
	if err != nil {
		return nil, err
	}
	switch kind {
	case "hex":
		b, err := randBytes(param)
		if err != nil {
			return nil, err
		}
		return []Output{{Value: hex.EncodeToString(b)}}, nil
	case "base64":
		b, err := randBytes(param)
		if err != nil {
			return nil, err
		}
		return []Output{{Value: base64.StdEncoding.EncodeToString(b)}}, nil
	case "password":
		pw, err := randPassword(param)
		if err != nil {
			return nil, err
		}
		return []Output{{Value: pw}}, nil
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, param)
		if err != nil {
			return nil, err
		}
		return keypairOutputs(key, key.Public())
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return keypairOutputs(priv, pub)
	}
	return nil, fmt.Errorf("generate %q: unreachable", spec)
}

// keypairOutputs marshals a private key to PKCS#8 PEM and its public key to PKIX
// PEM, returning both base64-encoded (Enc="b64") so they survive the no-newline
// secret store. The public half carries the PubSuffix.
func keypairOutputs(priv, pub any) ([]Output, error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return []Output{
		{NameSuffix: "", Value: base64.StdEncoding.EncodeToString(privPEM), Enc: "b64"},
		{NameSuffix: PubSuffix, Value: base64.StdEncoding.EncodeToString(pubPEM), Enc: "b64"},
	}, nil
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// randPassword builds an n-char password by uniform rejection-free sampling over
// the alphabet using crypto/rand.Int (no modulo bias).
func randPassword(n int) (string, error) {
	max := big.NewInt(int64(len(passwordAlphabet)))
	out := make([]byte, n)
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = passwordAlphabet[idx.Int64()]
	}
	return string(out), nil
}
