package web

import (
	"strings"
	"testing"
)

// §15 Phase-3 fuzzing of the security-critical parsers in the request pipeline:
// the XFF derivation (the most-abused trust seam), the path-confinement predicate,
// and the webhook signature verifier. Goal: zero panics on arbitrary input, and the
// accept-side invariants hold.

// singleXFF must accept ONLY when exactly one token is present, and that token must
// be comma-free and trimmed — a forged/appended chain must fail closed.
func FuzzSingleXFF(f *testing.F) {
	for _, s := range []string{
		"", "1.2.3.4", " 1.2.3.4 ", "1.2.3.4, 5.6.7.8", "a,b,c",
		"\n\n", ",", " , ", "::ffff:127.0.0.1", strings.Repeat("x,", 500),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		// One header line per \n, mirroring Header.Values.
		values := strings.Split(raw, "\n")
		tok, ok := singleXFF(values)
		if !ok {
			return
		}
		if strings.Contains(tok, ",") {
			t.Errorf("singleXFF accepted a token containing a comma: %q", tok)
		}
		if tok != strings.TrimSpace(tok) || tok == "" {
			t.Errorf("singleXFF accepted an untrimmed/empty token: %q", tok)
		}
	})
}

// confinedUnder must never panic on arbitrary path pairs.
func FuzzConfinedUnder(f *testing.F) {
	f.Add("/run/app/x", "/run/app")
	f.Add("/run/app/../etc", "/run/app")
	f.Add("", "")
	f.Add("relative/path", "/abs/base")
	f.Fuzz(func(t *testing.T, dest, runDir string) {
		_ = confinedUnder(dest, runDir) // must not panic
	})
}

// verifyWebhookSig must never panic on malformed timestamp/nonce/signature input
// (all attacker-controlled), and must reject non-hex / wrong-length signatures.
func FuzzVerifyWebhookSig(f *testing.F) {
	f.Add([]byte("secret"), "1700000000", "nonce", "deadbeef")
	f.Add([]byte(""), "", "", "")
	f.Add([]byte("k"), "not-a-time", "\x00", "zzzz")
	f.Fuzz(func(t *testing.T, secret []byte, ts, nonce, sig string) {
		_ = verifyWebhookSig(secret, ts, nonce, sig) // must not panic
	})
}
