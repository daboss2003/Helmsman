package envimport

import (
	"testing"

	"github.com/helmsman/helmsman/internal/secret"
)

// a high-entropy token-shaped value the §7.4 lint flags.
const hiEntropy = "Xk9Lm2Qp7Rs4Tv8Wy1Zb3Nd6Fg0Hj5Kl8Mn2Pq4Rt7Uv0"

func byKey(entries []Entry) map[string]Entry {
	m := map[string]Entry{}
	for _, e := range entries {
		m[e.Key] = e
	}
	return m
}

func TestParseClassifiesBiasedToSecret(t *testing.T) {
	raw := []byte("APP_NAME=myapp\nLOG_LEVEL=info\nDB_PASSWORD=hunter2\nAPI_TOKEN=" + hiEntropy + "\n")
	entries, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := byKey(entries)
	if m["APP_NAME"].Secret || m["LOG_LEVEL"].Secret {
		t.Error("plain low-entropy values must classify as non-secret")
	}
	if !m["DB_PASSWORD"].Secret {
		t.Error("a *_PASSWORD key must classify as secret (biased by key name)")
	}
	if !m["API_TOKEN"].Secret {
		t.Error("a high-entropy token value must classify as secret (lint)")
	}
}

// Regression (M17 review): secret shapes that previously slipped the classifier —
// a 2-class 40-char token, a Stripe key, and a URL with inline credentials — all
// classify as secret now, even with GENERIC keys (so the value lint is what catches).
func TestParseCatchesPreviouslyMissedSecrets(t *testing.T) {
	raw := []byte("GENERIC_VAL=AAAAAAAAAAAAAAAAAAAA1111111111111111111\n" +
		"STRIPE_VAL=STRIPE_TEST_KEY_REMOVED\n" +
		"DB_CONN=postgres://user:s3cretpw@db.example/app\n")
	m := byKey(mustParse(t, raw))
	for _, k := range []string{"GENERIC_VAL", "STRIPE_VAL", "DB_CONN"} {
		if !m[k].Secret {
			t.Errorf("%s must classify as secret (was a classification miss)", k)
		}
	}
}

func mustParse(t *testing.T, raw []byte) []Entry {
	t.Helper()
	e, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestParseHygiene(t *testing.T) {
	cases := map[string][]byte{
		"lowercase key": []byte("foo=bar\n"),
		"dash in key":   []byte("MY-KEY=bar\n"),
		"NUL in value":  []byte("KEY=ab\x00cd\n"),
	}
	for name, raw := range cases {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: must be rejected by hygiene", name)
		}
	}
}

func TestParseValuesNotInError(t *testing.T) {
	// A NUL-bearing value's error must not leak the value.
	_, err := Parse([]byte("SECRET_KEY=topsecret\x00value\n"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); contains(got, "topsecret") {
		t.Errorf("error leaked the value: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// The override-proof hard stop: a secret-shaped value forced to plain is rejected.
func TestValidateForIngestHardStop(t *testing.T) {
	// Simulate an operator override: a high-entropy value marked NOT secret.
	entries := []Entry{{Key: "FORCED_PLAIN", Value: secret.New(hiEntropy), Secret: false}}
	if err := ValidateForIngest(entries); err == nil {
		t.Error("a secret-shaped value forced to plain must be hard-rejected (no override)")
	}
	// A genuinely plain value passes.
	ok := []Entry{{Key: "APP_NAME", Value: secret.New("myapp"), Secret: false}}
	if err := ValidateForIngest(ok); err != nil {
		t.Errorf("a plain value must pass: %v", err)
	}
}

func TestDiffCategoriesAndRotations(t *testing.T) {
	current := map[string]Current{
		"API_TOKEN":   {Value: "oldtoken", Secret: true},
		"APP_NAME":    {Value: "myapp", Secret: false},
		"DB_PASSWORD": {Value: "p1", Secret: true},
		"LOG_LEVEL":   {Value: "info", Secret: false},
	}
	imported := []Entry{
		{Key: "API_TOKEN", Value: secret.New("newtoken"), Secret: true}, // secret rotation
		{Key: "APP_NAME", Value: secret.New("myapp"), Secret: false},    // unchanged
		{Key: "DB_PASSWORD", Value: secret.New("p1"), Secret: false},    // secret→plain downgrade
		{Key: "LOG_LEVEL", Value: secret.New("debug"), Secret: false},   // plain change
		{Key: "NEW_KEY", Value: secret.New("v"), Secret: false},         // added
	}
	d := Diff(current, imported)
	if len(d.Added) != 1 || d.Added[0] != "NEW_KEY" {
		t.Errorf("added wrong: %v", d.Added)
	}
	if len(d.Unchanged) != 1 || d.Unchanged[0] != "APP_NAME" {
		t.Errorf("unchanged wrong: %v", d.Unchanged)
	}
	if len(d.Changed) != 1 || d.Changed[0] != "LOG_LEVEL" {
		t.Errorf("changed wrong: %v", d.Changed)
	}
	// API_TOKEN rotation + DB_PASSWORD downgrade both need a per-secret confirm.
	if len(d.Rotations) != 2 || !d.NeedsRotationConfirm() {
		t.Errorf("rotations wrong: %v", d.Rotations)
	}
}
