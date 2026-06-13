package secret

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestRedactedNeverLeaks(t *testing.T) {
	r := New("hunter2-super-secret")

	if got := r.String(); got != Marker {
		t.Errorf("String() = %q, want %q", got, Marker)
	}
	if got := fmt.Sprintf("%v", r); got != Marker {
		t.Errorf("%%v = %q, want %q", got, Marker)
	}
	if got := fmt.Sprintf("%s", r); got != Marker {
		t.Errorf("%%s = %q, want %q", got, Marker)
	}
	if got := fmt.Sprintf("%#v", r); got == "" || got == "secret.Redacted{v:\"hunter2-super-secret\"}" {
		t.Errorf("%%#v leaked the secret: %q", got)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == `"hunter2-super-secret"` {
		t.Errorf("MarshalJSON leaked the secret: %s", b)
	}
	// And inside a struct (the common accidental-log path).
	wrapper := struct {
		Name string
		Key  Redacted
	}{"db", r}
	jb, _ := json.Marshal(wrapper)
	if contains(string(jb), "hunter2") {
		t.Errorf("struct JSON leaked the secret: %s", jb)
	}
	// Reveal is the one sanctioned escape.
	if r.Reveal() != "hunter2-super-secret" {
		t.Errorf("Reveal() did not return the plaintext")
	}
}

func TestRedactedNeverLeaksNonStringVerbs(t *testing.T) {
	r := New("hunter2-super-secret")
	verbs := []string{"%d", "%x", "%X", "%t", "%g", "%c", "%o", "%b", "%e", "%f", "%U", "%q", "%+v", "%#v"}
	for _, verb := range verbs {
		if out := fmt.Sprintf(verb, r); contains(out, "hunter2") {
			t.Errorf("verb %s leaked plaintext: %q", verb, out)
		}
	}
}

func TestRedactedEmptyStaysEmpty(t *testing.T) {
	if got := New("").String(); got != "" {
		t.Errorf("empty Redacted String() = %q, want empty", got)
	}
}

func TestCipherRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := NewCipher(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("a database url with a password in it")
	blob, err := c.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(blob), "password") {
		t.Errorf("ciphertext contains plaintext")
	}
	got, err := c.Open(blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pt) {
		t.Errorf("roundtrip mismatch: %q != %q", got, pt)
	}
}

func TestCipherTamperFails(t *testing.T) {
	key := make([]byte, 32)
	c, _ := NewCipher(key, nil)
	blob, _ := c.Seal([]byte("secret"))
	blob[len(blob)-1] ^= 0xff // flip a tag bit
	if _, err := c.Open(blob); err == nil {
		t.Errorf("tampered blob opened without error (GCM auth bypass)")
	}
}

func TestCipherKeyRotation(t *testing.T) {
	prev := make([]byte, 32)
	cur := make([]byte, 32)
	for i := range cur {
		cur[i] = 0xAB
	}
	// seal under previous key
	cprev, _ := NewCipher(prev, nil)
	blob, _ := cprev.Seal([]byte("rotate me"))

	// new cipher with current+previous can still open old blobs
	c, _ := NewCipher(cur, prev)
	got, err := c.Open(blob)
	if err != nil || string(got) != "rotate me" {
		t.Errorf("rotation open failed: %v / %q", err, got)
	}
	// new seals use current; previous-only cipher cannot open them
	nb, _ := c.Seal([]byte("new data"))
	if _, err := cprev.Open(nb); err == nil {
		t.Errorf("previous-only cipher opened a current-key blob")
	}
}

func TestKeyLenEnforced(t *testing.T) {
	if _, err := NewCipher(make([]byte, 16), nil); err != ErrKeyLen {
		t.Errorf("expected ErrKeyLen for 16-byte key, got %v", err)
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
