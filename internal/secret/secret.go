// Package secret holds the two secrecy primitives the whole binary depends on:
// the Redacted type (a value that refuses to serialize itself in the clear) and
// the AES-256-GCM Cipher used for secrets at rest (plan §5.5).
//
// Custom lint rule (CONTRIBUTING / plan §15): any type that holds a secret must
// have String()/MarshalJSON that return the redaction marker. Redacted is the
// canonical implementation; reach for it instead of a bare string.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// Marker is what a redacted value renders as anywhere it might be logged.
const Marker = "••••" // ••••

// Redacted wraps a secret string. Its String/MarshalJSON/MarshalText/GoString
// all return the redaction marker, so a secret can never leak into a log line,
// an error, a JSON response, %v/%+v/%#v formatting, or a template by accident.
// Reveal() is the single, greppable place the plaintext escapes.
type Redacted struct {
	v string
}

// New wraps a plaintext secret.
func New(s string) Redacted { return Redacted{v: s} }

// Reveal returns the underlying plaintext. This is the only API that does so;
// every call site is intentionally easy to audit (grep for ".Reveal(").
func (r Redacted) Reveal() string { return r.v }

// IsZero reports whether the secret is empty.
func (r Redacted) IsZero() bool { return r.v == "" }

// Equal compares the secret to a candidate in constant time.
func (r Redacted) Equal(candidate string) bool {
	return subtle.ConstantTimeCompare([]byte(r.v), []byte(candidate)) == 1
}

// String returns the redaction marker (empty stays empty so we never imply a
// secret exists where one does not).
func (r Redacted) String() string {
	if r.v == "" {
		return ""
	}
	return Marker
}

// GoString covers the %#v verb.
func (r Redacted) GoString() string { return "secret.Redacted{" + r.String() + "}" }

// Format implements fmt.Formatter so EVERY verb — including numeric/other verbs
// like %d/%x/%g that fmt would otherwise satisfy via reflection over the
// unexported field — routes through the redaction marker. Without this, a
// wrong-verb format string (e.g. `%d`) would print the plaintext (review #5).
func (r Redacted) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, r.String())
}

// MarshalJSON ensures encoding/json never emits the plaintext.
func (r Redacted) MarshalJSON() ([]byte, error) { return []byte(`"` + r.String() + `"`), nil }

// MarshalText covers encoders that prefer TextMarshaler (incl. some YAML paths).
func (r Redacted) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

var (
	// ErrDecrypt is returned for any open failure. It is intentionally opaque so
	// it cannot become a decryption oracle.
	ErrDecrypt = errors.New("secret: decryption failed")
	// ErrKeyLen is returned when a key is not exactly 32 bytes.
	ErrKeyLen = errors.New("secret: key must be 32 bytes (AES-256)")
)

const nonceLen = 12 // GCM standard nonce size

// Cipher seals/opens blobs with AES-256-GCM. It optionally holds a previous key
// so a rotation (encryption_key_previous, plan §5.5) can still open old rows;
// Seal always uses the current key.
type Cipher struct {
	current  cipher.AEAD
	previous cipher.AEAD // may be nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrKeyLen
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewCipher builds a Cipher from the current key and an optional previous key
// (pass nil/empty when not rotating).
func NewCipher(key, prevKey []byte) (*Cipher, error) {
	cur, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	c := &Cipher{current: cur}
	if len(prevKey) > 0 {
		prev, err := newAEAD(prevKey)
		if err != nil {
			return nil, err
		}
		c.previous = prev
	}
	return c, nil
}

// Seal encrypts plaintext under the current key. Output is nonce||ciphertext+tag.
func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Append the sealed bytes after the nonce; cap the slice to nonceLen so the
	// nonce buffer is never reused as the dst scratch space.
	return c.current.Seal(nonce[:nonceLen:nonceLen], nonce, plaintext, nil), nil
}

// Open decrypts a blob, trying the current key then the previous key.
func (c *Cipher) Open(blob []byte) ([]byte, error) {
	if len(blob) < nonceLen+16 { // 16 = GCM tag
		return nil, ErrDecrypt
	}
	nonce, ct := blob[:nonceLen], blob[nonceLen:]
	if pt, err := c.current.Open(nil, nonce, ct, nil); err == nil {
		return pt, nil
	}
	if c.previous != nil {
		if pt, err := c.previous.Open(nil, nonce, ct, nil); err == nil {
			return pt, nil
		}
	}
	return nil, ErrDecrypt
}
