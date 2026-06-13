package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
)

// RandomBytes returns n cryptographically random bytes or panics — a CSPRNG
// failure is unrecoverable and must never be swallowed into a weak token.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto: CSPRNG failure: " + err.Error())
	}
	return b
}

// RandomToken returns n random bytes encoded as URL-safe base64 (no padding).
// Used for session ids (32 bytes = 256 bits, plan §5.3) and webhook tokens.
func RandomToken(n int) string {
	return base64.RawURLEncoding.EncodeToString(RandomBytes(n))
}

// ConstantTimeEqualString compares two strings without leaking length-prefixed
// timing for equal-length inputs.
func ConstantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
