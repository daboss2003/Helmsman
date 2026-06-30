package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238). Implemented in-tree (HMAC-SHA1, 6 digits, 30s) to
// keep the dependency surface minimal — the single-static-binary ethos (plan §2).
const (
	totpDigits      = 6
	totpPeriod      = 30 // seconds
	totpSecretBytes = 20
)

// GenerateTOTPSecret returns a base32 (RFC 4648, no padding) secret suitable for
// `mooring gen-totp` and authenticator apps.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, totpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateTOTPCode returns the TOTP code for secret at time t (RFC 6238). Useful
// for provisioning/display and for tests.
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(secret, " ", "")))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return "", err
	}
	return hotp(key, uint64(t.Unix()/totpPeriod)), nil
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	code %= 1_000_000
	return fmt.Sprintf("%0*d", totpDigits, code)
}

// ValidateTOTP reports whether code is valid for secret at time t, allowing
// ±skew steps of clock drift. Per plan §5.9 the TOTP window is NOT widened under
// detected skew; callers pass skew=1 as the normal allowance.
func ValidateTOTP(secret, code string, t time.Time, skew int) bool {
	_, ok := ValidateTOTPStep(secret, code, t, skew)
	return ok
}

// ValidateTOTPStep is like ValidateTOTP but also returns the matched time step,
// so callers can persist a consumed-step watermark and reject replays of a code
// within its validity window (review #4). The whole window is scanned in
// constant time (no early return) so a match position can't be timed.
func ValidateTOTPStep(secret, code string, t time.Time, skew int) (matched uint64, ok bool) {
	secret = strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(secret, " ", "")))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return 0, false
	}
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	step := uint64(t.Unix() / totpPeriod)
	for d := -skew; d <= skew; d++ {
		c := step
		if d < 0 {
			c -= uint64(-d)
		} else {
			c += uint64(d)
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, c)), []byte(code)) == 1 {
			matched = c
			ok = true
		}
	}
	return matched, ok
}
