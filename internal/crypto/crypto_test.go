package crypto

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func mustDecode(t *testing.T, secret string) []byte {
	t.Helper()
	secret = strings.ToUpper(strings.TrimSpace(secret))
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode totp secret: %v", err)
	}
	return b
}

func TestPasswordHashVerify(t *testing.T) {
	enc, err := HashPassword([]byte("correct horse battery staple"), DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(enc, []byte("correct horse battery staple"))
	if err != nil || !ok {
		t.Errorf("correct password did not verify: ok=%v err=%v", ok, err)
	}
	ok, _ = VerifyPassword(enc, []byte("wrong password"))
	if ok {
		t.Errorf("wrong password verified")
	}
}

func TestParseArgon2RejectsGarbage(t *testing.T) {
	bad := []string{
		"",
		"not a hash",
		"$argon2i$v=19$m=8,t=2,p=1$c2FsdA$aGFzaA",               // argon2i, not id
		"$argon2id$v=99$m=8,t=2,p=1$c2FsdA$aGFzaA",              // wrong version
		"$argon2id$v=19$m=0,t=0,p=0$c2FsdA$aGFzaA",              // zero params
		"$argon2id$v=19$m=8192,t=2,p=1$$aGFzaGhhc2hoYXNoaGFzaA", // empty salt (review #20)
	}
	for _, b := range bad {
		if _, _, _, err := ParseArgon2(b); err == nil {
			t.Errorf("ParseArgon2(%q) accepted invalid hash", b)
		}
	}
}

func TestTOTP(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	// derive the current code by brute-checking all codes is not possible; instead
	// assert the code at `now` validates and a clearly-wrong code does not.
	// Generate the code the same way the validator does for the current step.
	code := currentCode(t, secret, now)
	if !ValidateTOTP(secret, code, now, 1) {
		t.Errorf("valid TOTP code rejected")
	}
	if ValidateTOTP(secret, "000000", now.Add(10*time.Minute), 1) {
		// extremely unlikely to be the real code 10 minutes later
		t.Errorf("stale/garbage TOTP code accepted")
	}
	if ValidateTOTP(secret, code, now.Add(5*time.Minute), 1) {
		t.Errorf("TOTP code valid far outside its window")
	}
}

// currentCode reproduces the validator's code for time t (skew 0 window).
func currentCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	// Reuse the package's own hotp via ValidateTOTP semantics: search the 1M space
	// would be slow, so instead recompute using the exported-ish path: we know
	// ValidateTOTP uses hotp(key, step). Recompute here.
	key := mustDecode(t, secret)
	step := uint64(at.Unix() / totpPeriod)
	return hotp(key, step)
}
