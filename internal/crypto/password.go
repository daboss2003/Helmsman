// Package crypto holds the password (argon2id), TOTP, and random/constant-time
// primitives for the security spine (plan §5.1, §5.3).
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are tuned small by default (plan §5.1: m≈8 MiB, t=2, p=1) so a
// login can never OOM a tiny box. Raise Memory on a larger host.
type Argon2Params struct {
	Memory      uint32 // KiB
	Time        uint32 // iterations
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultArgon2Params is the small, tiny-box-safe default.
var DefaultArgon2Params = Argon2Params{
	Memory:      8 * 1024, // 8 MiB
	Time:        2,
	Parallelism: 1,
	SaltLen:     16,
	KeyLen:      32,
}

var (
	// ErrInvalidHash means the encoded hash is not a parseable argon2id PHC string.
	ErrInvalidHash = errors.New("crypto: invalid argon2id hash")
	// ErrIncompatibleVersion means the argon2 version is not the one we support.
	ErrIncompatibleVersion = errors.New("crypto: incompatible argon2 version")
)

// HashPassword produces an argon2id PHC string for the given password.
func HashPassword(password []byte, p Argon2Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(password, salt, p.Time, p.Memory, p.Parallelism, p.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key),
	), nil
}

// ParseArgon2 validates and decodes an argon2id PHC string. It is also the
// fail-closed boot check for auth.password_hash (plan §5.1).
func ParseArgon2(encoded string) (p Argon2Params, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	// "" / "argon2id" / "v=19" / "m=..,t=..,p=.." / salt / hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return p, nil, nil, ErrIncompatibleVersion
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Parallelism); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	if salt, err = b64.DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if hash, err = b64.DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	p.SaltLen = uint32(len(salt))
	p.KeyLen = uint32(len(hash))
	// Reject abnormal parameters, including a too-short salt (review #20): a
	// zero/short salt defeats per-credential salting. 8 bytes is the conventional
	// argon2/PHC minimum.
	if p.Memory == 0 || p.Time == 0 || p.Parallelism == 0 || p.KeyLen < 16 || p.SaltLen < 8 {
		return p, nil, nil, ErrInvalidHash
	}
	return p, salt, hash, nil
}

// VerifyPassword reports whether password matches the encoded argon2id hash. The
// comparison is constant-time. A malformed hash returns (false, error).
func VerifyPassword(encoded string, password []byte) (bool, error) {
	p, salt, want, err := ParseArgon2(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey(password, salt, p.Time, p.Memory, p.Parallelism, p.KeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
