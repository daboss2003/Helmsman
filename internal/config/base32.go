package config

import (
	"encoding/base32"
	"strings"
)

// decodeBase32 validates an RFC 4648 base32 secret (no padding, case-insensitive)
// — the form `mooring gen-totp` emits.
func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(s, " ", "")))
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
