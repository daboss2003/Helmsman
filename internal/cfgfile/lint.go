package cfgfile

import (
	"regexp"
	"strings"
)

// LiteralSecretLint detects credential-shaped LITERALS in a config-file body
// that has NO secret: binding (plan §7.4): such material should be a
// {{hm.secret:KEY}} binding, not pasted in clear (which would also be written
// world-ish and stored unencrypted). Returns a reason + true on a hit.
func LiteralSecretLint(body []byte) (string, bool) {
	s := string(body)
	if strings.Contains(s, "-----BEGIN") && privKeyRe.MatchString(s) {
		return "contains a PEM private key — bind it as {{hm.secret:KEY}} instead of pasting it", true
	}
	for _, m := range tokenMarkers {
		if strings.Contains(s, m.needle) {
			return "looks like a " + m.what + " — bind it as {{hm.secret:KEY}}", true
		}
	}
	if highEntropyRun(s) {
		return "contains a long high-entropy token — bind secrets as {{hm.secret:KEY}}", true
	}
	return "", false
}

var privKeyRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)

var tokenMarkers = []struct{ needle, what string }{
	{"AKIA", "AWS access key id"},
	{"ASIA", "AWS temporary key id"},
	{"ghp_", "GitHub token"},
	{"github_pat_", "GitHub token"},
	{"xoxb-", "Slack token"},
	{"xoxp-", "Slack token"},
	{"eyJ", "JWT"},
	{"-----BEGIN OPENSSH PRIVATE KEY-----", "SSH private key"},
}

// b64run matches a run of base64/hex-ish characters.
var b64run = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)

// highEntropyRun reports whether the body has a long token with mixed character
// classes (a crude high-entropy signal for pasted credentials).
func highEntropyRun(s string) bool {
	for _, tok := range b64run.FindAllString(s, -1) {
		var hasLower, hasUpper, hasDigit bool
		for _, c := range tok {
			switch {
			case c >= 'a' && c <= 'z':
				hasLower = true
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			case c >= '0' && c <= '9':
				hasDigit = true
			}
		}
		classes := 0
		for _, b := range []bool{hasLower, hasUpper, hasDigit} {
			if b {
				classes++
			}
		}
		if classes >= 3 && len(tok) >= 40 {
			return true
		}
	}
	return false
}
