// Package cfgfile implements managed config files (plan §7.4): a SELECTIVE,
// single-pass renderer that fills ONLY Helmsman's own `{{hm.<key>}}` delimiter
// and copies everything else — the app's `${…}`, `$VAR`, Go `{{ }}`, and even
// `{{hmFoo}}` (no dot) — byte-identical. It is a byte scanner, NOT a template
// engine (no conditionals/loops/functions/shell). Output is emitted, never
// re-scanned, so a resolved secret containing `{{hm.X}}` can't trigger a second
// pass. Every `{{hm.X}}` resolves only via the file's explicit bindings allowlist
// and fails closed (never empty string) on anything unknown.
package cfgfile

import (
	"errors"
	"fmt"
	"strings"
)

const hmPrefix = "{{hm."

// Resolver returns a binding's value and whether it is secret-bearing.
type Resolver func(key string) (value string, secret bool, err error)

var (
	// ErrUnknownBinding means a well-formed {{hm.X}} had no binding (fail-closed).
	ErrUnknownBinding = errors.New("cfgfile: unknown binding")
	// ErrBadValue means a resolved value contained NUL or CR/LF.
	ErrBadValue = errors.New("cfgfile: resolved value contains NUL or newline")
)

// Render performs the selective substitution. It returns the rendered bytes and
// whether any secret-bearing binding was used. Any unknown binding, resolve
// error, or unsafe resolved value is a hard error (fail-closed).
func Render(template []byte, resolve Resolver) (out []byte, secretBearing bool, err error) {
	out = make([]byte, 0, len(template))
	i := 0
	for i < len(template) {
		if hasPrefixAt(template, i, hmPrefix) {
			key, end, isToken := parseToken(template, i)
			if isToken {
				val, sec, rerr := resolve(key)
				if rerr != nil {
					return nil, false, fmt.Errorf("binding %q: %w", key, rerr)
				}
				if err := hygiene(val); err != nil {
					return nil, false, fmt.Errorf("binding %q: %w", key, err)
				}
				if sec {
					secretBearing = true
				}
				out = append(out, val...) // emitted, NEVER re-scanned
				i = end
				continue
			}
			// Not a well-formed Helmsman token: emit "{{" literally and rescan the
			// remainder as ordinary data (so `{{hm.foo bar}}`, `{{hmFoo}}`, etc.
			// survive byte-identical).
			out = append(out, '{', '{')
			i += 2
			continue
		}
		out = append(out, template[i])
		i++
	}
	return out, secretBearing, nil
}

// parseToken tries to read a `{{hm.<key>}}` at position i. On success it returns
// the key, the index just past the closing `}}`, and true.
func parseToken(b []byte, i int) (key string, end int, ok bool) {
	j := i + len(hmPrefix)
	start := j
	for j < len(b) && isKeyChar(b[j]) {
		j++
	}
	if j == start { // empty key → not a token
		return "", 0, false
	}
	if !hasPrefixAt(b, j, "}}") {
		return "", 0, false
	}
	return string(b[start:j]), j + 2, true
}

func hasPrefixAt(b []byte, i int, s string) bool {
	if i+len(s) > len(b) {
		return false
	}
	return string(b[i:i+len(s)]) == s
}

// isKeyChar is the binding-key grammar: a simple, safe identifier.
func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// hygiene rejects a resolved value that could break or inject config lines
// regardless of the declared format (plan §7.4 red-team).
func hygiene(v string) error {
	if strings.ContainsAny(v, "\x00\r\n") {
		return ErrBadValue
	}
	return nil
}
