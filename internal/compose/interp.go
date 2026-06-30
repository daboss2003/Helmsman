// Package compose is the §5.6 allowlist validator — the ONE chokepoint every
// compose document passes before it can reach `docker compose` (plan §5.6). It
// resolves ${VAR}/.env interpolation FIRST (validating before interpolation is a
// known bypass), then rejects any unknown top-level/service key and the dangerous
// set, and confines every bind mount under the app's run_dir.
package compose

import (
	"bufio"
	"strings"
)

// Env is a name→value map used for ${VAR} resolution. It is built from the app's
// .env file (and, later, the encrypted env store) — NEVER from Mooring's own
// process environment, so Mooring secrets can't leak into a compose render.
type Env map[string]string

// ParseEnvFile parses KEY=VALUE lines (a .env file). Blank lines and #comments
// are skipped; values are taken literally (no nested interpolation), matching
// docker compose's .env handling closely enough for validation.
func ParseEnvFile(data []byte) Env {
	env := Env{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(line[len("export "):])
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := line[eq+1:]
		// strip matching surrounding quotes
		if len(val) >= 2 && (val[0] == '"' && val[len(val)-1] == '"' || val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
		env[key] = val
	}
	return env
}

// Interpolate resolves docker-compose-style ${VAR} references in raw text BEFORE
// YAML parsing (plan §5.6 step 1). Supported forms: $VAR, ${VAR}, ${VAR:-def},
// ${VAR-def}, ${VAR:?msg}, ${VAR?msg}; $$ is a literal $. An unset variable with
// no default resolves to "" (compose's default), which the validator then sees.
func Interpolate(raw string, env Env) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c != '$' {
			b.WriteByte(c)
			continue
		}
		// $$ → literal $
		if i+1 < len(raw) && raw[i+1] == '$' {
			b.WriteByte('$')
			i++
			continue
		}
		if i+1 < len(raw) && raw[i+1] == '{' {
			end := strings.IndexByte(raw[i+2:], '}')
			if end < 0 {
				b.WriteByte('$') // unterminated; emit literally
				continue
			}
			expr := raw[i+2 : i+2+end]
			b.WriteString(resolveExpr(expr, env))
			i = i + 2 + end
			continue
		}
		// $VAR (bare): consume a [A-Za-z_][A-Za-z0-9_]* run
		j := i + 1
		if j < len(raw) && isNameStart(raw[j]) {
			k := j + 1
			for k < len(raw) && isNameChar(raw[k]) {
				k++
			}
			name := raw[j:k]
			b.WriteString(env[name])
			i = k - 1
			continue
		}
		b.WriteByte('$')
	}
	return b.String()
}

func resolveExpr(expr string, env Env) string {
	// ${VAR}, ${VAR:-def}, ${VAR-def}, ${VAR:?msg}, ${VAR?msg}
	name := expr
	op, arg := "", ""
	for idx := 0; idx < len(expr); idx++ {
		if expr[idx] == ':' || expr[idx] == '-' || expr[idx] == '?' || expr[idx] == '+' {
			name = expr[:idx]
			rest := expr[idx:]
			if len(rest) >= 2 && rest[0] == ':' {
				op = rest[:2]
				arg = rest[2:]
			} else {
				op = rest[:1]
				arg = rest[1:]
			}
			break
		}
	}
	val, set := env[name]
	switch op {
	case ":-", "-": // default if unset (":-" also if empty)
		if !set || (op == ":-" && val == "") {
			return arg
		}
		return val
	case ":+", "+": // alternate value if set
		if set && (op == "+" || val != "") {
			return arg
		}
		return ""
	default: // "", "?", ":?" → just the value (a required-but-missing var resolves to "")
		return val
	}
}

func isNameStart(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func isNameChar(c byte) bool { return isNameStart(c) || c >= '0' && c <= '9' }
