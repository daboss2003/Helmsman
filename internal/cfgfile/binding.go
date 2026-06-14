package cfgfile

import (
	"fmt"
	"regexp"
	"strings"
)

// Binding maps a template key ({{hm.<Key>}}) to a typed source (plan §7.4).
type Binding struct {
	Key    string // the {{hm.<Key>}} placeholder name
	Source string // env:NAME | secret:NAME | cert:<binding>.<crt|key|ca> | app:<field>
}

var (
	bindingKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	envNameRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	certArgRe    = regexp.MustCompile(`^[A-Za-z0-9_-]+\.(crt|key|ca)$`)
)

// appFields is the fixed, safe set an app:<field> source may name (never free
// text). public_hostname / upstream arrive with the edge (M11).
var appFields = map[string]bool{"slug": true, "public_hostname": true, "upstream": true}

// ValidKey reports whether key is a valid {{hm.<key>}} binding name.
func ValidKey(key string) bool { return bindingKeyRe.MatchString(key) }

// ParseSource splits a binding source into its kind and argument, validating the
// argument grammar per kind. It does NOT resolve anything.
func ParseSource(source string) (kind, arg string, err error) {
	i := strings.IndexByte(source, ':')
	if i <= 0 {
		return "", "", fmt.Errorf("binding source %q must be kind:arg", source)
	}
	kind, arg = source[:i], source[i+1:]
	switch kind {
	case "env", "secret":
		if !envNameRe.MatchString(arg) {
			return "", "", fmt.Errorf("%s name %q is not a valid env name", kind, arg)
		}
	case "cert":
		if !certArgRe.MatchString(arg) {
			return "", "", fmt.Errorf("cert source %q must be <binding>.<crt|key|ca>", arg)
		}
	case "app":
		if !appFields[arg] {
			return "", "", fmt.Errorf("app field %q is not allowed", arg)
		}
	default:
		return "", "", fmt.Errorf("unknown binding kind %q", kind)
	}
	return kind, arg, nil
}

// ValidateBindings checks the binding set: valid keys, no duplicates, parseable
// sources. Returns the first violation.
func ValidateBindings(bindings []Binding) error {
	seen := map[string]bool{}
	for _, b := range bindings {
		if !ValidKey(b.Key) {
			return fmt.Errorf("invalid binding key %q", b.Key)
		}
		if seen[b.Key] {
			return fmt.Errorf("duplicate binding key %q", b.Key)
		}
		seen[b.Key] = true
		if _, _, err := ParseSource(b.Source); err != nil {
			return err
		}
	}
	return nil
}

// SecretBearing reports whether any binding draws from a secret source (so the
// rendered file must be stored encrypted and written 0600).
func SecretBearing(bindings []Binding) bool {
	for _, b := range bindings {
		if kind, _, err := ParseSource(b.Source); err == nil && kind == "secret" {
			return true
		}
	}
	return false
}
