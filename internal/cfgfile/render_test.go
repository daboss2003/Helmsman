package cfgfile

import (
	"errors"
	"strings"
	"testing"
)

// fixedResolver resolves a small binding map; unknown keys fail closed.
func fixedResolver(m map[string]string, secrets map[string]bool) Resolver {
	return func(key string) (string, bool, error) {
		v, ok := m[key]
		if !ok {
			return "", false, ErrUnknownBinding
		}
		return v, secrets[key], nil
	}
}

func TestRenderReplacesOnlyHmTokens(t *testing.T) {
	tmpl := []byte("cookie = {{hm.node_cookie}}\nuser = ${username}\ngo = {{ .Foo }}\nnodot = {{hmFoo}}\n")
	out, sec, err := Render(tmpl, fixedResolver(map[string]string{"node_cookie": "abc123"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	want := "cookie = abc123\nuser = ${username}\ngo = {{ .Foo }}\nnodot = {{hmFoo}}\n"
	if got != want {
		t.Errorf("render:\n got %q\nwant %q", got, want)
	}
	if sec {
		t.Error("non-secret render reported secret-bearing")
	}
}

func TestRenderPreservesAppPlaceholdersByteIdentical(t *testing.T) {
	// app placeholders that must survive untouched
	for _, s := range []string{
		"${username}", "$VAR", "%(topic)s", "{{ .Clientid }}", "{{hmFoo}}",
		"{{hm.}}", "{{hm.foo bar}}", "{{hm.foo", "{{ hm.x }}", "{{HM.x}}",
	} {
		out, _, err := Render([]byte(s), fixedResolver(nil, nil))
		if err != nil {
			t.Errorf("Render(%q) errored: %v", s, err)
			continue
		}
		if string(out) != s {
			t.Errorf("Render(%q) = %q, want byte-identical", s, string(out))
		}
	}
}

func TestRenderUnknownBindingFailsClosed(t *testing.T) {
	_, _, err := Render([]byte("x = {{hm.unknown}}"), fixedResolver(map[string]string{"known": "v"}, nil))
	if !errors.Is(err, ErrUnknownBinding) {
		t.Errorf("unknown binding: got %v, want ErrUnknownBinding (never empty string)", err)
	}
}

func TestRenderSecretBearingFlag(t *testing.T) {
	_, sec, err := Render([]byte("{{hm.pw}}"), fixedResolver(map[string]string{"pw": "s3cret"}, map[string]bool{"pw": true}))
	if err != nil || !sec {
		t.Errorf("secret binding should flag secret-bearing: sec=%v err=%v", sec, err)
	}
}

// The critical anti-rescan property: a resolved value that itself contains a
// {{hm.X}} must NOT trigger a second substitution pass.
func TestRenderOutputNeverRescanned(t *testing.T) {
	out, _, err := Render([]byte("v = {{hm.a}}"), fixedResolver(map[string]string{"a": "{{hm.b}}", "b": "SHOULD-NOT-APPEAR"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "v = {{hm.b}}" {
		t.Errorf("output was re-scanned: %q", out)
	}
}

// Resolved values with NUL/CR/LF are rejected (config-line injection).
func TestRenderValueHygiene(t *testing.T) {
	for _, bad := range []string{"line1\nline2", "x\ry", "nul\x00"} {
		_, _, err := Render([]byte("{{hm.v}}"), fixedResolver(map[string]string{"v": bad}, nil))
		if !errors.Is(err, ErrBadValue) {
			t.Errorf("value %q: got %v, want ErrBadValue", bad, err)
		}
	}
}

func TestLiteralSecretLint(t *testing.T) {
	hits := []string{
		"key = -----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
		"aws = AKIAIOSFODNN7EXAMPLE",
		"tok = ghp_0123456789abcdefghij",
		"jwt = eyJhbGciOiJIUzI1Ni012345",
		"k = " + strings.Repeat("aB3", 20),
	}
	for _, h := range hits {
		if _, hit := LiteralSecretLint([]byte(h)); !hit {
			t.Errorf("lint missed a literal secret: %q", h)
		}
	}
	clean := "log_level = info\nworkers = 4\ncookie = {{hm.secret:NODE_COOKIE}}\n"
	if reason, hit := LiteralSecretLint([]byte(clean)); hit {
		t.Errorf("lint false-positive on clean body: %s", reason)
	}
}

func TestParseSource(t *testing.T) {
	good := []string{"env:DB_HOST", "secret:NODE_COOKIE", "cert:web.crt", "cert:web.key", "app:slug"}
	for _, s := range good {
		if _, _, err := ParseSource(s); err != nil {
			t.Errorf("ParseSource(%q) errored: %v", s, err)
		}
	}
	bad := []string{"DB_HOST", "env:bad name", "cert:web.pem", "app:arbitrary", "weird:x", ":x"}
	for _, s := range bad {
		if _, _, err := ParseSource(s); err == nil {
			t.Errorf("ParseSource(%q) accepted invalid source", s)
		}
	}
}

func TestValidateBindings(t *testing.T) {
	if err := ValidateBindings([]Binding{{Key: "a", Source: "env:X"}, {Key: "a", Source: "env:Y"}}); err == nil {
		t.Error("duplicate key accepted")
	}
	if !SecretBearing([]Binding{{Key: "a", Source: "secret:S"}}) {
		t.Error("secret source not flagged secret-bearing")
	}
	if SecretBearing([]Binding{{Key: "a", Source: "env:X"}}) {
		t.Error("env source wrongly flagged secret-bearing")
	}
}

// FuzzRender: the renderer must never panic and must never emit a raw {{hm.<key>}}
// for a KNOWN binding (it resolves or errors), and must be byte-stable otherwise.
func FuzzRender(f *testing.F) {
	f.Add("plain text")
	f.Add("{{hm.a}} ${b} {{c}}")
	f.Add("{{hm.")
	f.Add("{{hm.}}{{hm.a}}")
	res := fixedResolver(map[string]string{"a": "VALUE"}, nil)
	f.Fuzz(func(t *testing.T, s string) {
		out, _, err := Render([]byte(s), res)
		if err != nil {
			return // unknown binding / bad value are acceptable hard errors
		}
		if strings.Contains(string(out), "{{hm.a}}") {
			t.Errorf("known binding left unresolved in output for input %q", s)
		}
	})
}
