package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests are the §15 Phase-1 "custom rules" — the high-signal, generic-tool-
// missing checks — implemented as AST walks so they run with `go test` and no
// external binary. Each rule is fail-closed: a NEW violation anywhere in the tree
// breaks the build, so a future change can't silently reintroduce a banned pattern.
// Each rule also has a self-test (against a known-bad snippet) proving the detector
// actually fires — a linter that has rotted into a no-op is worse than none.

// repoRoot walks up from the test's CWD to the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod above the test directory")
		}
		dir = parent
	}
}

// goFile is one parsed non-test source file with its repo-relative (slash) path.
type goFile struct {
	rel  string
	fset *token.FileSet
	file *ast.File
}

// walkSource parses every non-test .go file under internal/ and cmd/ (the code we
// ship), skipping vendored/generated trees. _test.go files are excluded so a rule's
// own banned-pattern literals (and test fixtures) never self-trip.
func walkSource(t *testing.T) []goFile {
	t.Helper()
	root := repoRoot(t)
	var out []goFile
	for _, sub := range []string{"internal", "cmd"} {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); name == "vendor" || name == "testdata" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, path)
			out = append(out, goFile{rel: filepath.ToSlash(rel), fset: fset, file: f})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("walkSource found no files — wrong root?")
	}
	return out
}

// parseSnippet builds a goFile from inline source, for the self-tests.
func parseSnippet(t *testing.T, rel, src string) goFile {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse snippet: %v", err)
	}
	return goFile{rel: rel, fset: fset, file: f}
}

func litString(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

func line(gf goFile, pos token.Pos) int { return gf.fset.Position(pos).Line }

// --- detectors (pure: goFile → violation messages) ---

var shellBinaries = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true,
	"/bin/sh": true, "/bin/bash": true, "/bin/zsh": true, "/usr/bin/sh": true,
	"/usr/bin/bash": true, "cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true,
}

// findShellExec flags an exec.Command/CommandContext call carrying BOTH a shell
// binary and a "-c"/"/c" arg (the shell-injection shape). git's `-c key=value`
// config flags carry no shell name, so they are not flagged.
func findShellExec(gf goFile) []string {
	var v []string
	ast.Inspect(gf.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !isSelector(call.Fun, "exec", "Command") && !isSelector(call.Fun, "exec", "CommandContext") {
			return true
		}
		hasShell, hasDashC := false, false
		for _, a := range call.Args {
			if s, ok := litString(a); ok {
				if shellBinaries[s] {
					hasShell = true
				}
				if s == "-c" || s == "/c" {
					hasDashC = true
				}
			}
		}
		if hasShell && hasDashC {
			v = append(v, gf.rel+":"+strconv.Itoa(line(gf, call.Pos())))
		}
		return true
	})
	return v
}

func findUnguardedHTTP(gf goFile) []string {
	banned := map[string]bool{"Get": true, "Post": true, "Head": true, "PostForm": true, "DefaultClient": true, "DefaultTransport": true}
	var v []string
	ast.Inspect(gf.file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "http" && banned[sel.Sel.Name] {
			v = append(v, gf.rel+":"+strconv.Itoa(line(gf, sel.Pos()))+" http."+sel.Sel.Name)
		}
		return true
	})
	return v
}

func findTextTemplateImport(gf goFile) []string {
	var v []string
	for _, imp := range gf.file.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == "text/template" {
			v = append(v, gf.rel)
		}
	}
	return v
}

func findDynamicTemplateConversion(gf goFile) []string {
	dangerous := map[string]bool{"HTML": true, "JS": true, "CSS": true, "URL": true, "HTMLAttr": true, "JSStr": true}
	var v []string
	ast.Inspect(gf.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !dangerous[sel.Sel.Name] {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "template" {
			return true
		}
		if _, isLit := litString(call.Args[0]); !isLit {
			v = append(v, gf.rel+":"+strconv.Itoa(line(gf, call.Pos()))+" template."+sel.Sel.Name)
		}
		return true
	})
	return v
}

// shellExecAllowed: ONLY the setup sandbox may build `<shell> -c <script>` — its
// purpose is to run the operator's setup script via /bin/sh -c INSIDE a disposable,
// egress-restricted, non-privileged, dropped-caps container (plan §9); the shell is
// the sandboxed payload, not a Helmsman command-injection surface. Everything else
// uses static argv with no shell, ever (§15 Phase 2).
var shellExecAllowed = map[string]bool{"internal/sandbox": true}

// --- repo-wide gates (fail-closed on any violation) ---

func TestNoShellExec(t *testing.T) {
	for _, gf := range walkSource(t) {
		if shellExecAllowed[filepath.ToSlash(filepath.Dir(gf.rel))] {
			continue
		}
		for _, v := range findShellExec(gf) {
			t.Errorf("SEC-1 (no shell): %s constructs a shell `-c` command — use static argv, never a shell", v)
		}
	}
}

func TestNoUnguardedHTTP(t *testing.T) {
	for _, gf := range walkSource(t) {
		for _, v := range findUnguardedHTTP(gf) {
			t.Errorf("SEC-2 (no unguarded outbound): %s — route outbound through the pinned SSRF-safe client", v)
		}
	}
}

func TestWebUsesHTMLTemplate(t *testing.T) {
	for _, gf := range walkSource(t) {
		if !strings.HasPrefix(gf.rel, "internal/web/") {
			continue
		}
		for _, v := range findTextTemplateImport(gf) {
			t.Errorf("SEC-3 (html escaping): %s imports text/template — the web layer must use html/template", v)
		}
	}
}

func TestNoDynamicTemplateTypeConversion(t *testing.T) {
	for _, gf := range walkSource(t) {
		for _, v := range findDynamicTemplateConversion(gf) {
			t.Errorf("SEC-3 (escape bypass): %s converts a non-constant — only constant literals may bypass escaping", v)
		}
	}
}

// --- self-tests: prove each detector fires (guards against a no-op linter) ---

func TestDetectorsFireOnKnownBad(t *testing.T) {
	cases := []struct {
		name string
		src  string
		find func(goFile) []string
	}{
		{"shell-exec", `package p
import "os/exec"
func f(x string) { exec.Command("/bin/sh", "-c", x) }`, findShellExec},
		{"unguarded-http", `package p
import "net/http"
func f() { http.Get("http://x") }`, findUnguardedHTTP},
		{"text-template", `package p
import _ "text/template"`, findTextTemplateImport},
		{"dynamic-template-conv", `package p
import "html/template"
func f(s string) template.HTML { return template.HTML(s) }`, findDynamicTemplateConversion},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gf := parseSnippet(t, "bad.go", c.src)
			if got := c.find(gf); len(got) == 0 {
				t.Errorf("detector %q did not fire on known-bad source (it has rotted into a no-op)", c.name)
			}
		})
	}
	// And prove the no-op cases DON'T fire (no false positives on safe shapes).
	safe := parseSnippet(t, "ok.go", `package p
import ("os/exec"; "html/template")
func f() { exec.Command("git", "-c", "core.hooksPath=/dev/null", "status") }
func g() template.HTML { return template.HTML("<b>constant</b>") }`)
	if got := findShellExec(safe); len(got) != 0 {
		t.Errorf("SEC-1 false positive on git `-c` config flags: %v", got)
	}
	if got := findDynamicTemplateConversion(safe); len(got) != 0 {
		t.Errorf("SEC-3 false positive on a constant template.HTML: %v", got)
	}
}
