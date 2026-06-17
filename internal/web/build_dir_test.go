package web

import "testing"

func TestFilesInDir(t *testing.T) {
	files := []string{
		"go.mod", "main.go", "package.json",
		"dns-resolver/go.mod", "dns-resolver/main.go", "dns-resolver/internal/x.go",
		"./README.md",
	}

	top := filesInDir(files, "")
	if !top["go.mod"] || !top["package.json"] || !top["README.md"] {
		t.Errorf("top-level set wrong: %v", top)
	}
	if top["main.go"] != true || top["x.go"] {
		t.Errorf("top-level set should hold direct files only: %v", top)
	}

	sub := filesInDir(files, "dns-resolver")
	if !sub["go.mod"] || !sub["main.go"] {
		t.Errorf("subdir set should surface its direct files (go.mod/main.go): %v", sub)
	}
	if sub["x.go"] {
		t.Error("nested files must NOT leak into the subdir detection set")
	}
	if sub["package.json"] {
		t.Error("the repo-root package.json must NOT appear in the subdir set (this is the polyglot-monorepo bug)")
	}

	// "./dir/" forms normalize the same way.
	if got := filesInDir(files, "./dns-resolver/"); !got["go.mod"] || got["x.go"] {
		t.Errorf("normalized dir form mismatch: %v", got)
	}
}
