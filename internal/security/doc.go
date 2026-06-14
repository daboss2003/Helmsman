// Package security holds the in-repo, dependency-free pieces of the §15 Security
// Assurance Program (milestone M12) — the parts that run as plain `go test ./...`
// on every machine and in CI, with no external tooling required.
//
// It is deliberately small and self-contained:
//
//   - staticlint_test.go — the "custom semgrep rules to author" of §15 Phase 1,
//     implemented as AST walks over the repo source (no semgrep/gosec dependency):
//     no shell command construction outside the sandbox jail; no unguarded outbound
//     HTTP (everything must go through the pinned SSRF-safe client); the web layer
//     must use html/template (never text/template) and never wrap untrusted content
//     in template.HTML/JS/CSS/URL.
//
// The heavyweight Phase-1/3 tooling that needs binaries (govulncheck, staticcheck,
// gosec, gitleaks, trivy/grype, semgrep, the DAST/pentest/fuzz cadence) is driven
// by scripts/security-gate.sh, which runs each tool IF it is installed and is the
// CI entrypoint. The per-invariant SBD-1..8 "Layer A" tests live with the code they
// guard (internal/edge); the authz route-posture gate lives in internal/web
// (it needs the route table). This package is the home for cross-cutting rules.
//
// See docs/security.md for the full program (phases, layers, exit criteria, and the
// split between what is automated here and what is an operational process).
package security
