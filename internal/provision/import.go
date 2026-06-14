package provision

import (
	"errors"
	"strings"

	"github.com/helmsman/helmsman/internal/compose"
)

// MaxPasteBytes caps a pasted compose/Dockerfile so a hostile paste can never be
// buffered unbounded (plan §7: size-cap the paste).
const MaxPasteBytes = 512 << 10

// ErrPasteTooLarge is returned when a paste exceeds MaxPasteBytes.
var ErrPasteTooLarge = errors.New("paste exceeds the size cap")

// Import is the Mode-2 validating importer (plan §7): it is NOT an interpreter.
// It size-caps the paste and runs it straight through the §5.6 chokepoint
// (compose.ValidateBytes resolves ${VAR}/.env FIRST, rejects YAML aliases +
// multi-doc, allowlists keys, denies the dangerous set, and confines every bind
// under runDir). The caller decides commit vs reject by compose_validation.mode.
func Import(pasted []byte, env compose.Env, runDir string, opts compose.Options) (compose.Result, error) {
	if len(pasted) > MaxPasteBytes {
		return compose.Result{}, ErrPasteTooLarge
	}
	res := compose.ValidateBytes(pasted, env, runDir, opts)
	res.SortViolations()
	return res, nil
}

// dockerfileWarnings flags instructions a pasted Dockerfile is SCANNED for (it is
// never built here — plan §7). The scan is advisory: an actual build is the same
// §0-gated write-plane action that re-confines its context.
var dockerfileWarnings = []struct {
	needle string
	reason string
}{
	{"add http://", "ADD <url> fetches over the network at build time; prefer COPY"},
	{"add https://", "ADD <url> fetches over the network at build time; prefer COPY"},
	{"--privileged", "privileged build steps are unsafe"},
}

// ScanDockerfile returns advisory warnings for a pasted Dockerfile (size-capped).
// It never executes or builds anything.
func ScanDockerfile(b []byte) ([]string, error) {
	if len(b) > MaxPasteBytes {
		return nil, ErrPasteTooLarge
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		for _, w := range dockerfileWarnings {
			if strings.Contains(l, w.needle) {
				out = append(out, w.reason)
			}
		}
	}
	return out, nil
}
