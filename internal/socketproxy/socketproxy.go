// Package socketproxy lets Helmsman MANAGE its own read-only docker-socket-proxy
// (plan §3) so the operator never runs a docker command — they only ever write
// helmsman.yaml. The proxy compose is EMBEDDED in the binary (never operator input);
// at boot Helmsman writes it under the data dir and brings it up idempotently.
//
// The proxy is the READ-plane security boundary: the raw docker socket is mounted
// ONLY into the proxy (read-only), and Helmsman polls container state through it on
// loopback. Write-plane actions never use it — they shell out to `docker compose`.
package socketproxy

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/helmsman/helmsman/internal/dockerexec"
)

//go:embed docker-compose.yml
var composeYAML []byte

// Project is the fixed compose project name for the managed proxy.
const Project = "helmsman-socket-proxy"

// Compose returns the embedded, Helmsman-owned proxy compose bytes.
func Compose() []byte { return composeYAML }

// Materialize writes the embedded proxy compose under dataDir/socket-proxy (dir 0700,
// file 0600) and returns its path. It is pure I/O (no docker), so it is unit-testable.
func Materialize(dataDir string) (composePath string, err error) {
	dir := filepath.Join(dataDir, "socket-proxy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("socketproxy: mkdir %s: %w", dir, err)
	}
	file := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(file, composeYAML, 0o600); err != nil {
		return "", fmt.Errorf("socketproxy: write compose: %w", err)
	}
	return file, nil
}

// EnsureRunning materializes the embedded proxy compose and brings it up idempotently
// (`docker compose up -d`). It is UNGATED (the read plane must work on a small box)
// and best-effort: a docker error is returned for the caller to log, never treated as
// fatal — the read plane simply reports "unavailable" until the proxy is up. The
// compose is embedded, so nothing operator-controlled ever reaches the docker argv.
func EnsureRunning(ctx context.Context, runner *dockerexec.Runner, dataDir string, onLine func(string)) error {
	if runner == nil {
		return fmt.Errorf("socketproxy: nil runner")
	}
	file, err := Materialize(dataDir)
	if err != nil {
		return err
	}
	job := dockerexec.Job{
		Project:     Project,
		Dir:         filepath.Dir(file),
		ConfigFiles: []string{file},
		Action:      []string{"up", "-d", "--remove-orphans"},
	}
	return runner.RunInternal(ctx, job, onLine)
}
