// Package ntfy lets Helmsman MANAGE a self-hosted ntfy server so an operator can get
// push alerts without depending on the public ntfy.sh or hand-running a container. Like
// internal/socketproxy, the compose + config are Helmsman-OWNED (generated, never
// operator input) and brought up via the dockerexec runner.
//
// Security model (operator's choices): the server is LOCKED DOWN — auth-default-access
// is deny-all and access is granted only via two seeded tokens:
//   - a WRITE-ONLY token Helmsman uses to publish alerts (never shown to the operator),
//   - a READ-ONLY token the operator puts in their phone's ntfy app to subscribe.
//
// So a leaked phone token can only RECEIVE, never publish. TLS + the public hostname are
// handled by Helmsman's managed edge (Caddy); iOS instant push uses the free ntfy.sh
// upstream relay (which only ever sees an opaque topic hash, never the name or body).
package ntfy

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/daboss2003/Helmsman/internal/dockerexec"
)

const (
	// Project is the fixed compose project name for the managed ntfy (protected infra).
	Project = "helmsman-ntfy"
	// Service is the compose service name (the edge routes hostname -> Service:Port).
	Service = "ntfy"
	// ContainerPort is ntfy's in-container HTTP port (Caddy reverse-proxies to it).
	ContainerPort = 80
	// LoopbackPort is the host-loopback port the container publishes to; Helmsman
	// publishes alerts to http://127.0.0.1:LoopbackPort (never reachable off-host).
	LoopbackPort = 2586

	// Image is the ntfy server image. NOTE: Helmsman's posture pins infra images by
	// digest (see internal/socketproxy). Pin this to a verified sha256 for production —
	// resolve with `docker buildx imagetools inspect binwiederhier/ntfy:<ver>` on a host
	// with registry access. A version tag is used here as a safe default.
	Image = "binwiederhier/ntfy:v2.11.0"
)

// Params is everything needed to render the server config for one managed instance.
// Tokens are persisted by the caller (in the encrypted channel config) and passed back
// in on every (re)materialize so the same tokens survive restarts. The bcrypt user
// passwords are NOT persisted — they're regenerated random each materialize because
// only the tokens are ever used to authenticate.
type Params struct {
	BaseURL    string // the public https URL, e.g. "https://ntfy.example.com"
	Topic      string // the alert topic
	WriteToken string // Helmsman publisher token (wo on Topic)
	ReadToken  string // subscriber/phone token (ro on Topic)
}

// GenerateToken returns a fresh ntfy-format access token ("tk_" + 30 [a-z0-9]).
func GenerateToken() (string, error) {
	const n = 30
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "tk_" + string(b), nil
}

// Validate checks the params are well-formed before they drive config generation.
func (p Params) Validate() error {
	if !strings.HasPrefix(p.BaseURL, "https://") {
		return fmt.Errorf("ntfy: base url must be https")
	}
	if !validToken(p.WriteToken) || !validToken(p.ReadToken) {
		return fmt.Errorf("ntfy: tokens must be tk_ + 30 [a-z0-9]")
	}
	if p.WriteToken == p.ReadToken {
		return fmt.Errorf("ntfy: write and read tokens must differ")
	}
	if !validTopic(p.Topic) {
		return fmt.Errorf("ntfy: topic must be 1-64 chars of [A-Za-z0-9_-]")
	}
	return nil
}

func validToken(t string) bool {
	if !strings.HasPrefix(t, "tk_") || len(t) != 33 {
		return false
	}
	for _, c := range t[3:] {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func validTopic(t string) bool {
	if t == "" || len(t) > 64 {
		return false
	}
	for _, c := range t {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ServerYAML renders the ntfy server.yml: locked down (deny-all) with two seeded users
// scoped to the topic — the publisher (write-only) and the subscriber (read-only) —
// each holding one of the seeded tokens. Behind-proxy + base-url are set for Caddy;
// upstream-base-url enables iOS push via the ntfy.sh relay.
func ServerYAML(p Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	// Random, never-used passwords — auth-users requires a bcrypt hash per user, but we
	// only ever authenticate with the tokens.
	pubHash, err := randomBcrypt()
	if err != nil {
		return nil, err
	}
	subHash, err := randomBcrypt()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Helmsman-OWNED — generated, do not edit; managed via the Alerts page.\n")
	fmt.Fprintf(&b, "base-url: %q\n", p.BaseURL)
	fmt.Fprintf(&b, "listen-http: \":%d\"\n", ContainerPort)
	fmt.Fprintf(&b, "behind-proxy: true\n")
	fmt.Fprintf(&b, "auth-file: \"/var/lib/ntfy/user.db\"\n")
	fmt.Fprintf(&b, "auth-default-access: \"deny-all\"\n")
	fmt.Fprintf(&b, "cache-file: \"/var/cache/ntfy/cache.db\"\n")
	fmt.Fprintf(&b, "upstream-base-url: \"https://ntfy.sh\"\n")
	fmt.Fprintf(&b, "auth-users:\n")
	fmt.Fprintf(&b, "  - %q\n", "helmsman:"+pubHash+":user")
	fmt.Fprintf(&b, "  - %q\n", "phone:"+subHash+":user")
	fmt.Fprintf(&b, "auth-access:\n")
	fmt.Fprintf(&b, "  - %q\n", "helmsman:"+p.Topic+":wo")
	fmt.Fprintf(&b, "  - %q\n", "phone:"+p.Topic+":ro")
	fmt.Fprintf(&b, "auth-tokens:\n")
	fmt.Fprintf(&b, "  - %q\n", "helmsman:"+p.WriteToken+":Helmsman publisher")
	fmt.Fprintf(&b, "  - %q\n", "phone:"+p.ReadToken+":Phone subscriber")
	return []byte(b.String()), nil
}

func randomBcrypt() (string, error) {
	pw := make([]byte, 24)
	if _, err := rand.Read(pw); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// ComposeYAML renders the compose for the managed ntfy. server.yml is bind-mounted
// read-only (0644 so the container user can read it; its parent dir stays 0700);
// state lives in named volumes (docker-owned perms). The HTTP port is published ONLY
// on 127.0.0.1 — Helmsman publishes there; the public path is Caddy -> the bridge IP.
func ComposeYAML(serverYAMLPath string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Helmsman-OWNED managed ntfy — generated, never operator input.\n")
	fmt.Fprintf(&b, "services:\n")
	fmt.Fprintf(&b, "  %s:\n", Service)
	fmt.Fprintf(&b, "    image: %s\n", Image)
	fmt.Fprintf(&b, "    container_name: %s\n", Project)
	fmt.Fprintf(&b, "    command: [\"serve\"]\n")
	fmt.Fprintf(&b, "    restart: unless-stopped\n")
	fmt.Fprintf(&b, "    cap_drop: [ALL]\n")
	fmt.Fprintf(&b, "    security_opt: [\"no-new-privileges:true\"]\n")
	fmt.Fprintf(&b, "    ports:\n")
	fmt.Fprintf(&b, "      - \"127.0.0.1:%d:%d\"\n", LoopbackPort, ContainerPort)
	fmt.Fprintf(&b, "    volumes:\n")
	fmt.Fprintf(&b, "      - %q\n", serverYAMLPath+":/etc/ntfy/server.yml:ro")
	fmt.Fprintf(&b, "      - helmsman-ntfy-lib:/var/lib/ntfy\n")
	fmt.Fprintf(&b, "      - helmsman-ntfy-cache:/var/cache/ntfy\n")
	fmt.Fprintf(&b, "volumes:\n")
	fmt.Fprintf(&b, "  helmsman-ntfy-lib:\n")
	fmt.Fprintf(&b, "  helmsman-ntfy-cache:\n")
	return []byte(b.String())
}

// Materialize writes server.yml (0644, container-readable) and docker-compose.yml (0600)
// under dataDir/ntfy (dir 0700) and returns the compose path. Pure I/O (no docker), so
// it is unit-testable.
func Materialize(dataDir string, p Params) (composePath string, err error) {
	dir := filepath.Join(dataDir, "ntfy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("ntfy: mkdir %s: %w", dir, err)
	}
	serverPath := filepath.Join(dir, "server.yml")
	server, err := ServerYAML(p)
	if err != nil {
		return "", err
	}
	// 0644: the file is bind-mounted INTO the container and read by ntfy's (non-root)
	// user; the 0700 parent dir keeps it private on the host.
	if err := os.WriteFile(serverPath, server, 0o644); err != nil {
		return "", fmt.Errorf("ntfy: write server.yml: %w", err)
	}
	composePath = filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(composePath, ComposeYAML(serverPath), 0o600); err != nil {
		return "", fmt.Errorf("ntfy: write compose: %w", err)
	}
	return composePath, nil
}

// EnsureRunning materializes the config and brings the managed ntfy up idempotently
// (`docker compose up -d`). UNGATED (infra plane) + best-effort, mirroring socketproxy:
// a docker error is returned to log, never fatal. Nothing operator-controlled reaches
// the docker argv (the compose is Helmsman-generated; the bind path is Helmsman-owned).
func EnsureRunning(ctx context.Context, runner *dockerexec.Runner, dataDir string, p Params, onLine func(string)) error {
	if runner == nil {
		return fmt.Errorf("ntfy: nil runner")
	}
	composePath, err := Materialize(dataDir, p)
	if err != nil {
		return err
	}
	job := dockerexec.Job{
		Project:     Project,
		Dir:         filepath.Dir(composePath),
		ConfigFiles: []string{composePath},
		Action:      []string{"up", "-d", "--remove-orphans"},
	}
	return runner.RunInternal(ctx, job, onLine)
}

// Stop tears the managed ntfy down (`docker compose down`), keeping named volumes so a
// re-enable preserves message history. Best-effort.
func Stop(ctx context.Context, runner *dockerexec.Runner, dataDir string, onLine func(string)) error {
	if runner == nil {
		return fmt.Errorf("ntfy: nil runner")
	}
	composePath := filepath.Join(dataDir, "ntfy", "docker-compose.yml")
	job := dockerexec.Job{
		Project:     Project,
		Dir:         filepath.Dir(composePath),
		ConfigFiles: []string{composePath},
		Action:      []string{"down", "--remove-orphans"},
	}
	return runner.RunInternal(ctx, job, onLine)
}
