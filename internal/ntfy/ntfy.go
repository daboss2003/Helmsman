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

	// Image is the ntfy server image, DIGEST-PINNED (plan §15 supply-chain posture, like
	// internal/socketproxy). It must be >= v2.14.0 — the first release with declarative
	// auth-users/auth-access/auth-tokens in server.yml, which is how this package seeds
	// the publisher/subscriber tokens (older images silently ignore those keys, so
	// deny-all would reject everything and no alert would ever arrive). This is the
	// multi-arch manifest-list digest for v2.24.0 (amd64/arm64/arm), resolved from the
	// registry. To bump: re-resolve with `docker buildx imagetools inspect binwiederhier/ntfy:<ver>`.
	Image = "binwiederhier/ntfy:v2.24.0@sha256:f8a9b104313b87cc24ae4f775f39e6328205b57dff6ede3eaf098a91e5d79f59"
)

// SubscriberUser is the read-only account the operator signs into the ntfy app/web UI
// with to subscribe. The ntfy app + web UI authenticate with username+password (not a
// raw token), so the subscriber gets a real password — not a token they can't enter.
const SubscriberUser = "phone"

// Params is everything needed to render the server config for one managed instance.
// They're persisted by the caller (encrypted channel config) and passed back on every
// (re)materialize so the same credentials survive restarts. Helmsman PUBLISHES with the
// write token (Bearer, over loopback); the operator SUBSCRIBES as SubscriberUser with
// SubPassword (read-only).
type Params struct {
	BaseURL     string // the public https URL, e.g. "https://ntfy.example.com"
	Topic       string // the alert topic
	WriteToken  string // Helmsman publisher token (wo on Topic)
	SubPassword string // the subscriber (phone) account password (ro on Topic)
}

// GenerateToken returns a fresh ntfy-format access token: "tk_" + 29 [a-z0-9] = 32
// chars total, which is exactly what ntfy requires. Uses crypto/rand with rejection
// sampling so the alphabet is uniform (no modulo bias).
func GenerateToken() (string, error) {
	const n = 29
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789" // 36
	const limit = 256 - (256 % len(alphabet))               // reject the biased tail (>=252)
	out := make([]byte, n)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= limit {
			continue
		}
		out[i] = alphabet[int(buf[0])%len(alphabet)]
		i++
	}
	return "tk_" + string(out), nil
}

// GeneratePassword returns a strong, app-typeable subscriber password (24 chars of
// [A-Za-z0-9], crypto/rand with rejection sampling — no modulo bias).
func GeneratePassword() (string, error) {
	const n = 24
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" // 62
	const limit = 256 - (256 % len(alphabet))
	out := make([]byte, n)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= limit {
			continue
		}
		out[i] = alphabet[int(buf[0])%len(alphabet)]
		i++
	}
	return string(out), nil
}

// Validate checks the params are well-formed before they drive config generation.
func (p Params) Validate() error {
	if !strings.HasPrefix(p.BaseURL, "https://") {
		return fmt.Errorf("ntfy: base url must be https")
	}
	if !validToken(p.WriteToken) {
		return fmt.Errorf("ntfy: write token must be tk_ + 29 [a-z0-9]")
	}
	if len(p.SubPassword) < 12 {
		return fmt.Errorf("ntfy: subscriber password too short")
	}
	if !validTopic(p.Topic) {
		return fmt.Errorf("ntfy: topic must be 1-64 chars of [A-Za-z0-9_-]")
	}
	return nil
}

func validToken(t string) bool {
	if !strings.HasPrefix(t, "tk_") || len(t) != 32 { // tk_ + 29 = 32, ntfy's required length
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
// scoped to the topic. The publisher (helmsman, write-only) authenticates with a token
// (Bearer, used over loopback). The subscriber (phone, read-only) authenticates with a
// real PASSWORD — because the ntfy app + web UI log in with username+password, not a
// raw token. Behind-proxy + base-url are set for Caddy; upstream-base-url enables iOS
// push via the ntfy.sh relay.
func ServerYAML(p Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	// helmsman's password is random + never used (it auths via the token); the phone
	// user's hash is the REAL subscriber password the operator signs in with.
	pubHash, err := randomBcrypt()
	if err != nil {
		return nil, err
	}
	subHash, err := bcryptHash(p.SubPassword)
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
	fmt.Fprintf(&b, "  - %q\n", SubscriberUser+":"+subHash+":user")
	fmt.Fprintf(&b, "auth-access:\n")
	fmt.Fprintf(&b, "  - %q\n", "helmsman:"+p.Topic+":wo")
	fmt.Fprintf(&b, "  - %q\n", SubscriberUser+":"+p.Topic+":ro")
	fmt.Fprintf(&b, "auth-tokens:\n")
	fmt.Fprintf(&b, "  - %q\n", "helmsman:"+p.WriteToken+":Helmsman publisher")
	return []byte(b.String()), nil
}

func randomBcrypt() (string, error) {
	pw := make([]byte, 24)
	if _, err := rand.Read(pw); err != nil {
		return "", err
	}
	return bcryptHash(string(pw))
}

func bcryptHash(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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

// EnsureRunning RE-materializes the config (fresh subscriber password + write token)
// and brings the managed ntfy up. UNGATED (infra plane) + best-effort, mirroring
// socketproxy: a docker error is returned to log, never fatal. Nothing operator-controlled
// reaches the docker argv (the compose is Helmsman-generated; the bind path is Helmsman-owned).
//
// --force-recreate is REQUIRED here (this is the (re)provision path): server.yml is
// bind-mounted, and ntfy only provisions/reconciles its auth-users + ACL into user.db
// at PROCESS START. Plain `docker compose up -d` recreates a container only when the
// compose SPEC changes — NOT when a bind-mounted file's CONTENTS change — so without it
// the already-running ntfy keeps serving the OLD user.db (old subscriber password) while
// the dashboard shows the NEW one, and signing in fails with "user phone not authorized".
// Forcing a recreate restarts ntfy so it re-reads the rewritten server.yml and updates
// the provisioned user/ACL (ntfy provisioning is create-OR-update on restart). The named
// volumes (user.db, cache) persist across the recreate, so history is kept. This is the
// only re-materialize path; the boot-time Up() below must NOT force-recreate (it would
// churn the running container on every restart for no config change).
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
		Action:      upAction(true), // (re)provision → force ntfy to re-read the new server.yml
	}
	return runner.RunInternal(ctx, job, onLine)
}

// upAction is the `docker compose up` argv for the managed ntfy. forceRecreate MUST be
// true on the (re)provision path (EnsureRunning) so a rewritten server.yml is actually
// re-read — ntfy provisions auth-users/ACL only at process start, and `up -d` alone won't
// restart a container just because a bind-mounted file's contents changed. It MUST be
// false on the boot reconcile path (Up) so a Helmsman restart never needlessly churns a
// correctly-running ntfy. Centralized so the two paths can't silently diverge again.
func upAction(forceRecreate bool) []string {
	a := []string{"up", "-d", "--remove-orphans"}
	if forceRecreate {
		a = append(a, "--force-recreate")
	}
	return a
}

// Up brings the EXISTING on-disk managed-ntfy compose up WITHOUT re-materializing the
// config (so it needs no tokens). Used at boot to reconcile the protected container to
// running if it was removed — restart:unless-stopped covers reboots, but not a manual
// `docker rm`. No-op error if it was never provisioned. Best-effort.
func Up(ctx context.Context, runner *dockerexec.Runner, dataDir string, onLine func(string)) error {
	if runner == nil {
		return fmt.Errorf("ntfy: nil runner")
	}
	composePath := filepath.Join(dataDir, "ntfy", "docker-compose.yml")
	if _, err := os.Stat(composePath); err != nil {
		return fmt.Errorf("ntfy: no managed compose on disk: %w", err)
	}
	job := dockerexec.Job{
		Project:     Project,
		Dir:         filepath.Dir(composePath),
		ConfigFiles: []string{composePath},
		Action:      upAction(false), // boot reconcile → don't churn a correctly-running container
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
