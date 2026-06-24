// Package gitstore persists per-app repo-path GitOps config (plan §7.6): the
// repo URL/ref/paths, the FSM state (deployed/staged commit, update_state), and
// the secret material (PAT/deploy-key, webhook HMAC secret) AES-256-GCM at rest.
// The webhook token is stored only as a SHA-256 hash; the token itself is never
// persisted or logged.
package gitstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/daboss2003/Helmsman/internal/crypto"
	"github.com/daboss2003/Helmsman/internal/git"
	"github.com/daboss2003/Helmsman/internal/secret"
	"github.com/daboss2003/Helmsman/internal/store"
)

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

func validSlug(s string) bool { return slugRe.MatchString(s) }

// helmsmanFileRe matches a root-level helmsman file: the plain helmsman.yaml or a
// named variant like helmsman.staging.yaml / helmsman.prod.yaml (.yml accepted).
// Root-level only — no path separators, so a stored value can never escape the repo
// root or smuggle traversal into a CatFile path.
var helmsmanFileRe = regexp.MustCompile(`^helmsman(\.[a-z0-9][a-z0-9-]*)?\.ya?ml$`)

// ValidHelmsmanFile reports whether name is an acceptable per-app helmsman file.
func ValidHelmsmanFile(name string) bool { return helmsmanFileRe.MatchString(name) }

// Config is one repo app's GitOps configuration + state.
type Config struct {
	Project        string
	RepoURL        string
	Ref            string
	ComposePath    string
	DockerfilePath string
	HelmsmanFile   string // repo-relative helmsman file driving this app (default helmsman.yaml)
	AutoDeploy     bool
	BuildPolicy    string
	CredKind       string // "" | token | ssh
	DeployedCommit string
	StagedCommit   string
	UpdateState    string
	CommitsBehind  int
	LastFetchAt    int64
	LastFetchError string
	HasWebhook     bool
}

// Store persists GitOps config.
type Store struct {
	db     *store.DB
	cipher *secret.Cipher
}

// New builds a Store.
func New(db *store.DB, cipher *secret.Cipher) *Store { return &Store{db: db, cipher: cipher} }

// SaveInput is an operator's repo-app config edit.
type SaveInput struct {
	Project        string
	RepoURL        string
	Ref            string
	ComposePath    string
	DockerfilePath string
	HelmsmanFile   string // "" keeps the stored value (or defaults to helmsman.yaml on insert)
	AutoDeploy     bool
	BuildPolicy    string
	// NewCred tri-state: nil keeps, "" clears, value replaces.
	NewCred    *string
	CredKind   string // token | ssh (when NewCred set)
	KnownHosts string // ssh only
}

var validState = map[string]bool{
	"up_to_date": true, "update_available": true, "deploying": true,
	"update_blocked": true, "history_rewritten": true,
}

// Save validates + upserts a repo app's config (URL through the SSRF allowlist).
func (s *Store) Save(ctx context.Context, in SaveInput) error {
	if !validSlug(in.Project) {
		return errors.New("app slug must match [a-z][a-z0-9-]{1,30}")
	}
	if err := git.ValidateRepoURL(in.RepoURL); err != nil {
		return err
	}
	if in.Ref == "" {
		in.Ref = "refs/heads/main"
	}
	if !strings.HasPrefix(in.Ref, "refs/") {
		return errors.New("git_ref must be fully-qualified (e.g. refs/heads/main)")
	}
	if in.ComposePath == "" {
		in.ComposePath = "docker-compose.yml"
	}
	if in.BuildPolicy != "never" && in.BuildPolicy != "on_missing" {
		in.BuildPolicy = "never"
	}
	// Resolve the helmsman file driving this app: an empty value KEEPS the stored
	// one (so the basic edit form never has to round-trip it), defaulting to the
	// plain helmsman.yaml on a fresh insert. A provided value is validated to a
	// root-level helmsman*.yaml — the connect/discovery flow is its only writer.
	helmsmanFile := strings.TrimSpace(in.HelmsmanFile)
	if helmsmanFile == "" {
		_ = s.db.QueryRowContext(ctx, `SELECT helmsman_file_path FROM app_git WHERE project=?`, in.Project).Scan(&helmsmanFile)
		if strings.TrimSpace(helmsmanFile) == "" {
			helmsmanFile = "helmsman.yaml"
		}
	} else if !ValidHelmsmanFile(helmsmanFile) {
		return errors.New("helmsman file must be a root-level helmsman*.yaml")
	}
	ad := b2i(in.AutoDeploy)

	// Resolve credential ciphertext: keep / clear / replace.
	var credEnc, khEnc []byte
	credKind := ""
	switch {
	case in.NewCred == nil: // keep existing
		_ = s.db.QueryRowContext(ctx, `SELECT cred_enc, known_hosts_enc, cred_kind FROM app_git WHERE project=?`, in.Project).Scan(&credEnc, &khEnc, &credKind)
	case *in.NewCred == "": // clear
		credKind = ""
	default: // replace
		ct, err := s.cipher.Seal([]byte(*in.NewCred))
		if err != nil {
			return err
		}
		credEnc = ct
		credKind = in.CredKind
		if credKind == "ssh" {
			kh, err := s.cipher.Seal([]byte(in.KnownHosts))
			if err != nil {
				return err
			}
			khEnc = kh
		}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_git(project, repo_url, git_ref, compose_path, dockerfile_path, helmsman_file_path, auto_deploy, build_policy, cred_kind, cred_enc, known_hosts_enc, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(project) DO UPDATE SET
		   repo_url=excluded.repo_url, git_ref=excluded.git_ref, compose_path=excluded.compose_path,
		   dockerfile_path=excluded.dockerfile_path, helmsman_file_path=excluded.helmsman_file_path,
		   auto_deploy=excluded.auto_deploy, build_policy=excluded.build_policy,
		   cred_kind=excluded.cred_kind, cred_enc=excluded.cred_enc, known_hosts_enc=excluded.known_hosts_enc, updated_at=excluded.updated_at`,
		in.Project, strings.TrimSpace(in.RepoURL), in.Ref, strings.TrimSpace(in.ComposePath),
		strings.TrimSpace(in.DockerfilePath), helmsmanFile, ad, in.BuildPolicy, credKind, credEnc, khEnc, time.Now().Unix())
	return err
}

// Delete removes an app's entire GitOps row — repo config, deploy FSM, the encrypted
// fetch credential, and the webhook material all live on this one row, so the row
// delete fully purges them. Used by the app-delete teardown.
func (s *Store) Delete(ctx context.Context, project string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_git WHERE project=?`, project)
	return err
}

// Get returns a repo app's config (no secret material).
func (s *Store) Get(project string) (Config, bool, error) {
	var c Config
	var ad int
	err := s.db.QueryRow(
		`SELECT project, repo_url, git_ref, compose_path, dockerfile_path, helmsman_file_path, auto_deploy, build_policy, cred_kind,
		        deployed_commit, staged_commit, update_state, commits_behind, last_fetch_at, last_fetch_error,
		        webhook_token_hash IS NOT NULL
		 FROM app_git WHERE project=?`, project).Scan(
		&c.Project, &c.RepoURL, &c.Ref, &c.ComposePath, &c.DockerfilePath, &c.HelmsmanFile, &ad, &c.BuildPolicy, &c.CredKind,
		&c.DeployedCommit, &c.StagedCommit, &c.UpdateState, &c.CommitsBehind, &c.LastFetchAt, &c.LastFetchError, &c.HasWebhook)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, false, err
	}
	c.AutoDeploy = ad == 1
	return c, true, nil
}

// List returns all repo apps. It selects every column in ONE query and scans each
// row directly — it must NOT call Get() inside the row loop. The DB pool is capped at
// a single connection (store.SetMaxOpenConns(1)), so a nested query issued while these
// rows are still open self-deadlocks: the open rows pin the only connection and the
// nested query waits forever for a connection that never frees, stranding the pool and
// hanging every subsequent request (session validation included).
func (s *Store) List() ([]Config, error) {
	rows, err := s.db.Query(
		`SELECT project, repo_url, git_ref, compose_path, dockerfile_path, helmsman_file_path, auto_deploy, build_policy, cred_kind,
		        deployed_commit, staged_commit, update_state, commits_behind, last_fetch_at, last_fetch_error,
		        webhook_token_hash IS NOT NULL
		 FROM app_git ORDER BY project`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Config
	for rows.Next() {
		var c Config
		var ad int
		if err := rows.Scan(
			&c.Project, &c.RepoURL, &c.Ref, &c.ComposePath, &c.DockerfilePath, &c.HelmsmanFile, &ad, &c.BuildPolicy, &c.CredKind,
			&c.DeployedCommit, &c.StagedCommit, &c.UpdateState, &c.CommitsBehind, &c.LastFetchAt, &c.LastFetchError, &c.HasWebhook); err != nil {
			return nil, err
		}
		c.AutoDeploy = ad == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// Creds returns decrypted fetch credentials for a project.
func (s *Store) Creds(project string) (git.Creds, error) {
	var credEnc, khEnc []byte
	var kind string
	err := s.db.QueryRow(`SELECT cred_kind, cred_enc, known_hosts_enc FROM app_git WHERE project=?`, project).Scan(&kind, &credEnc, &khEnc)
	if err != nil {
		return git.Creds{}, err
	}
	var c git.Creds
	if len(credEnc) > 0 {
		pt, err := s.cipher.Open(credEnc)
		if err != nil {
			return git.Creds{}, err
		}
		switch kind {
		case "token":
			c.Token = string(pt)
		case "ssh":
			c.SSHKey = string(pt)
			if len(khEnc) > 0 {
				kh, err := s.cipher.Open(khEnc)
				if err != nil {
					return git.Creds{}, err
				}
				c.KnownHosts = string(kh)
			}
		}
	}
	return c, nil
}

// SetFetchResult records a successful fetch outcome + FSM transition.
func (s *Store) SetFetchResult(ctx context.Context, project, stagedSha string, behind int, state string) {
	if !validState[state] {
		state = "update_available"
	}
	_, _ = s.db.ExecContext(ctx,
		`UPDATE app_git SET staged_commit=?, commits_behind=?, update_state=?, last_fetch_at=?, last_fetch_error='' WHERE project=?`,
		stagedSha, behind, state, time.Now().Unix(), project)
}

// SetFetchError records a classified fetch error (never raw git stderr).
func (s *Store) SetFetchError(ctx context.Context, project, classified string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE app_git SET last_fetch_at=?, last_fetch_error=? WHERE project=?`, time.Now().Unix(), classified, project)
}

// SetDeployed records a successful deploy (pins deployed_commit, FSM up_to_date).
func (s *Store) SetDeployed(ctx context.Context, project, sha string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE app_git SET deployed_commit=?, update_state='up_to_date', commits_behind=0 WHERE project=?`, sha, project)
}

// SetState transitions the FSM (e.g. deploying, update_blocked).
func (s *Store) SetState(ctx context.Context, project, state string) {
	if validState[state] {
		_, _ = s.db.ExecContext(ctx, `UPDATE app_git SET update_state=? WHERE project=?`, state, project)
	}
}

// RotateWebhook generates a new webhook token (returned once) + HMAC secret,
// storing only the token hash + the encrypted secret.
func (s *Store) RotateWebhook(ctx context.Context, project string) (token string, err error) {
	token = randToken()
	secretKey := randToken()
	enc, err := s.cipher.Seal([]byte(secretKey))
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(token))
	_, err = s.db.ExecContext(ctx, `UPDATE app_git SET webhook_token_hash=?, webhook_secret_enc=? WHERE project=?`, h[:], enc, project)
	return token, err
}

// WebhookLookup resolves a token to its project + decrypted HMAC secret.
func (s *Store) WebhookLookup(token string) (project string, hmacSecret []byte, ok bool) {
	h := sha256.Sum256([]byte(token))
	var enc []byte
	err := s.db.QueryRow(`SELECT project, webhook_secret_enc FROM app_git WHERE webhook_token_hash=?`, h[:]).Scan(&project, &enc)
	if err != nil {
		return "", nil, false
	}
	pt, err := s.cipher.Open(enc)
	if err != nil {
		return "", nil, false
	}
	return project, pt, true
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func randToken() string { return crypto.RandomToken(32) }
