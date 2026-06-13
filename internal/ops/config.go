package ops

import (
	"database/sql"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/helmsman/helmsman/internal/opsclient"
	"github.com/helmsman/helmsman/internal/secret"
	"github.com/helmsman/helmsman/internal/store"
)

// minSecretLen is the documented shared-secret floor (plan §4: ≥ 16 chars).
const minSecretLen = 16

// Config is one app's ops coordinates. The decrypted Secret lives only in memory
// (Redacted); it is never sent to the browser and never logged (plan §4.1/§5.5).
type Config struct {
	Project      string
	Enabled      bool
	BaseURL      string
	SecretHeader string
	Secret       secret.Redacted
	HasSecret    bool
	OpsMode      string // auto | rich | basic
	BasePath     string
	Adapter      string
}

// SetInput is an operator's ops-config edit. NewSecret is tri-state: nil keeps
// the stored secret, "" clears it, any other value replaces it.
type SetInput struct {
	Enabled      bool
	BaseURL      string
	SecretHeader string
	NewSecret    *string
	OpsMode      string
	BasePath     string
	Adapter      string
}

// ConfigStore persists per-app ops config, encrypting the shared secret.
type ConfigStore struct {
	db     *store.DB
	cipher *secret.Cipher
}

// NewConfigStore builds a store. cipher must be the master AES-256-GCM cipher.
func NewConfigStore(db *store.DB, cipher *secret.Cipher) *ConfigStore {
	return &ConfigStore{db: db, cipher: cipher}
}

var validOpsModes = map[string]bool{"auto": true, "rich": true, "basic": true}

// ValidateBaseURL enforces the pinned-origin rules (plan §4.1): http(s) scheme,
// a host, NO path/query/fragment, and not a loopback literal (loopback can't be
// distinguished from the control plane, which is loopback-bound).
func ValidateBaseURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("base URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("base URL is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("base URL must be http:// or https://")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("base URL must include a host")
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("base URL must be an origin only (scheme://host[:port]); put the prefix in base_path")
	}
	if u.User != nil {
		return errors.New("base URL must not contain userinfo (user:pass@)")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return errors.New("base URL must not be loopback; point it at the app's container endpoint (a service name or private IP)")
	}
	// Classify a literal-IP host with the SAME predicate the request-time dialer
	// uses, so config-time validation can't drift weaker than the dialer (#3).
	if ip, perr := netip.ParseAddr(host); perr == nil && opsclient.IsBlockedAddr(ip.Unmap()) {
		return errors.New("base URL must not be a loopback/link-local/metadata address; point it at the app's container endpoint")
	}
	return nil
}

// Get returns an app's ops config, decrypting the secret. ok=false if none.
func (s *ConfigStore) Get(project string) (Config, bool, error) {
	var (
		c         Config
		enabled   int
		secretEnc []byte
	)
	c.Project = project
	err := s.db.QueryRow(
		`SELECT enabled, base_url, secret_header, secret_enc, ops_mode, base_path, adapter
		 FROM app_ops WHERE project = ?`, project,
	).Scan(&enabled, &c.BaseURL, &c.SecretHeader, &secretEnc, &c.OpsMode, &c.BasePath, &c.Adapter)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, false, err
	}
	c.Enabled = enabled == 1
	if len(secretEnc) > 0 {
		pt, derr := s.cipher.Open(secretEnc)
		if derr != nil {
			return Config{}, false, derr
		}
		c.Secret = secret.New(string(pt))
		c.HasSecret = true
	}
	if c.Adapter == "" {
		c.Adapter = "ops.v1"
	}
	if c.OpsMode == "" {
		c.OpsMode = "auto"
	}
	return c, true, nil
}

// Set upserts an app's ops config, encrypting a provided secret.
func (s *ConfigStore) Set(project string, in SetInput) error {
	// Validate the base URL only when enabling ops, so disabling/clearing always
	// succeeds even if the base_url field is blank or stale (review #6).
	if in.Enabled {
		if err := ValidateBaseURL(in.BaseURL); err != nil {
			return err
		}
	}
	if in.OpsMode == "" {
		in.OpsMode = "auto"
	}
	if !validOpsModes[in.OpsMode] {
		return errors.New("ops_mode must be auto, rich, or basic")
	}
	if in.Adapter == "" {
		in.Adapter = "ops.v1"
	}
	// Normalize + validate base_path against the canonical §4.1 grammar so the
	// stored value is exactly what the prober will use (review #4).
	basePath := strings.TrimRight(strings.TrimSpace(in.BasePath), "/")
	if basePath != "" && !opsclient.ValidateRelPath(basePath) {
		return errors.New("base_path must be a relative path like /ops")
	}
	header := strings.TrimSpace(in.SecretHeader)
	if header != "" && !opsclient.ValidHeaderName(header) {
		return errors.New("secret header name must match [A-Za-z0-9-], 1-64 chars (e.g. X-Ops-Secret)")
	}

	now := time.Now().Unix()
	enabled := 0
	if in.Enabled {
		enabled = 1
	}

	// Resolve the secret ciphertext: keep / clear / replace.
	var secretEnc []byte
	switch {
	case in.NewSecret == nil: // keep existing
		var existing []byte
		err := s.db.QueryRow(`SELECT secret_enc FROM app_ops WHERE project = ?`, project).Scan(&existing)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err // a real read error must NOT silently null the secret (review #9)
		}
		secretEnc = existing
	case *in.NewSecret == "": // clear
		secretEnc = nil
	default: // replace
		if len(*in.NewSecret) < minSecretLen {
			return errors.New("shared secret must be at least 16 characters")
		}
		ct, err := s.cipher.Seal([]byte(*in.NewSecret))
		if err != nil {
			return err
		}
		secretEnc = ct
	}

	_, err := s.db.Exec(
		`INSERT INTO app_ops(project, enabled, base_url, secret_header, secret_enc, ops_mode, base_path, adapter, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project) DO UPDATE SET
		   enabled=excluded.enabled, base_url=excluded.base_url, secret_header=excluded.secret_header,
		   secret_enc=excluded.secret_enc, ops_mode=excluded.ops_mode, base_path=excluded.base_path,
		   adapter=excluded.adapter, updated_at=excluded.updated_at`,
		project, enabled, strings.TrimSpace(in.BaseURL), header,
		secretEnc, in.OpsMode, basePath, in.Adapter, now,
	)
	return err
}

// Status is the cached discovery/probe state for an app (review #10: surfaces
// the disc_* columns the prober records so the operator can see last outcome).
type Status struct {
	Mode        string
	Version     string
	LastProbeAt int64
	LastError   string
}

// Status returns the last recorded probe outcome. ok=false if never probed.
func (s *ConfigStore) Status(project string) (Status, bool) {
	var st Status
	err := s.db.QueryRow(
		`SELECT disc_mode, disc_version, last_probe_at, last_error FROM app_ops WHERE project = ?`, project,
	).Scan(&st.Mode, &st.Version, &st.LastProbeAt, &st.LastError)
	if err != nil || st.LastProbeAt == 0 {
		return Status{}, false
	}
	return st, true
}

// EnabledProjects returns the projects with ops probing enabled.
func (s *ConfigStore) EnabledProjects() ([]string, error) {
	rows, err := s.db.Query(`SELECT project FROM app_ops WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
