// Package cfgstore persists managed config files (templates + bindings) and cert
// bindings (plan §7.4/§7.5, M5b). Templates are AES-256-GCM at rest; bindings,
// secret-bearing flag, file mode, and rendered sha live alongside.
package cfgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/daboss2003/Helmsman/internal/cfgfile"
	"github.com/daboss2003/Helmsman/internal/secret"
	"github.com/daboss2003/Helmsman/internal/store"
)

// Mode constants (octal as decimal for storage).
const (
	mode0640 = 0o640
	mode0600 = 0o600
)

// ConfigFile is a managed config file record. Template is decrypted in memory.
type ConfigFile struct {
	Project        string
	Name           string
	RelPath        string
	Template       secret.Redacted
	Bindings       []cfgfile.Binding
	SecretBearing  bool
	Mode           int
	RenderedSHA256 string
}

// CertBinding wires an edge cert to an app.
type CertBinding struct {
	Project     string
	BindingName string
	Hostname    string
	SyncDirRel  string
	Required    bool
}

// Store persists config files + cert bindings.
type Store struct {
	db     *store.DB
	cipher *secret.Cipher
}

// New builds a Store.
func New(db *store.DB, cipher *secret.Cipher) *Store { return &Store{db: db, cipher: cipher} }

// ErrInternal wraps cipher/DB errors so callers can keep them out of operator-
// facing messages (review #10). Validation errors are returned plain.
var ErrInternal = errors.New("cfgstore: internal error")

// SaveInput is an operator's config-file edit.
type SaveInput struct {
	Name     string
	RelPath  string
	Template string
	Bindings []cfgfile.Binding
}

// SaveConfigFile validates and upserts a config file. It rejects bad bindings,
// an unconfinable rel_path, and a literal secret in a non-secret-bearing body.
func (s *Store) SaveConfigFile(ctx context.Context, project string, in SaveInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return errors.New("config file name is required")
	}
	if err := validateRelPath(in.RelPath); err != nil {
		return err
	}
	if err := cfgfile.ValidateBindings(in.Bindings); err != nil {
		return err
	}
	// Every {{hm.X}} in the template must have a binding (catch unknown at save,
	// not just at render — plan §7.4 "hard error at save AND render").
	if err := checkTemplateBindings([]byte(in.Template), in.Bindings); err != nil {
		return err
	}
	secretBearing := cfgfile.SecretBearing(in.Bindings)
	if !secretBearing {
		if reason, hit := cfgfile.LiteralSecretLint([]byte(in.Template)); hit {
			return fmt.Errorf("literal-secret lint: %s", reason)
		}
	}
	mode := mode0640
	if secretBearing {
		mode = mode0600
	}
	bj, err := json.Marshal(in.Bindings)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInternal, err)
	}
	tmplEnc, err := s.cipher.Seal([]byte(in.Template))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInternal, err)
	}
	sb := 0
	if secretBearing {
		sb = 1
	}
	if _, err = s.db.ExecContext(ctx,
		`INSERT INTO app_config_files(project, name, rel_path, template_enc, bindings_json, secret_bearing, mode_octal, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project, name) DO UPDATE SET
		   rel_path=excluded.rel_path, template_enc=excluded.template_enc, bindings_json=excluded.bindings_json,
		   secret_bearing=excluded.secret_bearing, mode_octal=excluded.mode_octal, updated_at=excluded.updated_at`,
		project, strings.TrimSpace(in.Name), filepath.Clean(in.RelPath), tmplEnc, string(bj), sb, mode, time.Now().Unix()); err != nil {
		return fmt.Errorf("%w: %v", ErrInternal, err)
	}
	return nil
}

// ConfigFiles returns all config files for a project (templates decrypted).
func (s *Store) ConfigFiles(project string) ([]ConfigFile, error) {
	rows, err := s.db.Query(
		`SELECT name, rel_path, template_enc, bindings_json, secret_bearing, mode_octal, rendered_sha256
		 FROM app_config_files WHERE project = ? ORDER BY name`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConfigFile
	for rows.Next() {
		c := ConfigFile{Project: project}
		var enc []byte
		var bj string
		var sb int
		if err := rows.Scan(&c.Name, &c.RelPath, &enc, &bj, &sb, &c.Mode, &c.RenderedSHA256); err != nil {
			return nil, err
		}
		pt, derr := s.cipher.Open(enc)
		if derr != nil {
			return nil, derr
		}
		c.Template = secret.New(string(pt))
		if err := json.Unmarshal([]byte(bj), &c.Bindings); err != nil {
			return nil, fmt.Errorf("config file %q: corrupt bindings: %w", c.Name, err)
		}
		c.SecretBearing = sb == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteConfigFile removes a config file record.
func (s *Store) DeleteConfigFile(ctx context.Context, project, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_config_files WHERE project = ? AND name = ?`, project, name)
	return err
}

// DeleteApp removes ALL of an app's managed config files AND cert bindings. Used by
// the app-delete teardown. (Two statements; each runs on its own — no nested query.)
func (s *Store) DeleteApp(ctx context.Context, project string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM app_config_files WHERE project = ?`, project); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_cert_bindings WHERE project = ?`, project)
	return err
}

// SetRenderedSHA records the sha of the last materialized output (drift detection).
func (s *Store) SetRenderedSHA(ctx context.Context, project, name, sha string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE app_config_files SET rendered_sha256 = ? WHERE project = ? AND name = ?`, sha, project, name)
}

// --- cert bindings ---

// CertBindings returns the cert bindings for a project.
func (s *Store) CertBindings(project string) ([]CertBinding, error) {
	rows, err := s.db.Query(`SELECT binding_name, hostname, sync_dir_rel, required FROM app_cert_bindings WHERE project = ? ORDER BY binding_name`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertBinding
	for rows.Next() {
		c := CertBinding{Project: project}
		var req int
		if err := rows.Scan(&c.BindingName, &c.Hostname, &c.SyncDirRel, &req); err != nil {
			return nil, err
		}
		c.Required = req == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// AllCertHostnames returns the distinct hostnames across all apps' cert bindings —
// the cert-only ACME subjects the managed edge must issue (spec.cert_bindings).
func (s *Store) AllCertHostnames() []string {
	rows, err := s.db.Query(`SELECT DISTINCT hostname FROM app_cert_bindings ORDER BY hostname`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return out
		}
		out = append(out, h)
	}
	return out
}

// SaveCertBinding upserts a cert binding (validating the sync dir is confinable).
func (s *Store) SaveCertBinding(ctx context.Context, project string, cb CertBinding) error {
	if !cfgfile.ValidKey(cb.BindingName) {
		return errors.New("binding name must be a simple identifier")
	}
	if strings.TrimSpace(cb.Hostname) == "" {
		return errors.New("hostname is required")
	}
	if err := validateRelPath(cb.SyncDirRel); err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	req := 0
	if cb.Required {
		req = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_cert_bindings(project, binding_name, hostname, sync_dir_rel, required, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project, binding_name) DO UPDATE SET
		   hostname=excluded.hostname, sync_dir_rel=excluded.sync_dir_rel, required=excluded.required, updated_at=excluded.updated_at`,
		project, cb.BindingName, strings.TrimSpace(cb.Hostname), filepath.Clean(cb.SyncDirRel), req, time.Now().Unix())
	return err
}

// DeleteCertBinding removes a cert binding.
func (s *Store) DeleteCertBinding(ctx context.Context, project, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_cert_bindings WHERE project = ? AND binding_name = ?`, project, name)
	return err
}

// validateRelPath ensures a relative path stays under run_dir (no abs, no ..).
func validateRelPath(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return errors.New("path is required")
	}
	if filepath.IsAbs(p) {
		return errors.New("path must be relative to the app directory")
	}
	clean := filepath.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("path escapes the app directory")
	}
	return nil
}

// checkTemplateBindings ensures every {{hm.X}} in the template has a binding.
func checkTemplateBindings(tmpl []byte, bindings []cfgfile.Binding) error {
	known := map[string]bool{}
	for _, b := range bindings {
		known[b.Key] = true
	}
	_, _, err := cfgfile.Render(tmpl, func(key string) (string, bool, error) {
		if !known[key] {
			return "", false, fmt.Errorf("%w: %q has no binding", cfgfile.ErrUnknownBinding, key)
		}
		return "", false, nil // value irrelevant at save-time check
	})
	return err
}
