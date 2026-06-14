package edge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/helmsman/helmsman/internal/store"
)

// ErrOverlayTampered means the stored overlay's HMAC did not verify — the row was
// changed outside Helmsman. The overlay is dropped fail-closed (the edge serves
// Layer 0 ⊕ 1 only) and the event is audited at level=security.
var ErrOverlayTampered = errors.New("edge overlay HMAC mismatch (tampered)")

// OverlayStore persists the Layer-2 operator overlay (plan §6.2). Each Save is a new
// version; the active overlay is the latest row. The text is NEVER loaded verbatim:
// RenderComposite re-parses + re-lints it as untrusted on every apply, and restore
// re-derives from the stored text re-validated the same way. The per-row HMAC is
// defence-in-depth — a DB tamper that still satisfies the linter is caught here.
type OverlayStore struct {
	db  *store.DB
	key []byte
}

// NewOverlayStore derives a dedicated HMAC key from the encryption key (domain-
// separated, so it is not the same key used for secret encryption) and returns the
// store.
func NewOverlayStore(db *store.DB, encKey []byte) *OverlayStore {
	h := sha256.New()
	h.Write([]byte("helmsman/edge-overlay-hmac/v1\x00"))
	h.Write(encKey)
	return &OverlayStore{db: db, key: h.Sum(nil)}
}

func (s *OverlayStore) mac(text []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(text)
	return m.Sum(nil)
}

// Save validates the overlay against the CURRENT managed hostnames (a conflicting
// overlay is rejected here, loudly, for operator feedback) and persists it as a new
// version. An empty overlay drops Layer 2 (keeps app routes). The text is stored
// trimmed; the HMAC covers exactly the stored bytes.
func (s *OverlayStore) Save(ctx context.Context, overlay []byte, managed map[string]bool, note string) error {
	if _, _, err := ParseOverlay(overlay, managed); err != nil {
		return err
	}
	text := bytes.TrimSpace(overlay)
	if text == nil {
		text = []byte{}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO edge_overlay(overlay, hmac, note, created_at) VALUES(?,?,?,?)`,
		string(text), s.mac(text), note, time.Now().Unix())
	return err
}

// Active returns the latest overlay text, HMAC-verified. No overlay yet → (nil,nil).
// A failed HMAC → (nil, ErrOverlayTampered) so the caller can drop it fail-closed.
func (s *OverlayStore) Active(ctx context.Context) ([]byte, error) {
	var text string
	var mac []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT overlay, hmac FROM edge_overlay ORDER BY id DESC LIMIT 1`).Scan(&text, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(mac, s.mac([]byte(text))) {
		return nil, ErrOverlayTampered
	}
	return []byte(text), nil
}

// Raw returns the latest overlay text for display WITHOUT failing on a bad HMAC
// (so the operator can see + re-save a tampered overlay). The bool reports whether
// the stored HMAC verified.
func (s *OverlayStore) Raw(ctx context.Context) (text []byte, verified bool, err error) {
	var t string
	var mac []byte
	e := s.db.QueryRowContext(ctx,
		`SELECT overlay, hmac FROM edge_overlay ORDER BY id DESC LIMIT 1`).Scan(&t, &mac)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, true, nil
	}
	if e != nil {
		return nil, false, e
	}
	return []byte(t), hmac.Equal(mac, s.mac([]byte(t))), nil
}
