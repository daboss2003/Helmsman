package web

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/daboss2003/mooring/internal/monitor"
)

// settings is the free-form operator-UI key/value store (never Tier-1 / security
// config). Used by the draggable tile grid (M7).

const tileOrderKey = "tile_order"

// maxTileOrder bounds the persisted order string so a hostile/buggy client can't
// grow the row unbounded.
const maxTileOrder = 16 << 10

func (s *Server) getSetting(ctx context.Context, key string) string {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows || err != nil {
		return ""
	}
	return v
}

func (s *Server) setSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// orderedApps returns the snapshot's apps reordered by the operator's saved tile
// order. Apps not named in the order keep their natural position AFTER the
// ordered ones (so a newly-discovered app always shows up). A stored name that no
// longer maps to an app is simply ignored — the setting is advisory, never a gate.
func (s *Server) orderedApps(snap *monitor.Snapshot) []monitor.App {
	if snap == nil {
		return nil
	}
	// Protected/managed projects (the read-plane socket-proxy, the edge) are
	// Mooring's own infrastructure — surfaced in the System section, never mixed
	// in with the operator's app tiles.
	apps := make([]monitor.App, 0, len(snap.Apps))
	for _, a := range snap.Apps {
		if !s.cfg.IsProtectedProject(a.Project) {
			apps = append(apps, a)
		}
	}
	order := s.getSetting(context.Background(), tileOrderKey)
	if order == "" {
		return apps
	}
	byProj := make(map[string]monitor.App, len(apps))
	for _, a := range apps {
		byProj[a.Project] = a
	}
	out := make([]monitor.App, 0, len(apps))
	seen := make(map[string]bool, len(apps))
	for _, p := range strings.Split(order, ",") {
		p = strings.TrimSpace(p)
		if a, ok := byProj[p]; ok && !seen[p] {
			out = append(out, a)
			seen[p] = true
		}
	}
	for _, a := range apps { // append any app not named in the saved order
		if !seen[a.Project] {
			out = append(out, a)
		}
	}
	return out
}

// systemApps returns the protected/managed projects (e.g. the read-plane socket-
// proxy) as read-only tiles, kept separate from the operator's apps. They are
// Mooring's own infrastructure: shown for visibility, never app-controllable.
func (s *Server) systemApps(snap *monitor.Snapshot) []monitor.App {
	if snap == nil {
		return nil
	}
	var out []monitor.App
	for _, a := range snap.Apps {
		if s.cfg.IsProtectedProject(a.Project) {
			out = append(out, a)
		}
	}
	return out
}

// handleTileOrder persists the operator's tile ordering (a comma-separated list
// of compose project names). It is a UI preference only — validated/sanitized and
// length-capped, never trusted as a security input (orderedApps only USES names
// that map to a real app, so junk is inert).
func (s *Server) handleTileOrder(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw := r.PostFormValue("order")
	if len(raw) > maxTileOrder {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return
	}
	// Sanitize: drop control characters and empty tokens; cap token count.
	var toks []string
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t == "" || strings.ContainsAny(t, "\x00\n\r") {
			continue
		}
		toks = append(toks, t)
		if len(toks) >= 1000 {
			break
		}
	}
	if err := s.setSetting(r.Context(), tileOrderKey, strings.Join(toks, ",")); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
