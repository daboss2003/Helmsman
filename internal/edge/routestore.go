package edge

import (
	"context"
	"strings"
	"time"

	"github.com/daboss2003/Helmsman/internal/store"
)

// RouteStore persists the declarative app_routes set (Layer 1). The edge config is
// re-rendered as a WHOLE document from this set on every apply (never stored as
// text — SBD-7).
type RouteStore struct{ db *store.DB }

// NewRouteStore builds a RouteStore.
func NewRouteStore(db *store.DB) *RouteStore { return &RouteStore{db: db} }

// Save validates + upserts a route by id (0 = insert). ValidateRoute rejects
// wildcards, control-plane upstreams, and loopback targets before it can persist.
func (s *RouteStore) Save(ctx context.Context, r Route) error {
	r.Hostname = strings.ToLower(strings.TrimSpace(r.Hostname))
	r.Upstream = strings.TrimSpace(r.Upstream)
	if r.UpstreamScheme == "" {
		r.UpstreamScheme = "http"
	}
	if err := ValidateRoute(r); err != nil {
		return err
	}
	if r.id == 0 {
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO app_routes(app_id, hostname, upstream, upstream_scheme, path_prefix, redirect_http, hsts, security_headers, enabled, created_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.AppID, r.Hostname, r.Upstream, r.UpstreamScheme, r.PathPrefix,
			b2i(r.RedirectHTTP), b2i(r.HSTS), b2i(r.SecurityHeaders), b2i(r.Enabled), time.Now().Unix())
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE app_routes SET app_id=?, hostname=?, upstream=?, upstream_scheme=?, path_prefix=?, redirect_http=?, hsts=?, security_headers=?, enabled=? WHERE id=?`,
		r.AppID, r.Hostname, r.Upstream, r.UpstreamScheme, r.PathPrefix,
		b2i(r.RedirectHTTP), b2i(r.HSTS), b2i(r.SecurityHeaders), b2i(r.Enabled), r.id)
	return err
}

// List returns all routes (for rendering + the UI).
func (s *RouteStore) List() ([]Route, error) {
	rows, err := s.db.Query(
		`SELECT id, app_id, hostname, upstream, upstream_scheme, path_prefix, redirect_http, hsts, security_headers, enabled FROM app_routes ORDER BY hostname, path_prefix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		var r Route
		var redir, hsts, sec, en int
		if err := rows.Scan(&r.id, &r.AppID, &r.Hostname, &r.Upstream, &r.UpstreamScheme, &r.PathPrefix, &redir, &hsts, &sec, &en); err != nil {
			return nil, err
		}
		r.RedirectHTTP, r.HSTS, r.SecurityHeaders, r.Enabled = redir == 1, hsts == 1, sec == 1, en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// ID returns a route's row id (for the UI).
func (r Route) ID() int64 { return r.id }

// Delete removes a route by id.
func (s *RouteStore) Delete(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_routes WHERE id=?`, id)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
