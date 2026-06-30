package l4

import (
	"context"
	"fmt"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

// RouteStore persists the L4 routes an app declares (mooring.yaml edge.l4_routes),
// keyed by project. The L4 LB config is rendered from the union of all projects'
// routes — never stored as nginx text. A listener (listen+protocol) is globally
// unique (DB constraint), so two apps can't claim the same public port.
type RouteStore struct{ db *store.DB }

// NewRouteStore builds a store over the shared DB.
func NewRouteStore(db *store.DB) *RouteStore { return &RouteStore{db: db} }

// ReplaceProject atomically replaces all of one project's L4 routes with the given
// set (the deploy-time op: an app's mooring.yaml is the source of truth for its
// routes). Every route is validated first; a cross-project listener collision trips
// the UNIQUE(listen, protocol) constraint and fails the whole transaction (nothing
// is changed) so the deploy is blocked with a clear error rather than hijacking a
// port another app owns.
func (s *RouteStore) ReplaceProject(ctx context.Context, project string, routes []Route) error {
	if project == "" {
		return fmt.Errorf("l4 store: empty project")
	}
	for _, r := range routes {
		if err := ValidateRoute(r); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_l4_routes WHERE app_id = ?`, project); err != nil {
		return err
	}
	now := time.Now().Unix()
	for _, r := range routes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO app_l4_routes(app_id, listen, protocol, service, port, lb, created_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?)`,
			project, r.Listen, r.Protocol, r.Service, r.Port, r.LB, now); err != nil {
			return fmt.Errorf("l4 route %d/%s: %w (a listener may be claimed by another app)", r.Listen, r.Protocol, err)
		}
	}
	return tx.Commit()
}

// List returns every project's L4 routes (the input to a render), ordered
// deterministically. AppID is returned so the reconciler can scope replica discovery
// to the owning project; Pool is left empty for the reconciler to populate.
func (s *RouteStore) List() ([]Route, error) {
	rows, err := s.db.Query(
		`SELECT app_id, listen, protocol, service, port, lb FROM app_l4_routes ORDER BY listen, protocol`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.AppID, &r.Listen, &r.Protocol, &r.Service, &r.Port, &r.LB); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
