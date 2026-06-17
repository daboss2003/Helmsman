package web

import (
	"context"
	"fmt"
	"strconv"

	"github.com/daboss2003/Helmsman/internal/definition"
	"github.com/daboss2003/Helmsman/internal/edge"
	"github.com/daboss2003/Helmsman/internal/l4"
)

// applyRoutes makes a deployed app's helmsman.yaml the source of truth for its edge
// routes: it persists the def's L7 edge.routes and L4 l4_routes (replace-by-project)
// and reconciles the live edge + L4 LB. Gated + guarded:
//   - L7: replaces ONLY when the def declares routes, so an app whose routes are
//     managed in the dashboard (none in helmsman.yaml) is never silently wiped.
//   - L4: replaces whenever the L4 LB is owned — L4 routes come only from
//     helmsman.yaml, so an empty set correctly clears the app's L4 routes.
//
// Persisting is fail-closed: a bad route or a cross-app listener/hostname collision
// returns an error and blocks the deploy (the stores are transactional, so nothing
// half-applies). A reconcile failure is best-effort/logged (matching cert_bindings):
// the routes are persisted and a later reconcile or edge restart picks them up, so a
// transient edge hiccup can't block an otherwise-good deploy.
func (s *Server) applyRoutes(ctx context.Context, project string, def *definition.Definition) error {
	if s.edgeRoutes != nil && len(def.Spec.Edge.Routes) > 0 {
		routes := make([]edge.Route, 0, len(def.Spec.Edge.Routes))
		for _, r := range def.Spec.Edge.Routes {
			port := r.Port
			if port == 0 {
				port = 80
			}
			routes = append(routes, edge.Route{
				Hostname:        r.Hostname,
				Upstream:        r.Service + ":" + strconv.Itoa(port), // selector, resolved at apply
				UpstreamScheme:  "http",
				PathPrefix:      r.PathPrefix,
				HSTS:            r.HSTS,
				SecurityHeaders: r.SecurityHeaders,
				RedirectHTTP:    r.RedirectHTTP,
				Enabled:         true,
			})
		}
		if err := s.edgeRoutes.ReplaceProject(ctx, project, routes); err != nil {
			return fmt.Errorf("apply edge routes: %w", err)
		}
		if s.edgeRecon != nil {
			if err := s.edgeRecon.Reconcile(ctx); err != nil {
				s.log.Warn("edge not reconciled after route apply (will pick up later)", "project", project, "err", err)
			}
		}
	}

	if s.l4Routes != nil {
		routes := make([]l4.Route, 0, len(def.Spec.Edge.L4Routes))
		for _, r := range def.Spec.Edge.L4Routes {
			routes = append(routes, l4.Route{
				Listen:   r.Listen,
				Protocol: r.Protocol,
				Service:  r.Service,
				Port:     r.Port,
				LB:       r.LB,
			})
		}
		if err := s.l4Routes.ReplaceProject(ctx, project, routes); err != nil {
			return fmt.Errorf("apply l4 routes: %w", err)
		}
		if s.l4Reconcile != nil {
			if err := s.l4Reconcile(ctx); err != nil {
				s.log.Warn("L4 LB not reconciled after route apply (will pick up later)", "project", project, "err", err)
			}
		}
	}
	return nil
}
