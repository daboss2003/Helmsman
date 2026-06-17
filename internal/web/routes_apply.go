package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/daboss2003/Helmsman/internal/definition"
	"github.com/daboss2003/Helmsman/internal/edge"
	"github.com/daboss2003/Helmsman/internal/l4"
	"github.com/daboss2003/Helmsman/internal/scale"
)

// handleDefinitionYAML serves the app's canonical helmsman.yaml — "the file,
// dashboard-updated last." For a repo-connected app that's drifted (last edited in
// the dashboard), this is how the operator commits those edits back to the repo.
func (s *Server) handleDefinitionYAML(w http.ResponseWriter, r *http.Request) {
	if s.defStore == nil {
		http.Error(w, "definition store unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	def, err := s.defStore.Current(project)
	if err != nil {
		http.Error(w, "could not load the definition", http.StatusInternalServerError)
		return
	}
	if def == nil {
		http.Error(w, "no canonical definition yet — deploy once to create it", http.StatusNotFound)
		return
	}
	canon, err := definition.Canonical(def)
	if err != nil {
		http.Error(w, "could not render the definition", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="helmsman.yaml"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(canon)
}

// applyDefinition makes def the app's CANONICAL helmsman.yaml (the single source of
// truth) and reconciles every runtime projection from it. Both planes call it: a
// deploy (file edit) and the dashboard editors (write-back), so the definition is
// always "the file, whoever-edited-last." It re-validates the canonical form (the
// same gate a committed file gets), persists it as a new version, then applies the
// projections (edge/L4 routes, scaling). note records the writer (e.g. "git deploy:
// <sha>" / "dashboard: scaling api") and drives drift detection vs the repo.
func (s *Server) applyDefinition(ctx context.Context, project string, def *definition.Definition, note string) error {
	if s.defStore != nil {
		canon, err := definition.Canonical(def)
		if err != nil {
			return fmt.Errorf("render canonical: %w", err)
		}
		if _, err := definition.Parse(canon); err != nil { // re-validate before it becomes the truth
			return fmt.Errorf("invalid definition: %w", err)
		}
		if _, err := s.defStore.SaveCanonical(ctx, def, note); err != nil {
			return fmt.Errorf("save canonical: %w", err)
		}
	}
	if err := s.applyRoutes(ctx, project, def); err != nil {
		return err
	}
	return s.applyScaling(ctx, project, def)
}

// defDriftedFromRepo reports whether the canonical was last written by the dashboard
// (so it's ahead of the repo's helmsman.yaml). The next repo deploy writes a
// "git deploy" version and clears it. Only meaningful for repo-connected apps.
func (s *Server) defDriftedFromRepo(project string) bool {
	if s.defStore == nil {
		return false
	}
	vers, err := s.defStore.List(project)
	if err != nil || len(vers) == 0 {
		return false
	}
	return strings.HasPrefix(vers[0].Note, "dashboard:")
}

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

// applyScaling persists this app's helmsman.yaml scaling policies (one per service)
// into the scale store, so a repo's yaml drives auto-scaling for SEVERAL services —
// e.g. an HTTP api and an L4 resolver in one app. Additive + gated: it only runs when
// the scaler is owned and the def declares scaling; SavePolicy validates each policy
// (and a bad one — e.g. too-small dead band — blocks the deploy, fail-closed). It does
// not touch services the def omits, so dashboard-managed policies are left alone.
func (s *Server) applyScaling(ctx context.Context, project string, def *definition.Definition) error {
	if s.scaling == nil || len(def.Spec.Scaling) == 0 {
		return nil
	}
	for _, sc := range def.Spec.Scaling {
		if err := s.scaling.SavePolicy(ctx, scale.Key{App: project, Service: sc.Service}, scalingPolicyRow(sc)); err != nil {
			return fmt.Errorf("apply scaling for %q: %w", sc.Service, err)
		}
	}
	return nil
}

// scalingPolicyRow maps a definition scaling entry to a controller policy, filling
// the dashboard defaults for any field the YAML omits so the controller contract
// (≥20-pt dead band, positive breach window, down-lazy cooldowns) holds.
func scalingPolicyRow(sc definition.Scaling) scale.PolicyRow {
	upCPU, downCPU := sc.UpCPUPct, sc.DownCPUPct
	if upCPU == 0 {
		upCPU = 80
	}
	if downCPU == 0 {
		downCPU = 40
	}
	upMem, downMem := sc.UpMemPct, sc.DownMemPct
	if upMem == 0 {
		upMem = 80
	}
	if downMem == 0 {
		downMem = 40
	}
	min, max := sc.Min, sc.Max
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	breach := int64(sc.BreachForSecs)
	if breach <= 0 {
		breach = 60
	}
	cdUp := int64(sc.CooldownUpSecs)
	if cdUp <= 0 {
		cdUp = 60
	}
	cdDown := int64(sc.CooldownDownSecs)
	if cdDown < cdUp {
		cdDown = 300
		if cdDown < cdUp {
			cdDown = cdUp
		}
	}
	return scale.PolicyRow{
		Policy: scale.Policy{
			Min: min, Max: max,
			UpCPUPct: upCPU, DownCPUPct: downCPU,
			UpMemPct: upMem, DownMemPct: downMem,
			BreachForSecs: breach, CooldownUpSecs: cdUp, CooldownDownSecs: cdDown,
		},
		Enabled:       sc.Enabled,
		PerReplicaMem: uint64(sc.PerReplicaMemMiB) << 20,
		PerReplicaCPU: uint64(sc.PerReplicaCPUMilli),
	}
}
