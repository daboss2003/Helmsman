package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/Helmsman/internal/definition"
	"github.com/daboss2003/Helmsman/internal/edge"
	"github.com/daboss2003/Helmsman/internal/l4"
	"github.com/daboss2003/Helmsman/internal/ops"
	"github.com/daboss2003/Helmsman/internal/scale"
	"github.com/daboss2003/Helmsman/internal/selfheal"
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
	if err := s.applyScaling(ctx, project, def); err != nil {
		return err
	}
	if err := s.applySelfHealing(ctx, project, def); err != nil {
		return err
	}
	return s.applyOps(ctx, project, def)
}

// applyOps reconciles this app's helmsman.yaml ops_interface into the ops config store
// (the prober reads it for RICH health). Gated + additive: it only runs when ops is
// owned and the def declares the block; an omitted block leaves any dashboard-set ops
// config untouched. The shared-secret VALUE never lives in the YAML — if the block
// names a `secret` reference, its value is resolved from the encrypted secret store at
// deploy; with no reference, ops.Set keeps the stored secret (NewSecret left nil), so
// a dashboard-managed secret survives a yaml deploy.
func (s *Server) applyOps(ctx context.Context, project string, def *definition.Definition) error {
	if s.opsStore == nil || def.Spec.OpsInterface == nil {
		return nil
	}
	oi := def.Spec.OpsInterface
	in := ops.SetInput{
		Enabled:      oi.Enabled,
		BaseURL:      oi.BaseURL,
		SecretHeader: oi.SecretHeader,
		OpsMode:      oi.Mode,
		BasePath:     oi.BasePath,
		Adapter:      oi.Adapter,
	}
	if oi.Secret != "" && s.envStore != nil {
		if v, ok, err := s.envStore.Reveal(project, oi.Secret); err == nil && ok {
			in.NewSecret = &v
		}
	}
	if err := s.opsStore.Set(project, in); err != nil {
		return fmt.Errorf("apply ops_interface: %w", err)
	}
	return nil
}

// applySelfHealing persists this app's helmsman.yaml self-healing tunables into the
// supervisor's per-app policy store (the watcher reads it per tick, so a redeploy
// re-tunes without a restart). Gated + additive: it only runs when the supervisor is
// owned and the def declares the block; omitted fields keep the built-in default. An
// omitted block leaves any existing policy untouched (matching applyScaling), so a
// dashboard-managed default is never silently reset.
func (s *Server) applySelfHealing(ctx context.Context, project string, def *definition.Definition) error {
	if s.selfHeal == nil || def.Spec.SelfHealing == nil {
		return nil
	}
	if err := s.selfHeal.SavePolicy(ctx, project, selfHealPolicy(def.Spec.SelfHealing), time.Now().Unix()); err != nil {
		return fmt.Errorf("apply self_healing: %w", err)
	}
	return nil
}

// selfHealPolicy maps a definition self-healing block onto a controller policy: it
// starts from the conservative built-in default and overrides only the fields the
// YAML sets (0 = keep the default). redeploy_enabled is a bool, so it's always taken
// from the YAML (default off).
func selfHealPolicy(sh *definition.SelfHealing) selfheal.Policy {
	p := selfheal.DefaultPolicy()
	if sh.SustainTicks > 0 {
		p.SustainTicks = sh.SustainTicks
	}
	if sh.AttemptCap > 0 {
		p.AttemptCap = sh.AttemptCap
	}
	if sh.StabilizeTicks > 0 {
		p.StabilizeTicks = sh.StabilizeTicks
	}
	if sh.OOMStrikeCap > 0 {
		p.OOMStrikeCap = sh.OOMStrikeCap
	}
	if sh.WindowSeconds > 0 {
		p.WindowSeconds = int64(sh.WindowSeconds)
	}
	if sh.BackoffBaseSecs > 0 {
		p.BackoffBaseSecs = int64(sh.BackoffBaseSecs)
	}
	if sh.BackoffMaxSecs > 0 {
		p.BackoffMaxSecs = int64(sh.BackoffMaxSecs)
	}
	p.RedeployEnabled = sh.RedeployEnabled
	return p
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

// applyRoutes reconciles an app's edge (L7) + L4 routes FROM the canonical definition
// (the source of truth) — replace-by-project, so the canonical's set is exactly what's
// live. The canonical is authoritative (both the deploy and dashboard write-back feed
// it), so an empty set correctly clears the app's routes.
//
// Persisting is fail-closed: a bad route or a cross-app listener/hostname collision
// returns an error and blocks (the stores are transactional, so nothing half-applies).
// A reconcile failure is best-effort/logged (matching cert_bindings): the routes are
// persisted and a later reconcile or edge restart picks them up, so a transient edge
// hiccup can't block an otherwise-good apply.
func (s *Server) applyRoutes(ctx context.Context, project string, def *definition.Definition) error {
	if s.edgeRoutes != nil {
		routes := make([]edge.Route, 0, len(def.Spec.Edge.Routes))
		for _, r := range def.Spec.Edge.Routes {
			port := r.Port
			if port == 0 {
				port = 80
			}
			scheme := r.UpstreamScheme
			if scheme == "" {
				scheme = "http"
			}
			routes = append(routes, edge.Route{
				Hostname:        r.Hostname,
				Upstream:        r.Service + ":" + strconv.Itoa(port), // selector, resolved at apply
				UpstreamScheme:  scheme,
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
