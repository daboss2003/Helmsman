package web

import (
	"context"
	"net/http"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/ops"
	secretpkg "github.com/daboss2003/mooring/internal/secret"
)

// serviceView is the per-service page model: one service's live status, self-heal
// phase, desired replicas, and its current scaling policy (to pre-fill the form). A
// dedicated page per service keeps each service's logs/actions/auto-scaling separate
// instead of crammed into one shared app screen.
type serviceView struct {
	Project, Service          string
	Found                     bool // has a live container in the snapshot
	Running                   bool
	State, Health, StatusText string
	CPUPercent                float64
	MemBytes, MemLimit        uint64
	RestartCount              int
	Phase                     string              // self-heal supervisor phase, e.g. CIRCUIT_OPEN
	DesiredReplicas           int                 // 0 when scaling isn't active
	Policy                    *definition.Scaling // current scaling policy; nil = none yet
	HasOps                    bool                // the service declares an enabled (non-basic) ops endpoint → live-poll its fragment
	Ops                       *ops.Result         // live ops probe (RICH queues/metrics); nil if no ops endpoint or unreachable
}

// probeServiceOps probes one service's own ops endpoint (from the canonical def) on
// demand and returns the RICH result (queues/metrics), or nil when the service has no
// ops endpoint, ops is off/basic, or it isn't reachable. Bounded timeout so a slow
// endpoint degrades to nil rather than hanging the request. Shared by the page handler
// and the live-poll fragment so the two can never drift.
func (s *Server) probeServiceOps(ctx context.Context, project string, svcDef definition.Service) *ops.Result {
	oi := svcDef.OpsInterface
	if oi == nil || !oi.Enabled || oi.Mode == "basic" || s.prober == nil {
		return nil
	}
	secret := ""
	if oi.Secret != "" && s.envStore != nil {
		if ent, ok, _ := s.envStore.Get(project, oi.Secret); ok {
			if v, derr := ent.DecodedValue(); derr == nil {
				secret = string(v)
			}
		}
	}
	target := ops.Target{BaseURL: oi.BaseURL, SecretHeader: oi.SecretHeader, Secret: secretpkg.New(secret), BasePath: oi.BasePath}
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	return s.prober.ProbeTarget(pctx, project, target, oi.Adapter, oi.Mode)
}

// handleServiceGet renders the per-service page.
func (s *Server) handleServiceGet(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	service := r.PathValue("service")

	var app *monitor.App
	if snap := s.snapshot(); snap != nil {
		app = snap.AppByProject(project)
	}
	sv := &serviceView{Project: project, Service: service}
	if app != nil {
		for _, svc := range app.Services {
			if svc.Service == service {
				sv.Found = true
				sv.Running = svc.Running()
				sv.State, sv.Health, sv.StatusText = svc.State, svc.Health, svc.StatusText
				sv.CPUPercent, sv.MemBytes, sv.MemLimit = svc.CPUPercent, svc.MemBytes, svc.MemLimit
				sv.RestartCount = svc.RestartCount
				break
			}
		}
	}
	inDef := false
	var svcDef definition.Service
	if def := s.currentDef(project); def != nil {
		if sd, ok := def.Spec.Compose.Services[service]; ok {
			inDef = true
			svcDef = sd
		}
		for i := range def.Spec.Scaling {
			if def.Spec.Scaling[i].Service == service {
				sv.Policy = &def.Spec.Scaling[i]
				break
			}
		}
	}
	// Unknown service: neither running nor declared in the definition.
	if !sv.Found && !inDef {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}
	sv.Phase = s.supervisorStates(project)[service]
	sv.DesiredReplicas = s.scalingDesired(project)[service]

	// Per-service ops: probe THIS service's ops endpoint (from the canonical) on demand,
	// so its RICH queues / metric cards render on its own page. (The live poll fragment
	// /partials/service/.../ops re-runs the same probe; both go through probeServiceOps.)
	if oi := svcDef.OpsInterface; oi != nil && oi.Enabled && oi.Mode != "basic" {
		sv.HasOps = true // the page wraps the ops panels in a poll fragment only when true
	}
	sv.Ops = s.probeServiceOps(r.Context(), project, svcDef)

	s.render(w, r, "service.html", tmplData{
		Title:               service + " — " + project,
		CSRFToken:           CSRFToken(r.Context()),
		Username:            sessionUser(r),
		Project:             project,
		Protected:           s.cfg.IsProtectedProject(project),
		WriteDisabledReason: s.writeDisabledReason(),
		Svc:                 sv,
	})
}

// handleServiceOpsPartial re-probes one service's ops endpoint and returns just the
// ops fragment, for the service page's live poll (mirrors handleAppPartial). The probe
// is the same one the page handler runs, via probeServiceOps.
func (s *Server) handleServiceOpsPartial(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	service := r.PathValue("service")
	sv := &serviceView{Project: project, Service: service}
	if def := s.currentDef(project); def != nil {
		if sd, ok := def.Spec.Compose.Services[service]; ok {
			sv.Ops = s.probeServiceOps(r.Context(), project, sd)
		}
	}
	s.renderPartial(w, "service_ops", tmplData{Svc: sv})
}
