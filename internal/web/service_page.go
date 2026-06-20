package web

import (
	"net/http"

	"github.com/daboss2003/Helmsman/internal/definition"
	"github.com/daboss2003/Helmsman/internal/monitor"
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
	if def := s.currentDef(project); def != nil {
		if _, ok := def.Spec.Compose.Services[service]; ok {
			inDef = true
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
