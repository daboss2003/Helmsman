package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/helmsman/helmsman/internal/audit"
	"github.com/helmsman/helmsman/internal/edge"
)

// M11 managed-edge UI: per-app public routes. The operator manages routes only —
// Helmsman renders + pushes the WHOLE Caddy config (never edited by hand).

type edgeRouteView struct {
	ID              int64
	AppID           string
	Hostname        string
	Upstream        string
	UpstreamScheme  string
	PathPrefix      string
	HSTS            bool
	SecurityHeaders bool
	Enabled         bool
}

type edgeView struct {
	Reason          string // non-empty when the edge isn't owned (banner)
	Routes          []edgeRouteView
	Overlay         string // the Layer-2 overlay JSON (Advanced tab), if any
	OverlayTampered bool   // the stored overlay's HMAC did not verify (warn)
}

func (s *Server) handleEdge(w http.ResponseWriter, r *http.Request) {
	if s.edgeRoutes == nil {
		http.Error(w, "edge unavailable", http.StatusServiceUnavailable)
		return
	}
	ev := &edgeView{Reason: s.edgeReason}
	if routes, err := s.edgeRoutes.List(); err == nil {
		for _, rt := range routes {
			ev.Routes = append(ev.Routes, edgeRouteView{
				ID: rt.ID(), AppID: rt.AppID, Hostname: rt.Hostname, Upstream: rt.Upstream,
				UpstreamScheme: rt.UpstreamScheme, PathPrefix: rt.PathPrefix,
				HSTS: rt.HSTS, SecurityHeaders: rt.SecurityHeaders, Enabled: rt.Enabled,
			})
		}
	}
	if s.edgeOverlay != nil {
		if raw, verified, err := s.edgeOverlay.Raw(r.Context()); err == nil {
			ev.Overlay = string(raw)
			ev.OverlayTampered = !verified
		}
	}
	s.render(w, r, "edge.html", tmplData{
		Title:     "Edge routes — Helmsman",
		CSRFToken: CSRFToken(r.Context()),
		Username:  sessionUser(r),
		Edge:      ev,
	})
}

func (s *Server) handleEdgeRouteSave(w http.ResponseWriter, r *http.Request) {
	if s.edgeRoutes == nil {
		http.Error(w, "edge unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	rt := edge.Route{
		AppID:           strings.TrimSpace(r.PostFormValue("app_id")),
		Hostname:        r.PostFormValue("hostname"),
		Upstream:        r.PostFormValue("upstream"),
		UpstreamScheme:  r.PostFormValue("upstream_scheme"),
		PathPrefix:      strings.TrimSpace(r.PostFormValue("path_prefix")),
		RedirectHTTP:    true,
		HSTS:            r.PostFormValue("hsts") == "on",
		SecurityHeaders: r.PostFormValue("security_headers") == "on",
		Enabled:         r.PostFormValue("enabled") == "on",
	}
	if err := s.edgeRoutes.Save(r.Context(), rt); err != nil {
		http.Error(w, "route rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.reconcileEdge(r, "edge_route_save", rt.Hostname)
	http.Redirect(w, r, "/edge", http.StatusSeeOther)
}

func (s *Server) handleEdgeRouteDelete(w http.ResponseWriter, r *http.Request) {
	if s.edgeRoutes == nil {
		http.Error(w, "edge unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	_ = s.edgeRoutes.Delete(r.Context(), id)
	s.reconcileEdge(r, "edge_route_delete", strconv.FormatInt(id, 10))
	http.Redirect(w, r, "/edge", http.StatusSeeOther)
}

// managedHosts builds the set of Helmsman-owned hostnames the overlay may not
// shadow: the Layer-0 admin vhost host + every ENABLED Layer-1 app route host
// (matching exactly what RenderComposite puts in its `seen` set, so a save-time
// reject lines up with the apply-time conflict gate).
func (s *Server) managedHosts() map[string]bool {
	managed := map[string]bool{}
	if s.edgeAdminHost != "" {
		managed[strings.ToLower(strings.TrimSpace(s.edgeAdminHost))] = true
	}
	if s.edgeRoutes != nil {
		if routes, err := s.edgeRoutes.List(); err == nil {
			for _, rt := range routes {
				if rt.Enabled {
					managed[strings.ToLower(strings.TrimSpace(rt.Hostname))] = true
				}
			}
		}
	}
	return managed
}

// handleEdgeOverlaySave validates + persists the Layer-2 operator overlay (the
// Advanced tab). The text is conflict-checked + linted as untrusted; a violation is
// a hard reject (operator feedback), never a silent merge. The overlay is NEVER
// loaded verbatim — the reconcile re-derives the composite from typed structs.
func (s *Server) handleEdgeOverlaySave(w http.ResponseWriter, r *http.Request) {
	if s.edgeOverlay == nil {
		http.Error(w, "edge unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	overlay := strings.TrimSpace(r.PostFormValue("overlay"))
	if err := s.edgeOverlay.Save(r.Context(), []byte(overlay), s.managedHosts(), sessionUser(r)); err != nil {
		// A rejected overlay must surface loudly — and be audited as a security event
		// (an operator tried to push edge config that the reject tier refused).
		_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "edge_overlay_rejected", Target: err.Error(), Outcome: audit.Error, Level: audit.Security})
		http.Error(w, "overlay rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.reconcileEdge(r, "edge_overlay_save", "")
	http.Redirect(w, r, "/edge", http.StatusSeeOther)
}

// handleEdgeOverlayClear drops the Layer-2 overlay (saves an empty overlay), keeping
// the app routes — the web equivalent of `helmsman edge restore-default`'s overlay
// drop.
func (s *Server) handleEdgeOverlayClear(w http.ResponseWriter, r *http.Request) {
	if s.edgeOverlay == nil {
		http.Error(w, "edge unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.edgeOverlay.Save(r.Context(), nil, s.managedHosts(), sessionUser(r)); err != nil {
		http.Error(w, "clear failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.reconcileEdge(r, "edge_overlay_clear", "")
	http.Redirect(w, r, "/edge", http.StatusSeeOther)
}

// reconcileEdge re-renders + pushes the whole config after a route change. The
// route is already persisted; a reconcile failure (edge not owned / Caddy down)
// is logged + audited but never fails the save (it applies when the edge is up).
func (s *Server) reconcileEdge(r *http.Request, action, target string) {
	outcome := audit.OK
	if s.edgeRecon != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := s.edgeRecon.Reconcile(ctx); err != nil {
			outcome = audit.Error
			s.log.Warn("edge reconcile failed (route saved; will apply when the edge is up)", "err", err)
		}
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: action, Target: target, Outcome: outcome, Level: audit.Security})
}
