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
	Reason string // non-empty when the edge isn't owned (banner)
	Routes []edgeRouteView
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
