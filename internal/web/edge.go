package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/Helmsman/internal/audit"
	"github.com/daboss2003/Helmsman/internal/definition"
	"github.com/daboss2003/Helmsman/internal/edge"
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
	// Write-back: an app-scoped route edits the canonical helmsman.yaml (source of
	// truth); enabling upserts it, disabling removes it, then we reconcile from the
	// canonical. Falls back to the direct projection write for an app with no canonical.
	if s.defStore != nil && rt.AppID != "" {
		if def, derr := s.defStore.Current(rt.AppID); derr == nil && def != nil {
			host := strings.ToLower(strings.TrimSpace(rt.Hostname))
			if rt.Enabled {
				svc, port, ok := parseUpstream(rt.Upstream)
				if !ok {
					http.Error(w, "upstream must be service:port", http.StatusUnprocessableEntity)
					return
				}
				scheme := rt.UpstreamScheme
				if scheme != "https" {
					scheme = ""
				}
				def.Spec.Edge.Routes = upsertRoute(def.Spec.Edge.Routes, definition.Route{
					Hostname: host, Service: svc, Port: port, PathPrefix: rt.PathPrefix,
					HSTS: rt.HSTS, SecurityHeaders: rt.SecurityHeaders, RedirectHTTP: true, UpstreamScheme: scheme,
				})
			} else {
				def.Spec.Edge.Routes = removeRoute(def.Spec.Edge.Routes, host, rt.PathPrefix)
			}
			if err := s.applyDefinition(r.Context(), rt.AppID, def, "dashboard: route "+host); err != nil {
				http.Error(w, "route rejected: "+err.Error(), http.StatusUnprocessableEntity)
				return
			}
			_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "edge_route_save", Target: host, Outcome: audit.OK, Level: audit.Security})
			http.Redirect(w, r, "/edge", http.StatusSeeOther)
			return
		}
	}
	if err := s.edgeRoutes.Save(r.Context(), rt); err != nil {
		http.Error(w, "route rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.reconcileEdge(r, "edge_route_save", rt.Hostname)
	http.Redirect(w, r, "/edge", http.StatusSeeOther)
}

// parseUpstream splits a "service:port" selector into its parts.
func parseUpstream(s string) (service string, port int, ok bool) {
	s = strings.TrimSpace(s)
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", 0, false
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil || p < 1 || p > 65535 {
		return "", 0, false
	}
	return s[:i], p, true
}

// upsertRoute replaces the entry for (Hostname, PathPrefix) or appends it.
func upsertRoute(list []definition.Route, e definition.Route) []definition.Route {
	for i := range list {
		if list[i].Hostname == e.Hostname && list[i].PathPrefix == e.PathPrefix {
			list[i] = e
			return list
		}
	}
	return append(list, e)
}

// removeRoute drops the entry matching (hostname, pathPrefix).
func removeRoute(list []definition.Route, hostname, pathPrefix string) []definition.Route {
	out := list[:0]
	for _, r := range list {
		if r.Hostname == hostname && r.PathPrefix == pathPrefix {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s *Server) handleEdgeRouteDelete(w http.ResponseWriter, r *http.Request) {
	if s.edgeRoutes == nil {
		http.Error(w, "edge unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	// Write-back: resolve the route's app + hostname, drop it from that app's canonical
	// helmsman.yaml, and reconcile from it. Falls back to a direct store delete.
	if s.defStore != nil {
		if routes, lerr := s.edgeRoutes.List(); lerr == nil {
			for _, rt := range routes {
				if rt.ID() != id || rt.AppID == "" {
					continue
				}
				if def, derr := s.defStore.Current(rt.AppID); derr == nil && def != nil {
					def.Spec.Edge.Routes = removeRoute(def.Spec.Edge.Routes, rt.Hostname, rt.PathPrefix)
					if err := s.applyDefinition(r.Context(), rt.AppID, def, "dashboard: route delete "+rt.Hostname); err != nil {
						http.Error(w, "route delete rejected: "+err.Error(), http.StatusUnprocessableEntity)
						return
					}
					_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "edge_route_delete", Target: rt.Hostname, Outcome: audit.OK, Level: audit.Security})
					http.Redirect(w, r, "/edge", http.StatusSeeOther)
					return
				}
				break
			}
		}
	}
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
