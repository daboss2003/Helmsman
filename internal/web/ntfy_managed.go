package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/Helmsman/internal/audit"
	"github.com/daboss2003/Helmsman/internal/edge"
	"github.com/daboss2003/Helmsman/internal/ntfy"
)

// hostnameRe matches a fully-qualified DNS hostname (it must resolve to this server for
// the managed edge to terminate TLS for it).
var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

func validHostname(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	return len(h) <= 253 && hostnameRe.MatchString(h)
}

// provisionManagedNtfy stands up the Helmsman-hosted ntfy for one alert channel: it
// generates a write token (Helmsman publishes) + a read-only token (the phone
// subscribes), brings the locked-down ntfy container up, exposes it via the managed
// edge at the operator's hostname (auto-HTTPS), and saves the channel. The container is
// only ever started here — it is NOT run by default.
func (s *Server) provisionManagedNtfy(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" {
		name = "Helmsman ntfy"
	}
	hostname := strings.ToLower(strings.TrimSpace(r.PostFormValue("ntfy_hostname")))
	topic := strings.TrimSpace(r.PostFormValue("ntfy_topic"))

	if s.runner == nil || s.edgeRoutes == nil || s.edgeRecon == nil {
		s.redirectAlertsErr(w, r, "Helmsman-hosted ntfy needs the managed edge — it can't expose ntfy without it.")
		return
	}
	if !validHostname(hostname) {
		s.redirectAlertsErr(w, r, "Enter a valid hostname for ntfy (e.g. ntfy.example.com) pointed at this server.")
		return
	}
	// Single managed instance: the container + edge route are keyed to one fixed project,
	// so a second one (with a different name) would clobber the first and break teardown.
	// Enforce it server-side (the form also hides the option). A same-name resubmit is an
	// in-place reconfigure and is allowed.
	if info, ok, _ := s.alertStore.ManagedNtfy(); ok && info.Name != name {
		s.redirectAlertsErr(w, r, "A Helmsman-hosted ntfy is already configured ("+info.Name+") — delete it first to reconfigure.")
		return
	}
	// The first run pulls the image (can exceed WriteTimeout) — exempt this handler.
	clearWriteDeadline(w)
	writeTok, err := ntfy.GenerateToken()
	if err != nil {
		s.redirectAlertsErr(w, r, "internal error generating tokens")
		return
	}
	readTok, err := ntfy.GenerateToken()
	if err != nil {
		s.redirectAlertsErr(w, r, "internal error generating tokens")
		return
	}
	params := ntfy.Params{BaseURL: "https://" + hostname, Topic: topic, WriteToken: writeTok, ReadToken: readTok}
	if err := params.Validate(); err != nil {
		s.redirectAlertsErr(w, r, "invalid ntfy settings: "+err.Error())
		return
	}

	// Roll back the container + edge route if any step below fails, so a partial
	// provision never leaves an orphaned ntfy running/exposed with no channel.
	provisioned := false
	defer func() {
		if !provisioned {
			s.teardownManagedNtfy(context.Background())
		}
	}()

	// Bring the container up (the first run pulls the image — give it room).
	ec, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	if err := ntfy.EnsureRunning(ec, s.runner, s.cfg.DataDir, params, func(string) {}); err != nil {
		s.log.Warn("managed ntfy could not start", "err", err)
		s.redirectAlertsErr(w, r, "could not start the ntfy container (is Docker reachable + the image pullable?): "+err.Error())
		return
	}

	// Expose it publicly via the managed edge (Caddy auto-provisions TLS for the host).
	route := edge.Route{
		Hostname:        hostname,
		Upstream:        ntfy.Service + ":" + strconv.Itoa(ntfy.ContainerPort),
		UpstreamScheme:  "http",
		RedirectHTTP:    true,
		SecurityHeaders: true,
		Enabled:         true,
	}
	if err := s.edgeRoutes.ReplaceProject(r.Context(), ntfy.Project, []edge.Route{route}); err != nil {
		s.redirectAlertsErr(w, r, "could not add the edge route for ntfy: "+err.Error())
		return
	}
	if err := s.edgeRecon.Reconcile(r.Context()); err != nil {
		s.log.Warn("edge not reconciled after adding the ntfy route (will pick up later)", "err", err)
	}

	// Save the channel. The write token publishes (over loopback); read_token + base_url
	// are stored so the dashboard can show the operator how to subscribe.
	cfg, _ := json.Marshal(map[string]string{
		"url":        fmt.Sprintf("http://127.0.0.1:%d", ntfy.LoopbackPort),
		"topic":      topic,
		"token":      writeTok,
		"read_token": readTok,
		"base_url":   params.BaseURL,
	})
	if err := s.alertStore.SaveChannel(r.Context(), name, "ntfy_managed", cfg); err != nil {
		s.redirectAlertsErr(w, r, "channel rejected: "+err.Error())
		return
	}
	provisioned = true
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "ntfy_managed_provision", Target: hostname, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/alerts/channels", http.StatusSeeOther)
}

// teardownManagedNtfy removes the managed ntfy's edge route and stops its container
// (named volumes are kept). Best-effort.
func (s *Server) teardownManagedNtfy(ctx context.Context) {
	if s.edgeRoutes != nil {
		_ = s.edgeRoutes.ReplaceProject(ctx, ntfy.Project, nil)
		if s.edgeRecon != nil {
			_ = s.edgeRecon.Reconcile(ctx)
		}
	}
	if s.runner != nil {
		_ = ntfy.Stop(ctx, s.runner, s.cfg.DataDir, func(string) {})
	}
}

func (s *Server) redirectAlertsErr(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/alerts/channels?err="+url.QueryEscape(msg), http.StatusSeeOther)
}
