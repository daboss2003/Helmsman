package web

import (
	"bytes"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/helmsman/helmsman/internal/envstore"
	"github.com/helmsman/helmsman/internal/monitor"
	"github.com/helmsman/helmsman/internal/ops"
)

// tmplData is the view model passed to every template render.
type tmplData struct {
	Title       string
	CSRFToken   string
	Username    string
	Error       string
	EdgeMode    string
	Events      []eventRow
	Snap        *monitor.Snapshot
	OrderedApps []monitor.App     // overview tiles in the operator's saved order (M7)
	Provisioned []provisionedView // provisioned apps incl. not-yet-deployed (M8)
	App         *monitor.App
	Project     string
	OpsCfg      *ops.Config
	OpsStatus   *ops.Status

	WriteDisabledReason string // non-empty when the §0 write-plane gate is closed

	EnvVersion     int
	EnvLiterals    []envEntryView
	EnvSecrets     []envEntryView
	EnvLiteralText string
	EnvVersions    []envstore.Version
	FileSecrets    []fileSecretView

	ManagedFiles []configFileView
	CertBindings []certBindingView

	Git    *gitView
	Setup  *setupView
	Alerts *alertsView
	Edge   *edgeView

	// Supervisor (M13): per-service FSM phase, e.g. "CIRCUIT_OPEN", for the app view.
	Supervisor map[string]string
	// Scaling (M14): per-service desired replica count, for the app view.
	Scaling map[string]int

	// Audit-log viewer filters + pagination (M7).
	EventLevel    string
	EventOutcome  string
	EventQuery    string
	EventOlderURL string // "" when there is no older page
}

type eventRow struct {
	Seq     int64
	When    string
	Actor   string
	IP      string
	Action  string
	Target  string
	Outcome string
	Level   string
	Detail  string
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, errMsg string) {
	s.render(w, r, "login.html", tmplData{
		Title:     "Sign in — Helmsman",
		CSRFToken: CSRFToken(r.Context()),
		Error:     errMsg,
	})
}

func (s *Server) snapshot() *monitor.Snapshot {
	if s.mon == nil {
		return nil
	}
	return s.mon.Snapshot()
}

// writeDisabledReason returns "" if lifecycle actions are available, else why not.
func (s *Server) writeDisabledReason() string {
	if s.runner == nil {
		return "write plane unavailable"
	}
	if ok, reason := s.runner.WriteAllowed(); !ok {
		return reason
	}
	return ""
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	sess := SessionFrom(r.Context())
	snap := s.snapshot()
	s.render(w, r, "home.html", tmplData{
		Title:       "Helmsman",
		CSRFToken:   CSRFToken(r.Context()),
		Username:    sess.Username,
		EdgeMode:    string(s.cfg.Edge.Mode),
		Snap:        snap,
		OrderedApps: s.orderedApps(snap),
		Provisioned: s.provisionedApps(),
	})
}

// handleOverviewPartial returns just the overview fragment for live polling.
func (s *Server) handleOverviewPartial(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshot()
	s.renderPartial(w, "overview", tmplData{Snap: snap, OrderedApps: s.orderedApps(snap)})
}

func (s *Server) handleApp(w http.ResponseWriter, r *http.Request) {
	sess := SessionFrom(r.Context())
	project := r.PathValue("project")
	snap := s.snapshot()
	var app *monitor.App
	if snap != nil {
		app = snap.AppByProject(project)
	}
	if app == nil {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	s.render(w, r, "app.html", tmplData{
		Title:               project + " — Helmsman",
		CSRFToken:           CSRFToken(r.Context()),
		Username:            sess.Username,
		App:                 app,
		Snap:                snap,
		WriteDisabledReason: s.writeDisabledReason(),
		Supervisor:          s.supervisorStates(project),
		Scaling:             s.scalingDesired(project),
	})
}

// handleAppPartial returns just the app service-table fragment for live polling.
func (s *Server) handleAppPartial(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	snap := s.snapshot()
	var app *monitor.App
	if snap != nil {
		app = snap.AppByProject(project)
	}
	if app == nil {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	s.renderPartial(w, "appdetail", tmplData{App: app, Snap: snap, CSRFToken: CSRFToken(r.Context()), WriteDisabledReason: s.writeDisabledReason(), Supervisor: s.supervisorStates(project)})
}

// eventsPageSize bounds one page of the audit viewer.
const eventsPageSize = 200

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	sess := SessionFrom(r.Context())

	// Parse + tightly validate the filters (only known enum values; substring is
	// capped and LIKE-escaped). Unknown values are dropped to "no filter".
	level := allowOne(r.URL.Query().Get("level"), "info", "security")
	outcome := allowOne(r.URL.Query().Get("outcome"), "ok", "deny", "error")
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 100 {
		q = q[:100]
	}
	var before int64
	if b, err := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64); err == nil && b > 0 {
		before = b
	}

	where := []string{}
	args := []any{}
	if level != "" {
		where = append(where, "level = ?")
		args = append(args, level)
	}
	if outcome != "" {
		where = append(where, "outcome = ?")
		args = append(args, outcome)
	}
	if q != "" {
		where = append(where, "(action LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\')")
		pat := "%" + escapeLike(q) + "%"
		args = append(args, pat, pat)
	}
	if before > 0 {
		where = append(where, "seq < ?")
		args = append(args, before)
	}
	query := `SELECT seq, ts, actor, ip, action, target, outcome, level, detail FROM events`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY seq DESC LIMIT ?"
	args = append(args, eventsPageSize)

	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var events []eventRow
	for rows.Next() {
		var ts int64
		var e eventRow
		if err := rows.Scan(&e.Seq, &ts, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Outcome, &e.Level, &e.Detail); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		e.When = time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05Z")
		events = append(events, e)
	}
	// rows.Next() returns false on error too; without this a truncated audit view
	// would render as complete (review #9).
	if err := rows.Err(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := tmplData{
		Title:        "Audit log — Helmsman",
		CSRFToken:    CSRFToken(r.Context()),
		Username:     sess.Username,
		Events:       events,
		EventLevel:   level,
		EventOutcome: outcome,
		EventQuery:   q,
	}
	// Offer an "older" link only when the page was full (more may exist).
	if len(events) == eventsPageSize {
		v := url.Values{}
		if level != "" {
			v.Set("level", level)
		}
		if outcome != "" {
			v.Set("outcome", outcome)
		}
		if q != "" {
			v.Set("q", q)
		}
		v.Set("before", strconv.FormatInt(events[len(events)-1].Seq, 10))
		data.EventOlderURL = "/events?" + v.Encode()
	}
	s.render(w, r, "events.html", data)
}

// allowOne returns v iff it is one of allowed, else "" (drop the filter).
func allowOne(v string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return ""
}

// escapeLike escapes the LIKE metacharacters so a substring filter is a literal
// match (used with ESCAPE '\').
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// render executes a template into a buffer first so a template error never emits
// a half-written, mis-statused response.
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data tmplData) {
	// Backfill the shell's needs so every authenticated page renders the sidebar +
	// edge badge without each handler having to remember (login stays unauthenticated:
	// no session → no Username → no shell, which is the centered-card layout it wants).
	if data.Username == "" {
		if sess := SessionFrom(r.Context()); sess != nil {
			data.Username = sess.Username
		}
	}
	if data.EdgeMode == "" {
		data.EdgeMode = string(s.cfg.Edge.Mode)
	}
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Authenticated/dynamic pages (incl. the audit log and the CSRF token in the
	// page) must not be retained by the browser bfcache or any cache (review #19).
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

// renderPartial renders a named {{define}} block (a fragment for live polling).
func (s *Server) renderPartial(w http.ResponseWriter, name string, data tmplData) {
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}
