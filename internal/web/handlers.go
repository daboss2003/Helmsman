package web

import (
	"bytes"
	"net/http"
	"time"

	"github.com/helmsman/helmsman/internal/monitor"
	"github.com/helmsman/helmsman/internal/ops"
)

// tmplData is the view model passed to every template render.
type tmplData struct {
	Title     string
	CSRFToken string
	Username  string
	Error     string
	EdgeMode  string
	Events    []eventRow
	Snap      *monitor.Snapshot
	App       *monitor.App
	Project   string
	OpsCfg    *ops.Config
	OpsStatus *ops.Status
}

type eventRow struct {
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

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	sess := SessionFrom(r.Context())
	s.render(w, r, "home.html", tmplData{
		Title:     "Helmsman",
		CSRFToken: CSRFToken(r.Context()),
		Username:  sess.Username,
		EdgeMode:  string(s.cfg.Edge.Mode),
		Snap:      s.snapshot(),
	})
}

// handleOverviewPartial returns just the overview fragment for live polling.
func (s *Server) handleOverviewPartial(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "overview", tmplData{Snap: s.snapshot()})
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
		Title:     project + " — Helmsman",
		CSRFToken: CSRFToken(r.Context()),
		Username:  sess.Username,
		App:       app,
		Snap:      snap,
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
	s.renderPartial(w, "appdetail", tmplData{App: app, Snap: snap, CSRFToken: CSRFToken(r.Context())})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	sess := SessionFrom(r.Context())
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT ts, actor, ip, action, target, outcome, level, detail
		 FROM events ORDER BY seq DESC LIMIT 200`)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var events []eventRow
	for rows.Next() {
		var ts int64
		var e eventRow
		if err := rows.Scan(&ts, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Outcome, &e.Level, &e.Detail); err != nil {
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
	s.render(w, r, "events.html", tmplData{
		Title:     "Audit log — Helmsman",
		CSRFToken: CSRFToken(r.Context()),
		Username:  sess.Username,
		Events:    events,
	})
}

// render executes a template into a buffer first so a template error never emits
// a half-written, mis-statused response.
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data tmplData) {
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
