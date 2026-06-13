package web

import (
	"net/http"

	"github.com/helmsman/helmsman/internal/audit"
	"github.com/helmsman/helmsman/internal/ops"
)

// handleOpsConfigGet renders the per-app App Ops Interface configuration form.
func (s *Server) handleOpsConfigGet(w http.ResponseWriter, r *http.Request) {
	if s.opsStore == nil {
		http.Error(w, "ops not available", http.StatusNotFound)
		return
	}
	project := r.PathValue("project")
	cfg, _, err := s.opsStore.Get(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cfg.Project = project
	s.renderOpsConfig(w, r, project, &cfg, "")
}

// handleOpsConfigPost saves ops coordinates. The shared secret is write-only:
// a blank field keeps the stored secret; "clear_secret" removes it.
func (s *Server) handleOpsConfigPost(w http.ResponseWriter, r *http.Request) {
	if s.opsStore == nil {
		http.Error(w, "ops not available", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	project := r.PathValue("project")

	in := ops.SetInput{
		Enabled:      r.PostFormValue("enabled") == "on",
		BaseURL:      r.PostFormValue("base_url"),
		SecretHeader: r.PostFormValue("secret_header"),
		OpsMode:      r.PostFormValue("ops_mode"),
		BasePath:     r.PostFormValue("base_path"),
		Adapter:      r.PostFormValue("adapter"),
	}
	// Tri-state secret: clear > replace > keep.
	if r.PostFormValue("clear_secret") == "on" {
		empty := ""
		in.NewSecret = &empty
	} else if v := r.PostFormValue("secret"); v != "" {
		in.NewSecret = &v
	}

	if err := s.opsStore.Set(project, in); err != nil {
		// Re-render the form with the validation error (no secret echoed back).
		cfg, _, _ := s.opsStore.Get(project)
		cfg.Project = project
		s.renderOpsConfig(w, r, project, &cfg, err.Error())
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(),
		Action: "ops_config_set", Target: project, Outcome: audit.OK, Level: audit.Security,
	})
	http.Redirect(w, r, "/apps/"+project, http.StatusSeeOther)
}

// handleQueueAction performs a server-side, secret-bearing queue action (the
// secret never reaches the browser, plan §4.2).
func (s *Server) handleQueueAction(w http.ResponseWriter, r *http.Request) {
	if s.prober == nil {
		http.Error(w, "ops not available", http.StatusNotFound)
		return
	}
	project := r.PathValue("project")
	queue := r.PathValue("queue")
	action := r.PathValue("action")

	err := s.prober.QueueAction(r.Context(), project, queue, action)
	outcome := audit.OK
	if err != nil {
		outcome = audit.Error
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(),
		Action: "ops_queue_" + action, Target: project + "/" + queue, Outcome: outcome, Level: audit.Info,
	})
	if err != nil {
		http.Error(w, "queue action failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/apps/"+project, http.StatusSeeOther)
}

func (s *Server) renderOpsConfig(w http.ResponseWriter, r *http.Request, project string, cfg *ops.Config, errMsg string) {
	sess := SessionFrom(r.Context())
	var status *ops.Status
	if st, ok := s.opsStore.Status(project); ok {
		status = &st
	}
	s.render(w, r, "ops_config.html", tmplData{
		Title:     "Ops config — " + project,
		CSRFToken: CSRFToken(r.Context()),
		Username:  sess.Username,
		Error:     errMsg,
		Project:   project,
		OpsCfg:    cfg,
		OpsStatus: status,
	})
}

func sessionUser(r *http.Request) string {
	if s := SessionFrom(r.Context()); s != nil {
		return s.Username
	}
	return ""
}
