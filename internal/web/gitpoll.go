package web

import (
	"context"
	"time"
)

// RunGitPoller is the "just connect the repo and it works" loop: it periodically
// FETCHES every connected repo so change-detection needs NO webhook setup. It is
// READ-PLANE ONLY — it never deploys; it surfaces an "update available" the operator
// deploys with a click (push-to-deploy stays an explicit opt-in via the webhook +
// auto_deploy, never this background loop). A fetch never mutates a running app, and
// the loop is serialized through the same single-flight gate as deploys, so it can
// never pile up docker/git children.
//
// interval <= 0 disables polling. Blocks until ctx is cancelled.
func (s *Server) RunGitPoller(ctx context.Context, interval time.Duration) {
	if s.gitStore == nil || interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.pollAllRepos(ctx)
		}
	}
}

// pollAllRepos fetches each connected, non-protected repo once. Protected projects
// (the socket-proxy, the edge) are never git-managed and are skipped defensively.
func (s *Server) pollAllRepos(ctx context.Context) {
	cfgs, err := s.gitStore.List()
	if err != nil {
		return
	}
	for _, c := range cfgs {
		if ctx.Err() != nil {
			return
		}
		if s.cfg.IsProtectedProject(c.Project) {
			continue
		}
		s.pollOneRepo(ctx, c.Project)
	}
}

// pollOneRepo FETCHES a single repo (never deploys), holding the single-flight gate
// for just that repo. If a deploy/fetch is already in progress anywhere, it skips this
// tick rather than queueing (queuing children is the OOM vector) — the next tick
// retries. The fetch is bounded by its own short timeout (in doFetch), so a slow or
// hostile repo endpoint can't hold the shared gate for a deploy-sized window.
func (s *Server) pollOneRepo(ctx context.Context, project string) {
	if !s.gitDeploy.TryAcquire() {
		return
	}
	defer s.gitDeploy.Release()
	if _, _, err := s.doFetch(ctx, project); err != nil {
		s.log.Warn("git poll fetch failed", "project", project)
	}
}
