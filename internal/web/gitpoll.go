package web

import (
	"context"
	"time"
)

// RunGitPoller is the "just connect the repo and it works" loop: it periodically
// fetches every connected repo so change-detection needs NO webhook setup (the
// webhook stays as an optional instant trigger). It is read-plane — a fetch never
// mutates a running app — and serialized through the same single-flight gate as the
// webhook + manual deploy, so it can never pile up docker/git children. Repos that
// opted into auto_deploy then deploy through the same gated promote path.
//
// interval <= 0 disables polling (webhook-only). Blocks until ctx is cancelled.
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

// pollOneRepo fetches (and, if opted in, auto-deploys) a single repo, holding the
// single-flight gate for just that repo. If a deploy/fetch is already in progress
// anywhere, it skips this tick rather than queueing (queuing children is the OOM
// vector) — the next tick retries.
func (s *Server) pollOneRepo(ctx context.Context, project string) {
	if !s.gitDeploy.TryAcquire() {
		return
	}
	defer s.gitDeploy.Release()
	// Bound a single repo's fetch+maybe-deploy so one slow repo can't stall the loop.
	rc, cancel := context.WithTimeout(ctx, gitDeployTimeout)
	defer cancel()
	s.fetchAndMaybeDeploy(rc, project, "poller")
}
