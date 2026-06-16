package web

import (
	"context"
	"testing"
	"time"
)

// The poller must be a prompt no-op when disabled (interval <= 0) so webhook-only
// operators pay nothing, and the loop must exit cleanly on a cancelled context.
func TestGitPollerDisabledReturnsImmediately(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	for _, iv := range []time.Duration{0, -time.Second} {
		done := make(chan struct{})
		go func() { e.srv.RunGitPoller(context.Background(), iv); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("RunGitPoller(%v) did not return immediately when disabled", iv)
		}
	}
}

func TestGitPollerStopsOnContextCancel(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.srv.RunGitPoller(ctx, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunGitPoller did not stop on context cancel")
	}
}

// pollAllRepos with no connected repos is a safe no-op (no panic, no network).
func TestPollAllReposEmptyIsSafe(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.pollAllRepos(context.Background())
}

// The focus gate is what makes the poller idle when nobody is looking: a server
// that has never been pinged is "inactive", a fresh heartbeat makes it "active",
// and a heartbeat older than the window goes inactive again.
func TestDashActiveRecentlyGate(t *testing.T) {
	s := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "").srv

	if s.dashActiveRecently() {
		t.Fatal("never-pinged server must be inactive (so the poller stays idle)")
	}

	s.lastActive.Store(time.Now().UnixNano())
	if !s.dashActiveRecently() {
		t.Fatal("server pinged just now must be active")
	}

	s.lastActive.Store(time.Now().Add(-dashActiveWindow - time.Second).UnixNano())
	if s.dashActiveRecently() {
		t.Fatal("heartbeat older than the window must be inactive again")
	}
}
