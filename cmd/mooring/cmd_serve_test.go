package main

import (
	"testing"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/socketproxy"
)

// The managed socket-proxy is the read-plane security boundary; it must be protected
// from every write path by default, without the operator listing it (review finding).
func TestProtectManagedProxy(t *testing.T) {
	// Default (managed) install: the proxy project is seeded + protected.
	cfg := &config.Config{}
	protectManagedProxy(cfg)
	if !cfg.IsProtectedProject(socketproxy.Project) {
		t.Fatalf("managed proxy %q must be protected by default", socketproxy.Project)
	}

	// Idempotent: a second call (or an operator who already listed it) doesn't dupe.
	protectManagedProxy(cfg)
	n := 0
	for _, p := range cfg.ProtectedProjects {
		if p == socketproxy.Project {
			n++
		}
	}
	if n != 1 {
		t.Errorf("proxy project listed %d times, want exactly 1 (idempotent)", n)
	}

	// Operator-listed projects are preserved alongside the seeded proxy.
	cfg2 := &config.Config{ProtectedProjects: []string{"edge-stack"}}
	protectManagedProxy(cfg2)
	if !cfg2.IsProtectedProject("edge-stack") || !cfg2.IsProtectedProject(socketproxy.Project) {
		t.Error("must preserve operator projects AND add the proxy")
	}

	// external_proxy: Mooring doesn't run the proxy, so it doesn't seed it.
	cfg3 := &config.Config{}
	cfg3.Docker.ExternalProxy = true
	protectManagedProxy(cfg3)
	if cfg3.IsProtectedProject(socketproxy.Project) {
		t.Error("with external_proxy, Mooring must not seed the proxy project")
	}
}
