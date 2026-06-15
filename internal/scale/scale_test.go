package scale

import "testing"

// --- candidacy ---

func goodSpec() ServiceSpec {
	return ServiceSpec{Name: "web", EdgeUpstream: true, StatelessContract: true, OptedIn: true}
}

func TestCandidacyHappyPath(t *testing.T) {
	if ok, why := Candidacy(goodSpec()); !ok {
		t.Errorf("a clean opted-in edge upstream should be a candidate, got %q", why)
	}
}

func TestCandidacyDefaultNotScalable(t *testing.T) {
	// Zero value: not opted in, not an edge upstream → not scalable.
	if ok, _ := Candidacy(ServiceSpec{}); ok {
		t.Error("default (zero) spec must NOT be scalable")
	}
}

func TestCandidacyDisqualifiers(t *testing.T) {
	cases := map[string]func(s *ServiceSpec){
		"not opted in":          func(s *ServiceSpec) { s.OptedIn = false },
		"not edge upstream":     func(s *ServiceSpec) { s.EdgeUpstream = false },
		"fixed host port":       func(s *ServiceSpec) { s.FixedHostPort = true },
		"rw volume":             func(s *ServiceSpec) { s.RWVolume = true },
		"stateful":              func(s *ServiceSpec) { s.Stateful = true },
		"identity placeholder":  func(s *ServiceSpec) { s.IdentityPlaceholder = true },
		"no stateless contract": func(s *ServiceSpec) { s.StatelessContract = false },
	}
	for name, mut := range cases {
		s := goodSpec()
		mut(&s)
		if ok, _ := Candidacy(s); ok {
			t.Errorf("%s must disqualify the service", name)
		}
	}
}

// --- capacity guard (the OOM-safety math) ---

const GiB = 1 << 30

func TestCapacityMeasuredFreeCapsGrowth(t *testing.T) {
	// 8 GiB host, but only ~1.5 GiB measured-free and a 512 MiB free floor → at most
	// 2 more replicas fit by MEASURED room even though the declared budget is larger.
	in := CapacityInput{
		Mem:       Budget{HostTotal: 8 * GiB, HostFree: 1536 << 20, Reserved: 1 * GiB, FreeFloor: 512 << 20, PerReplica: 512 << 20, Current: 2},
		CPU:       Budget{HostTotal: 8000, HostFree: 8000, Reserved: 0, PerReplica: 100, Current: 2},
		PolicyMax: 10, PerReplicaMemFloor: 64 << 20,
	}
	ceil, near, _ := MaxReplicas(in)
	if near {
		t.Fatal("not near OOM here")
	}
	// measured: current(2) + floor((1536-512)MiB / 512MiB) = 2 + 2 = 4.
	if ceil != 4 {
		t.Errorf("measured-free should cap the ceiling at 4, got %d", ceil)
	}
}

func TestCapacityDeclaredReservationCaps(t *testing.T) {
	// Lots of free right now, but the declared budget (incl. other apps' desired) is
	// the binding constraint — closes the multi-app over-commit-into-OOM hole.
	in := CapacityInput{
		Mem:       Budget{HostTotal: 4 * GiB, HostFree: 4 * GiB, Reserved: 3 * GiB /* control+edge+OTHER apps' desired */, FreeFloor: 256 << 20, PerReplica: 512 << 20, Current: 1},
		CPU:       Budget{HostTotal: 8000, HostFree: 8000, PerReplica: 100, Current: 1},
		PolicyMax: 10, PerReplicaMemFloor: 64 << 20,
	}
	ceil, _, _ := MaxReplicas(in)
	// declared: (4-3)GiB / 512MiB = 2. Even though free could fund more.
	if ceil != 2 {
		t.Errorf("declared-reservation math should cap at 2 (reserve against others' desired), got %d", ceil)
	}
}

func TestCapacityNearOOMCollapsesToOne(t *testing.T) {
	in := CapacityInput{
		Mem:       Budget{HostTotal: 1 * GiB, HostFree: 80 << 20, Reserved: 256 << 20, FreeFloor: 128 << 20, PerReplica: 128 << 20, Current: 3},
		CPU:       Budget{HostTotal: 4000, HostFree: 4000, PerReplica: 100, Current: 3},
		PolicyMax: 10, PerReplicaMemFloor: 64 << 20, NearOOMFreeBytes: 128 << 20,
	}
	ceil, near, _ := MaxReplicas(in)
	if !near || ceil != 1 {
		t.Errorf("near-OOM must collapse to effective_max=1, got ceil=%d near=%v", ceil, near)
	}
}

func TestCapacityImplausibleReservationRefusesGrowth(t *testing.T) {
	in := CapacityInput{
		Mem:       Budget{HostTotal: 8 * GiB, HostFree: 8 * GiB, PerReplica: 1 << 20 /* 1 MiB, implausible */, Current: 2},
		CPU:       Budget{HostTotal: 8000, HostFree: 8000, PerReplica: 100, Current: 2},
		PolicyMax: 50, PerReplicaMemFloor: 64 << 20,
	}
	ceil, _, reason := MaxReplicas(in)
	if ceil != 2 || reason == "" {
		t.Errorf("an implausible per-replica reservation must refuse growth (ceiling=current), got %d %q", ceil, reason)
	}
}

func TestCapacityCPUBudgetCanBind(t *testing.T) {
	// Memory is plentiful but the CPU budget is the binding constraint.
	in := CapacityInput{
		Mem:       Budget{HostTotal: 32 * GiB, HostFree: 32 * GiB, PerReplica: 256 << 20, Current: 1},
		CPU:       Budget{HostTotal: 4000, HostFree: 4000, Reserved: 1000, FreeFloor: 500, PerReplica: 1000, Current: 1},
		PolicyMax: 20, PerReplicaMemFloor: 64 << 20,
	}
	ceil, _, _ := MaxReplicas(in)
	// cpu declared: (4000-1000)/1000 = 3; measured: 1 + (4000-500)/1000 = 1+3 = 4 → min 3.
	if ceil != 3 {
		t.Errorf("the CPU budget should bind the ceiling at 3, got %d", ceil)
	}
}

func TestCapacityPolicyMaxCaps(t *testing.T) {
	in := CapacityInput{
		Mem:       Budget{HostTotal: 64 * GiB, HostFree: 64 * GiB, PerReplica: 256 << 20, Current: 1},
		CPU:       Budget{HostTotal: 64000, HostFree: 64000, PerReplica: 100, Current: 1},
		PolicyMax: 5, PerReplicaMemFloor: 64 << 20,
	}
	if ceil, _, _ := MaxReplicas(in); ceil != 5 {
		t.Errorf("the policy max should cap the ceiling at 5, got %d", ceil)
	}
}

func TestStatefulImageDenylist(t *testing.T) {
	stateful := []string{"postgres", "postgres:16", "ghcr.io/acme/postgres:16", "redis:7-alpine", "docker.io/library/mysql", "rabbitmq:3-management", "mongo"}
	for _, img := range stateful {
		if !StatefulImage(img) {
			t.Errorf("%q must be detected as stateful (C4)", img)
		}
	}
	scalable := []string{"nginx", "caddy", "ghcr.io/acme/web:1.2", "my-postgres-helper", "node:20", "myapp/api"}
	for _, img := range scalable {
		if StatefulImage(img) {
			t.Errorf("%q must NOT be flagged stateful", img)
		}
	}
}
