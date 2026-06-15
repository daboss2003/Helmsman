package backup

import "testing"

func TestPruneImageSafe(t *testing.T) {
	s := LiveState{
		ProtectedImages:  map[string]bool{"sha256:edge": true},
		ReferencedImages: map[string]bool{"sha256:rollback": true},
		InUseImages:      map[string]bool{"sha256:running": true},
	}
	deny := map[string]string{"sha256:edge": "protected", "sha256:rollback": "rollback", "sha256:running": "in-use", "": "unresolved"}
	for d := range deny {
		if ok, _ := PruneImageSafe(d, s); ok {
			t.Errorf("image %q must NOT be prunable", d)
		}
	}
	// A genuinely orphaned image is the safe complement.
	if ok, _ := PruneImageSafe("sha256:orphan", s); !ok {
		t.Error("an unreferenced, not-in-use, non-protected image should be prunable")
	}
}

// Fail-closed: an unresolved (nil-map) LiveState must refuse every prune, not allow
// it via the safe-complement branch.
func TestPruneFailsClosedOnUnresolvedState(t *testing.T) {
	var empty LiveState // all maps nil (a failed/absent resolve)
	if ok, _ := PruneImageSafe("sha256:anything", empty); ok {
		t.Error("an unresolved LiveState must refuse image prune (fail-closed)")
	}
	if ok, _ := PruneVolumeSafe("anyvol", empty); ok {
		t.Error("an unresolved LiveState must refuse volume prune (fail-closed)")
	}
}

func TestPruneVolumeSafe(t *testing.T) {
	s := LiveState{
		ProtectedVolumes: map[string]bool{"edge_data": true},
		SoleDataVolumes:  map[string]bool{"db_data": true, "cache_data": true},
		BackedUpVolumes:  map[string]bool{"db_data": true}, // db backed up, cache not
	}
	if ok, _ := PruneVolumeSafe("edge_data", s); ok {
		t.Error("a protected volume must never be prunable")
	}
	if ok, _ := PruneVolumeSafe("cache_data", s); ok {
		t.Error("a sole-data volume NOT in backup_inventory must be refused (back it up first)")
	}
	if ok, _ := PruneVolumeSafe("db_data", s); !ok {
		t.Error("a sole-data volume that IS backed up may be pruned")
	}
	if ok, _ := PruneVolumeSafe("scratch", s); !ok {
		t.Error("a non-protected, non-sole-data volume is the safe complement")
	}
}

func TestRestoreTupleBindsAndDriftVoids(t *testing.T) {
	base := RestoreTuple("ptsha", "ctsha", []string{"v1", "v2"}, []string{"web:8080"}, []int64{100, 200})
	// Deterministic + order-independent for the sets.
	if base != RestoreTuple("ptsha", "ctsha", []string{"v2", "v1"}, []string{"web:8080"}, []int64{100, 200}) {
		t.Error("tuple must be order-independent for volumes/bindings")
	}
	// Any drift in the operation voids the token.
	drifts := []string{
		RestoreTuple("OTHER", "ctsha", []string{"v1", "v2"}, []string{"web:8080"}, []int64{100, 200}), // plaintext
		RestoreTuple("ptsha", "OTHER", []string{"v1", "v2"}, []string{"web:8080"}, []int64{100, 200}), // ciphertext
		RestoreTuple("ptsha", "ctsha", []string{"v1", "v3"}, []string{"web:8080"}, []int64{100, 200}), // target volume
		RestoreTuple("ptsha", "ctsha", []string{"v1", "v2"}, []string{"web:9090"}, []int64{100, 200}), // binding
		RestoreTuple("ptsha", "ctsha", []string{"v1", "v2"}, []string{"web:8080"}, []int64{100, 999}), // size
	}
	for i, d := range drifts {
		if d == base {
			t.Errorf("drift #%d must produce a different token (void on drift)", i)
		}
	}
}
