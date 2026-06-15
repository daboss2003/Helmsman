package definition

import "testing"

func base() *Definition {
	d, err := Parse([]byte(goodDef))
	if err != nil {
		panic(err)
	}
	return d
}

func TestMergeBothUnchanged(t *testing.T) {
	res, err := Merge3(base(), base(), base())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean() {
		t.Errorf("identical defs must merge clean, got conflicts=%v repo=%v", res.Conflicts, res.RepoChanges)
	}
}

func TestMergeLocalOnlyChangeTaken(t *testing.T) {
	local := base()
	local.Spec.Scaling = &Scaling{Service: "web", Enabled: true, Min: 1, Max: 3}
	res, err := Merge3(base(), local, base())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean() {
		t.Errorf("a local-only change needs no ack and no conflict, got %+v", res)
	}
	merged, _ := res.Definition()
	if merged.Spec.Scaling == nil || merged.Spec.Scaling.Max != 3 {
		t.Error("a local-only change must be taken into the merge")
	}
}

func TestMergeRepoOnlyChangeRequiresAck(t *testing.T) {
	repo := base()
	repo.Spec.Git = &Git{Repo: "https://x/y", AutoDeploy: true} // attacker flips auto_deploy in the repo
	res, err := Merge3(base(), base(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) != 0 {
		t.Errorf("a repo-only change is not a conflict, got %v", res.Conflicts)
	}
	if len(res.RepoChanges) == 0 {
		t.Fatal("a repo-side change MUST require acknowledgement (never silently folded in)")
	}
	if res.Clean() {
		t.Error("an unacknowledged repo change must make the merge non-clean")
	}
}

func TestMergeBothChangedSameWins(t *testing.T) {
	local, repo := base(), base()
	local.Spec.Scaling = &Scaling{Service: "web", Max: 5}
	repo.Spec.Scaling = &Scaling{Service: "web", Max: 5} // identical change on both sides
	res, err := Merge3(base(), local, repo)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean() {
		t.Errorf("an identical change on both sides must merge clean, got %+v", res)
	}
}

func TestMergeBothChangedDifferentlyConflicts(t *testing.T) {
	local, repo := base(), base()
	local.Spec.Scaling = &Scaling{Service: "web", Max: 5}
	repo.Spec.Scaling = &Scaling{Service: "web", Max: 9} // different change to the same field
	res, err := Merge3(base(), local, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) == 0 {
		t.Fatal("both sides changing the same field differently MUST conflict (never auto-merge)")
	}
}

// Non-conflicting changes on BOTH sides reassemble into a definition carrying both
// (but the repo side still requires ack, so the merge isn't auto-applied).
func TestMergeNonConflictingBothSides(t *testing.T) {
	local, repo := base(), base()
	local.Spec.Scaling = &Scaling{Service: "web", Max: 4} // local adds scaling
	repo.Spec.Git = &Git{Repo: "https://x/y"}             // repo adds git (different field)
	res, err := Merge3(base(), local, repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Conflicts) != 0 {
		t.Errorf("changes to different fields must not conflict, got %v", res.Conflicts)
	}
	if len(res.RepoChanges) == 0 {
		t.Error("the repo-side git addition must require ack")
	}
	merged, _ := res.Definition()
	if merged.Spec.Scaling == nil || merged.Spec.Git == nil {
		t.Error("a non-conflicting merge must carry both sides' changes")
	}
}
