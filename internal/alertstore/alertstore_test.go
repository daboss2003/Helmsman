package alertstore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helmsman/helmsman/internal/alert"
	"github.com/helmsman/helmsman/internal/secret"
	"github.com/helmsman/helmsman/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(db, cipher)
}

func TestChannelEncryptedRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.SaveChannel(ctx, "hook", "webhook", []byte(`{"url":"https://example.com/h","secret":"top-secret-hmac"}`)); err != nil {
		t.Fatal(err)
	}
	metas, _ := s.ListChannels()
	if len(metas) != 1 || metas[0].Kind != "webhook" {
		t.Fatalf("list channels: %+v", metas)
	}
	var raw []byte
	if err := s.db.QueryRow(`SELECT config_enc FROM alert_channels WHERE name='hook'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "top-secret-hmac") {
		t.Error("channel secret stored in plaintext")
	}
	if _, err := s.ChannelByID(metas[0].ID); err != nil {
		t.Errorf("channel did not rebuild: %v", err)
	}
}

func TestChannelSaveRejectsBadConfig(t *testing.T) {
	s := newStore(t)
	if err := s.SaveChannel(context.Background(), "x", "webhook", []byte(`{"url":"https://x","evil":1}`)); err == nil {
		t.Error("unknown-field config should be rejected")
	}
	if err := s.SaveChannel(context.Background(), "x", "nope", []byte(`{}`)); err == nil {
		t.Error("unknown kind should be rejected")
	}
}

func TestRuleCRUD(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.SaveRule(ctx, alert.Rule{Name: "cpu", Kind: alert.KindHostCPU, Threshold: 90, ForSeconds: 60, Level: alert.LevelWarning, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ListRules()
	if len(rules) != 1 || rules[0].Kind != alert.KindHostCPU {
		t.Fatalf("rules: %+v", rules)
	}
	if err := s.SaveRule(ctx, alert.Rule{Name: "bad", Kind: "nonsense"}); err == nil {
		t.Error("unknown kind rule should be rejected")
	}
	_ = s.DeleteRule(ctx, rules[0].ID)
	if rules, _ := s.ListRules(); len(rules) != 0 {
		t.Error("rule not deleted")
	}
}

func TestStatePersistAndPrune(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	states := []alert.State{
		{RuleID: 1, Target: "host", Phase: alert.PhaseFiring, Since: 100, Level: "warning"},
		{RuleID: 1, Target: "shop/web", Phase: alert.PhaseOK},
	}
	if err := s.SaveStates(ctx, states); err != nil {
		t.Fatal(err)
	}
	loaded, _ := s.LoadStates()
	if len(loaded) != 1 || loaded[0].Target != "host" {
		t.Fatalf("expected only the firing row, got %+v", loaded)
	}
	if firing, _ := s.FiringStates(); len(firing) != 1 {
		t.Errorf("firing states: %d", len(firing))
	}
}

func TestOutboxLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.EnqueueOutbox(ctx, []alert.Outbox{{RuleID: 1, Target: "host", Kind: "host_cpu", Level: "warning", Transition: "firing", Summary: "hot"}}); err != nil {
		t.Fatal(err)
	}
	pending, _ := s.PendingOutbox(10)
	if len(pending) != 1 {
		t.Fatalf("pending: %d", len(pending))
	}
	s.MarkSent(ctx, pending[0].ID, true, 3)
	if p, _ := s.PendingOutbox(10); len(p) != 0 {
		t.Error("row should be sent")
	}
}

func TestAckAndSilence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.SaveStates(ctx, []alert.State{{RuleID: 1, Target: "host", Phase: alert.PhaseFiring, Since: 1}})
	if err := s.Ack(ctx, 1, "host"); err != nil {
		t.Fatal(err)
	}
	fs, _ := s.FiringStates()
	if len(fs) != 1 || !fs[0].Acked {
		t.Errorf("ack not recorded: %+v", fs)
	}
	_ = s.Silence(ctx, 1, "host", 1<<40)
	if !s.IsSilenced(1, "host", 100) {
		t.Error("silence not recorded")
	}
}
