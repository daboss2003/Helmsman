package hostmon

import "testing"

func TestParseProcStat(t *testing.T) {
	// user=100 nice=0 system=50 idle=800 iowait=50 irq=0 softirq=0 steal=0
	data := "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 ...\nintr 123\n"
	busy, total, err := parseProcStat(data)
	if err != nil {
		t.Fatal(err)
	}
	// total = 100+0+50+800+50 = 1000; idle = idle+iowait = 850; busy = 150
	if total != 1000 || busy != 150 {
		t.Errorf("busy=%d total=%d, want 150/1000", busy, total)
	}
}

func TestParseMemInfo(t *testing.T) {
	data := "MemTotal:       2048 kB\nMemFree:  100 kB\nMemAvailable:    512 kB\nBuffers: 1 kB\n"
	total, used, err := parseMemInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2048*1024 {
		t.Errorf("total=%d, want %d", total, 2048*1024)
	}
	// used = total - available = (2048-512)*1024
	if used != (2048-512)*1024 {
		t.Errorf("used=%d, want %d", used, (2048-512)*1024)
	}
}

func TestParseMemInfoMissingFieldsFails(t *testing.T) {
	if _, _, err := parseMemInfo("MemTotal: 100 kB\n"); err == nil {
		t.Error("expected error when MemAvailable missing")
	}
}

func TestParseLoadAvg(t *testing.T) {
	l, err := parseLoadAvg("0.42 0.31 0.10 1/234 5678")
	if err != nil || l != 0.42 {
		t.Errorf("load=%v err=%v, want 0.42", l, err)
	}
}

func TestCPUPercent(t *testing.T) {
	// first sample (no prev) → 0
	if got := cpuPercent(false, 0, 0, 100, 200); got != 0 {
		t.Errorf("first sample = %v, want 0", got)
	}
	// normal: busy +50, total +100 → 50%
	if got := cpuPercent(true, 100, 1000, 150, 1100); got != 50 {
		t.Errorf("normal = %v, want 50", got)
	}
	// review #2/#6: busy DECREASES while total increases — must NOT underflow.
	if got := cpuPercent(true, 500, 1000, 480, 1100); got != 0 {
		t.Errorf("busy regression = %v, want 0 (no uint64 underflow)", got)
	}
	// dt <= 0 → 0
	if got := cpuPercent(true, 100, 1000, 150, 1000); got != 0 {
		t.Errorf("zero total delta = %v, want 0", got)
	}
	// clamp to 100 if busy delta somehow exceeds total delta
	if got := cpuPercent(true, 0, 0, 200, 100); got != 100 {
		t.Errorf("over-100 = %v, want clamp 100", got)
	}
}

func TestSamplerCPUDelta(t *testing.T) {
	// On a platform without /proc this returns ErrUnsupported, which is fine —
	// the delta math itself is covered by parseProcStat. Just ensure New works.
	s := New("/")
	if s == nil {
		t.Fatal("New returned nil")
	}
}
