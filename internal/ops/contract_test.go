package ops

import "testing"

func TestMajorMatches(t *testing.T) {
	for _, v := range []string{"1.0", "1.5", "1"} {
		if !majorMatches(v) {
			t.Errorf("majorMatches(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"2.0", "0.9", "", "x"} {
		if majorMatches(v) {
			t.Errorf("majorMatches(%q) = true, want false", v)
		}
	}
}

func TestParseDescriptor(t *testing.T) {
	d, ok := parseDescriptor([]byte(`{"opsInterfaceVersion":"1.2","capabilities":["health","queues","alerting"],"basePath":"/ops","extra":"ignored"}`))
	if !ok {
		t.Fatal("valid descriptor rejected")
	}
	if d.OpsInterfaceVersion != "1.2" || d.BasePath != "/ops" || len(d.Capabilities) != 3 {
		t.Errorf("descriptor parse wrong: %+v", d)
	}
	if _, ok := parseDescriptor([]byte(`not json`)); ok {
		t.Error("garbage descriptor accepted")
	}
	if _, ok := parseDescriptor([]byte(`{}`)); ok {
		t.Error("descriptor without version accepted")
	}
}

func TestUnwrapEnvelope(t *testing.T) {
	// {status,data,meta} envelope → returns data
	got := unwrapEnvelope([]byte(`{"status":"ok","data":{"x":1},"meta":{}}`))
	if string(got) != `{"x":1}` {
		t.Errorf("envelope unwrap = %s, want {\"x\":1}", got)
	}
	// bare object → returned unchanged
	bare := []byte(`{"status":"ok","details":{}}`)
	if string(unwrapEnvelope(bare)) != string(bare) {
		t.Errorf("bare object should be unchanged")
	}
}

func TestParseHealthTerminus(t *testing.T) {
	body := []byte(`{"status":"error","info":{},"details":{"db":{"status":"up"},"cache":{"status":"down","message":"timeout"},"queue":{"status":"degraded"}}}`)
	inds, ok := parseHealth(body, "ops.v1")
	if !ok {
		t.Fatal("valid health rejected")
	}
	if len(inds) != 3 {
		t.Fatalf("want 3 indicators, got %d", len(inds))
	}
	// sorted: cache, db, queue
	if inds[0].Name != "cache" || inds[0].Status != "down" || inds[0].Message != "timeout" {
		t.Errorf("cache indicator wrong: %+v", inds[0])
	}
	if inds[1].Name != "db" || inds[1].Status != "up" {
		t.Errorf("db indicator wrong: %+v", inds[1])
	}
	if inds[2].Status != "degraded" {
		t.Errorf("queue should be degraded: %+v", inds[2])
	}
}

func TestParseHealthInEnvelope(t *testing.T) {
	body := []byte(`{"status":"ok","data":{"status":"ok","details":{"db":{"status":"up"}}},"meta":{}}`)
	inds, ok := parseHealth(body, "ops.v1")
	if !ok || len(inds) != 1 || inds[0].Name != "db" {
		t.Errorf("health-in-envelope parse failed: ok=%v inds=%+v", ok, inds)
	}
}

func TestParseHealthRejectsGarbage(t *testing.T) {
	for _, b := range []string{`not json`, `{"foo":"bar"}`, `[]`, `42`} {
		if _, ok := parseHealth([]byte(b), "ops.v1"); ok {
			t.Errorf("parseHealth(%q) accepted non-health body", b)
		}
	}
}

func TestParseQueues(t *testing.T) {
	body := []byte(`{"queues":[{"name":"emails","isPaused":true,"counts":{"waiting":5,"active":2,"failed":1}}],"results":{}}`)
	qs, ok := parseQueues(body)
	if !ok || len(qs) != 1 {
		t.Fatalf("parseQueues failed: ok=%v qs=%+v", ok, qs)
	}
	q := qs[0]
	if q.Name != "emails" || !q.IsPaused || len(q.Counts) != 3 {
		t.Errorf("queue parse wrong: %+v", q)
	}
	// counts sorted by name: active, failed, waiting
	if q.Counts[0].Name != "active" || q.Counts[0].Value != 2 {
		t.Errorf("counts wrong: %+v", q.Counts)
	}
}

// review #1: element count from a hostile app must be capped.
func TestParseHealthCapsIndicators(t *testing.T) {
	var b []byte
	b = append(b, []byte(`{"status":"ok","details":{`)...)
	for i := 0; i < 5000; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, []byte(`"dep`)...)
		b = append(b, []byte(itoa(i))...)
		b = append(b, []byte(`":{"status":"up"}`)...)
	}
	b = append(b, []byte(`}}`)...)
	inds, ok := parseHealth(b, "ops.v1")
	if !ok {
		t.Fatal("valid (large) health rejected")
	}
	if len(inds) > maxIndicators {
		t.Errorf("indicators not capped: got %d, cap %d", len(inds), maxIndicators)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestResultHealthScore(t *testing.T) {
	r := Result{Indicators: []Indicator{{Status: "up"}, {Status: "down"}, {Status: "up"}, {Status: "degraded"}}}
	if got := r.HealthScore(); got != 0.5 {
		t.Errorf("HealthScore = %v, want 0.5", got)
	}
	if (Result{}).HealthScore() != 1 {
		t.Error("empty result should score 1")
	}
}
