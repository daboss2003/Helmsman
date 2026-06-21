package l4

import (
	"strings"
	"testing"
)

func TestRenderTCPandUDP(t *testing.T) {
	out, err := Render([]Route{
		{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353, LB: "hash_client_ip",
			Pool: []string{"10.0.0.7:5353"}},
		{Listen: 853, Protocol: "tcp", Service: "coredns", Port: 8853, LB: "least_conn",
			Pool: []string{"10.0.0.5:8853", "10.0.0.6:8853"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// UDP listener + udp directive; the upstream is the discovered replica bridge IP.
	for _, want := range []string{
		// loads the dynamic stream module on Debian/Ubuntu (else "unknown directive stream")
		"include /etc/nginx/modules-enabled/*.conf;",
		// runtime paths stay inside the writable prefix (non-root, sandboxed)
		"pid nginx.pid;",
		"error_log stderr;",
		"stream {",
		"upstream l4_53_udp {",
		"hash $remote_addr consistent;",
		"server 10.0.0.7:5353;",
		"listen 53 udp;",
		"proxy_pass l4_53_udp;",
		// TCP listener + explicit pool + least_conn.
		"upstream l4_853_tcp {",
		"least_conn;",
		"server 10.0.0.5:8853;",
		"server 10.0.0.6:8853;",
		"listen 853;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "listen 853 udp") {
		t.Errorf("tcp route must not get a udp listener:\n%s", out)
	}
}

// A route with no discovered pool must be SKIPPED — never emitted as the unresolvable
// service name (the host nginx can't resolve it, and one bad upstream makes nginx -t
// reject the WHOLE config). The pooled route still renders; an all-empty set is a valid
// empty stream{} (so the other listeners bind instead of every listener going down).
func TestRenderSkipsEmptyPool(t *testing.T) {
	out, err := Render([]Route{
		{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353}, // no Pool → skipped
		{Listen: 853, Protocol: "tcp", Service: "coredns", Port: 8853, Pool: []string{"10.0.0.5:8853"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"l4_53_udp", "listen 53", "coredns:5353"} {
		if strings.Contains(out, absent) {
			t.Errorf("empty-pool route must be skipped (no listener, no name fallback): found %q\n%s", absent, out)
		}
	}
	if !strings.Contains(out, "server 10.0.0.5:8853;") {
		t.Errorf("the pooled route must still render:\n%s", out)
	}

	empty, err := Render([]Route{{Listen: 53, Protocol: "udp", Service: "x", Port: 5353}})
	if err != nil {
		t.Fatalf("an all-empty-pool render must succeed (valid empty stream): %v", err)
	}
	if strings.Contains(empty, "upstream ") || strings.Contains(empty, "server ") {
		t.Errorf("all-empty-pool render must emit no upstream/server:\n%s", empty)
	}
}

func TestRenderRejectsDuplicateListener(t *testing.T) {
	_, err := Render([]Route{
		{Listen: 53, Protocol: "udp", Service: "a", Port: 5353},
		{Listen: 53, Protocol: "udp", Service: "b", Port: 5353},
	})
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("duplicate listen+proto must be rejected, got %v", err)
	}
	// Same port, different protocol is fine (DNS commonly uses both).
	if _, err := Render([]Route{
		{Listen: 53, Protocol: "udp", Service: "a", Port: 5353},
		{Listen: 53, Protocol: "tcp", Service: "a", Port: 5353},
	}); err != nil {
		t.Fatalf("same port different protocol should be allowed: %v", err)
	}
}

func TestValidateRouteRejects(t *testing.T) {
	cases := map[string]Route{
		"bad protocol":     {Listen: 53, Protocol: "sctp", Service: "a", Port: 5353},
		"edge port 443":    {Listen: 443, Protocol: "tcp", Service: "a", Port: 5353},
		"edge port 80":     {Listen: 80, Protocol: "tcp", Service: "a", Port: 5353},
		"control listen":   {Listen: 9000, Protocol: "tcp", Service: "a", Port: 5353},
		"control upstream": {Listen: 53, Protocol: "tcp", Service: "a", Port: 2375},
		"bad lb":           {Listen: 53, Protocol: "tcp", Service: "a", Port: 5353, LB: "magic"},
		"loopback member":  {Listen: 53, Protocol: "tcp", Service: "a", Port: 5353, Pool: []string{"127.0.0.1:5353"}},
		"member no port":   {Listen: 53, Protocol: "tcp", Service: "a", Port: 5353, Pool: []string{"host"}},
	}
	for name, r := range cases {
		if err := ValidateRoute(r); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
}

// Injection safety: a service name or pool member carrying nginx-config metacharacters
// (newline, space, brace, semicolon) must be rejected, never emitted into the config.
func TestRenderRejectsInjection(t *testing.T) {
	bad := []Route{
		{Listen: 53, Protocol: "tcp", Service: "a;\nlisten 9000", Port: 5353},
		{Listen: 53, Protocol: "tcp", Service: "ok", Port: 5353, Pool: []string{"evil:1;}\nserver 127.0.0.1:9000"}},
		{Listen: 53, Protocol: "tcp", Service: "has space", Port: 5353},
	}
	for i, r := range bad {
		if _, err := Render([]Route{r}); err == nil {
			t.Errorf("case %d: injection route must be rejected", i)
		}
	}
}
