package web

import (
	"net/http"
	"testing"
)

func req(host string, hdr map[string]string) *http.Request {
	r := &http.Request{Host: host, Header: http.Header{}}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestOriginOK(t *testing.T) {
	const host = "localhost:9000"
	cases := []struct {
		name string
		hdr  map[string]string
		want bool
	}{
		// The bug: no-referrer makes a same-origin POST send Origin: null.
		{"origin null rejected", map[string]string{"Origin": "null"}, false},
		// Sec-Fetch-Site rescues it (sent regardless of referrer policy).
		{"sec-fetch same-origin accepted", map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}, true},
		{"sec-fetch same-origin, no origin", map[string]string{"Sec-Fetch-Site": "same-origin"}, true},
		// Sec-Fetch-Site is additive — a non-same-origin value falls through, never auto-rejects a good Origin.
		{"sec-fetch cross-site falls through to good origin", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "http://localhost:9000"}, true},
		{"sec-fetch cross-site, no origin", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		// Origin/Referer fallback (older browsers).
		{"loopback http origin accepted", map[string]string{"Origin": "http://localhost:9000"}, true},
		{"https origin accepted", map[string]string{"Origin": "https://localhost:9000"}, true},
		{"cross-origin rejected", map[string]string{"Origin": "https://evil.example.com"}, false},
		{"referer fallback accepted", map[string]string{"Referer": "http://localhost:9000/login"}, true},
		{"no signals rejected", map[string]string{}, false},
	}
	for _, c := range cases {
		if got := originOK(req(host, c.hdr)); got != c.want {
			t.Errorf("%s: originOK=%v, want %v", c.name, got, c.want)
		}
	}
}

// A plaintext non-loopback origin must NOT be treated as same-origin with the host
// (review #17) — only the forge-proof Sec-Fetch-Site or a loopback/https origin passes.
func TestSameOriginSchemeGuard(t *testing.T) {
	if sameOrigin("http://app.example.com", "app.example.com") {
		t.Error("plaintext non-loopback origin must be rejected")
	}
	if !sameOrigin("http://127.0.0.1:9000", "127.0.0.1:9000") {
		t.Error("loopback http origin should pass")
	}
}
