package ops

import "testing"

// §15 Phase-3 fuzzing of the App Ops Interface parsers — the surface that ingests a
// COMPROMISED monitored app's responses (attacker class C: "assume every app is
// eventually hostile"). Goal: zero panics / OOM / hangs on arbitrary bytes; a
// malformed body must degrade to (_, false), never crash the poller.

var opsSeeds = []string{
	"",
	"{}",
	"[]",
	"null",
	`{"status":"ok"}`,
	`{"data":{"indicators":[{"name":"db","status":"healthy"}]}}`,
	`{"queues":[{"name":"emails","pending":3,"failed":0}]}`,
	`{"version":1,"health":{"path":"/health"},"queues":{"path":"/queues"}}`,
	`{"data":{"queues":[{"name":"x","pending":"not-a-number"}]}}`,
	`{"indicators":[` + `{"name":"a","status":"ok"},` + `{"name":"b"}]}`,
	"\x00\xff\xfe garbage",
}

func FuzzParseDescriptor(f *testing.F) {
	for _, s := range opsSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = parseDescriptor(body) // must not panic on any input
	})
}

func FuzzParseHealth(f *testing.F) {
	for _, s := range opsSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		inds, ok := parseHealth(body, "json")
		if !ok && inds != nil {
			t.Errorf("parseHealth returned ok=false but non-nil indicators")
		}
	})
}

func FuzzParseQueues(f *testing.F) {
	for _, s := range opsSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = parseQueues(body) // must not panic on any input
	})
}
