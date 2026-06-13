// Package ops implements the App Ops Interface contract v1 (plan §4): discovery,
// the versioned descriptor, Terminus-style health normalization, queues, the
// pluggable adapter seam, and the per-app prober. All app responses are treated
// as hostile input: size-capped (by opsclient), schema-checked, and on ANY parse
// failure the app degrades to BASIC — never a crash (plan §4.3).
package ops

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Element caps on UNTRUSTED app responses (review #1): the 1 MiB byte cap alone
// does not bound element COUNT, so a hostile app could pack tens of thousands of
// tiny entries. These caps keep per-poll work bounded; excess is truncated.
const (
	maxIndicators     = 256
	maxQueues         = 256
	maxCountsPerQueue = 64
)

// Mode distinguishes a RICH (contract-implementing) app from a BASIC one.
type Mode string

const (
	RICH  Mode = "rich"
	BASIC Mode = "basic"
)

// contractMajor is the MAJOR version Helmsman speaks. Same MAJOR required;
// higher MINOR tolerated; unknown fields ignored (plan §4).
const contractMajor = 1

// Descriptor is the public GET /.well-known/ops document (plan §4.1).
type Descriptor struct {
	OpsInterfaceVersion string   `json:"opsInterfaceVersion"`
	Capabilities        []string `json:"capabilities"`
	BasePath            string   `json:"basePath"`
}

// Indicator is one normalized per-dependency health tile (plan §4.3).
type Indicator struct {
	Name    string
	Status  string // up | down | degraded | unknown
	Message string
	Source  string // adapter name, e.g. "ops.v1"
}

// QueueCount is one named counter within a queue.
type QueueCount struct {
	Name  string
	Value int64
}

// Queue is a normalized queue row (plan §4.2).
type Queue struct {
	Name     string
	IsPaused bool
	Counts   []QueueCount
}

// SnapshotPoint is one health-score ring sample for the sparkline.
type SnapshotPoint struct {
	At    int64
	Value float64 // 0..1 fraction of dependencies up
}

// Result is the canonical ops record attached to an app (plan §4.3: one record,
// distinguished by Mode + per-indicator Source).
type Result struct {
	Mode            Mode
	Version         string
	Capabilities    []string
	Indicators      []Indicator
	Queues          []Queue
	Snapshot        []SnapshotPoint
	AlertingCapable bool
	Err             string
}

// HealthScore returns the fraction of indicators that are up (1.0 if none).
func (r Result) HealthScore() float64 {
	if len(r.Indicators) == 0 {
		return 1
	}
	up := 0
	for _, ind := range r.Indicators {
		if ind.Status == "up" {
			up++
		}
	}
	return float64(up) / float64(len(r.Indicators))
}

// hasCapability reports whether the capability list contains name.
func hasCapability(caps []string, name string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, name) {
			return true
		}
	}
	return false
}

// majorMatches parses a "MAJOR.MINOR" version and checks the MAJOR equals ours.
func majorMatches(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	maj := v
	if i := strings.IndexByte(v, '.'); i >= 0 {
		maj = v[:i]
	}
	n, err := strconv.Atoi(maj)
	return err == nil && n == contractMajor
}

// parseDescriptor decodes the /.well-known/ops document. Unknown fields are
// ignored (forward-compat). Returns ok=false on malformed JSON.
func parseDescriptor(body []byte) (Descriptor, bool) {
	var d Descriptor
	if err := json.Unmarshal(body, &d); err != nil {
		return Descriptor{}, false
	}
	if d.OpsInterfaceVersion == "" {
		return Descriptor{}, false
	}
	return d, true
}

// unwrapEnvelope tolerates both a {status,data,meta} success envelope and a bare
// object (plan §4.2): if the top level has a "data" member, that raw value is
// returned; otherwise the original body is returned unchanged.
func unwrapEnvelope(body []byte) []byte {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return body // not an object; let the specific parser deal with it
	}
	if raw, ok := top["data"]; ok && len(raw) > 0 {
		// only treat as an envelope if a status/meta sibling is present
		_, hasStatus := top["status"]
		_, hasMeta := top["meta"]
		if hasStatus || hasMeta {
			return raw
		}
	}
	return body
}

// terminusHealth is the {status, info, error, details:{dep:{status,message}}}
// shape (plan §4.2).
type terminusHealth struct {
	Status  string `json:"status"`
	Details map[string]struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"details"`
}

// parseHealth normalizes a Terminus-style health/live body into indicators.
// Returns ok=false if the body is not recognizable health JSON (→ caller drops
// to BASIC).
func parseHealth(body []byte, source string) (inds []Indicator, ok bool) {
	var h terminusHealth
	if err := json.Unmarshal(unwrapEnvelope(body), &h); err != nil {
		return nil, false
	}
	if h.Status == "" && len(h.Details) == 0 {
		return nil, false
	}
	for dep, d := range h.Details {
		if len(inds) >= maxIndicators {
			break
		}
		status := "unknown"
		switch strings.ToLower(d.Status) {
		case "up":
			status = "up"
		case "down":
			status = "down"
		case "degraded", "warn", "warning":
			status = "degraded"
		}
		inds = append(inds, Indicator{Name: dep, Status: status, Message: d.Message, Source: source})
	}
	// Deterministic order for stable rendering (O(n log n); review #1).
	sort.Slice(inds, func(i, j int) bool { return inds[i].Name < inds[j].Name })
	return inds, true
}

// queuesEnvelope is the {queues:[{name,isPaused,counts:{…}}]} shape (plan §4.2).
type queuesEnvelope struct {
	Queues []struct {
		Name     string                     `json:"name"`
		IsPaused bool                       `json:"isPaused"`
		Counts   map[string]json.RawMessage `json:"counts"`
	} `json:"queues"`
}

// parseQueues normalizes a /queues body. Returns ok=false on malformed JSON.
func parseQueues(body []byte) (qs []Queue, ok bool) {
	var env queuesEnvelope
	if err := json.Unmarshal(unwrapEnvelope(body), &env); err != nil {
		return nil, false
	}
	for _, q := range env.Queues {
		if len(qs) >= maxQueues {
			break
		}
		out := Queue{Name: q.Name, IsPaused: q.IsPaused}
		for name, raw := range q.Counts {
			if len(out.Counts) >= maxCountsPerQueue {
				break
			}
			var n int64
			_ = json.Unmarshal(raw, &n) // non-numeric counts default to 0
			out.Counts = append(out.Counts, QueueCount{Name: name, Value: n})
		}
		sort.Slice(out.Counts, func(i, j int) bool { return out.Counts[i].Name < out.Counts[j].Name })
		qs = append(qs, out)
	}
	return qs, true
}
