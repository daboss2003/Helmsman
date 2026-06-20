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
	maxMetricGroups   = 64
	maxMetricItems    = 64
	maxOpsStrLen      = 200 // cap any single untrusted label/value/unit string
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

// MetricItem is one labeled value within a metric group (e.g. "Hit rate" = "94.2"
// "%"). Status is optional and only used to color the row (up/down/degraded).
type MetricItem struct {
	Label  string
	Value  string
	Unit   string
	Status string // "" | up | down | degraded | unknown
}

// MetricGroup is a titled card of metric items — the open-ended "monitor" unit. The
// app names the groups it wants (Database, Cache, Routes, System, Memory, …); Helmsman
// renders each as a panel, so the set is NOT limited to a fixed schema.
type MetricGroup struct {
	Title string
	Items []MetricItem
}

// Result is the canonical ops record attached to a service (plan §4.3: one record,
// distinguished by Mode + per-indicator Source).
type Result struct {
	Mode            Mode
	Version         string
	Capabilities    []string
	Indicators      []Indicator
	Queues          []Queue
	Metrics         []MetricGroup
	Snapshot        []SnapshotPoint
	AlertingCapable bool
	Err             string
}

// IsRich reports whether this is a RICH ops record (for template use).
func (r Result) IsRich() bool { return r.Mode == RICH }

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

// metricsEnvelope is the {groups:[{title, items:[{label,value,unit,status}]}]} shape —
// open-ended cards (database/cache/routes/system/…), each a labeled table. value is
// accepted as a JSON string OR number.
type metricsEnvelope struct {
	Groups []struct {
		Title string `json:"title"`
		Items []struct {
			Label  string          `json:"label"`
			Value  json.RawMessage `json:"value"`
			Unit   string          `json:"unit"`
			Status string          `json:"status"`
		} `json:"items"`
	} `json:"groups"`
}

// parseMetrics normalizes a /metrics body into metric groups. Returns ok=false on
// malformed JSON (→ caller leaves Metrics empty, app stays RICH from health). Element
// counts and string lengths are capped — the body is untrusted.
func parseMetrics(body []byte) (gs []MetricGroup, ok bool) {
	var env metricsEnvelope
	if err := json.Unmarshal(unwrapEnvelope(body), &env); err != nil {
		return nil, false
	}
	for _, g := range env.Groups {
		if len(gs) >= maxMetricGroups {
			break
		}
		grp := MetricGroup{Title: clipOps(g.Title)}
		for _, it := range g.Items {
			if len(grp.Items) >= maxMetricItems {
				break
			}
			grp.Items = append(grp.Items, MetricItem{
				Label:  clipOps(it.Label),
				Value:  clipOps(rawScalar(it.Value)),
				Unit:   clipOps(it.Unit),
				Status: normMetricStatus(it.Status),
			})
		}
		gs = append(gs, grp)
	}
	return gs, true
}

// rawScalar renders a JSON value (string or number) as a plain string; anything else
// becomes "". (html/template escapes it at render; this only normalizes the type.)
func rawScalar(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}

func normMetricStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "up", "ok", "healthy":
		return "up"
	case "down", "error", "critical":
		return "down"
	case "degraded", "warn", "warning":
		return "degraded"
	default:
		return ""
	}
}

func clipOps(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxOpsStrLen {
		return s[:maxOpsStrLen]
	}
	return s
}
