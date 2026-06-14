package ops

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// health.json is a second built-in adapter that proves the §4.4 registry seam is
// real: a non-Terminus app that merely exposes a plain JSON health endpoint
// (e.g. {"status":"ok"} at /healthz) can still light up a RICH single-indicator
// tile. Select it per app with `adapter: health.json`. Like ops.v1, the app
// response is untrusted: size-capped by the Doer, schema-checked, never eval'd,
// degrade-to-BASIC on any mismatch.
func init() { Register(jsonHealth{}) }

type jsonHealth struct{}

func (jsonHealth) Name() string { return "health.json" }

// healthPath is the conventional endpoint; the operator base path is prepended.
const healthPath = "/healthz"

func (a jsonHealth) Discover(ctx context.Context, c Doer, t Target) Discovery {
	path := joinPath(cleanBasePath(t.BasePath), healthPath)
	resp, err := c.Get(ctx, t.BaseURL, path, t.SecretHeader, t.Secret)
	if err != nil || (resp.Status != http.StatusOK && resp.Status != http.StatusServiceUnavailable) {
		return Discovery{Mode: BASIC}
	}
	if _, ok := parseJSONHealth(resp.Body); !ok {
		return Discovery{Mode: BASIC}
	}
	return Discovery{Mode: RICH, Version: "json-health", Capabilities: []string{"health"}, BasePath: cleanBasePath(t.BasePath)}
}

func (a jsonHealth) Probe(ctx context.Context, c Doer, t Target, d Discovery) Result {
	res := Result{Mode: RICH, Version: d.Version, Capabilities: d.Capabilities}
	base := d.BasePath
	if base == "" {
		base = cleanBasePath(t.BasePath)
	}
	resp, err := c.Get(ctx, t.BaseURL, joinPath(base, healthPath), t.SecretHeader, t.Secret)
	if err != nil || (resp.Status != http.StatusOK && resp.Status != http.StatusServiceUnavailable) {
		res.Mode = BASIC
		res.Err = "json health probe failed"
		return res
	}
	jh, ok := parseJSONHealth(resp.Body)
	if !ok {
		res.Mode = BASIC
		res.Err = "json health response did not parse"
		return res
	}
	// Status: a recognized body value wins; otherwise derive from the HTTP code.
	status := "unknown"
	switch strings.ToLower(strings.TrimSpace(jh.Status)) {
	case "ok", "up", "healthy", "pass":
		status = "up"
	case "down", "fail", "unhealthy", "error":
		status = "down"
	case "degraded", "warn", "warning":
		status = "degraded"
	default:
		if resp.Status == http.StatusOK {
			status = "up"
		} else {
			status = "down"
		}
	}
	res.Indicators = []Indicator{{Name: "service", Status: status, Message: jh.Message, Source: a.Name()}}
	return res
}

// jsonHealthBody is the tiny accepted shape; unknown fields are ignored.
type jsonHealthBody struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// parseJSONHealth decodes a plain health body, tolerating a {data:…} envelope.
// ok=false when the body is not a JSON object (→ degrade to BASIC). An object
// with no status field is still ok (we then derive status from the HTTP code).
func parseJSONHealth(body []byte) (jsonHealthBody, bool) {
	var h jsonHealthBody
	if err := json.Unmarshal(unwrapEnvelope(body), &h); err != nil {
		return jsonHealthBody{}, false
	}
	return h, true
}
