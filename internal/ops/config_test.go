package ops

import "testing"

// A base_url must never target a control-plane port (SBD-4) — it's now an actual probe
// dial once the service name resolves to a container IP. Ordinary app ports are fine.
func TestValidateBaseURLControlPorts(t *testing.T) {
	for _, bad := range []string{"http://api:9000", "http://api:2019", "http://api:2375"} {
		if err := ValidateBaseURL(bad); err == nil {
			t.Errorf("%q (control-plane port) must be rejected", bad)
		}
	}
	for _, ok := range []string{"http://api:3000", "http://resolver:8081", "https://api"} {
		if err := ValidateBaseURL(ok); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
}
