package edge

// The typed subset of the Caddy v2 admin-API config Mooring emits. The config is
// ALWAYS marshalled from these structs (never string concat / loose maps for the
// security-relevant parts) so what Caddy runs is exactly Mooring's typed render
// (SBD-7). Only the fields Mooring uses are modelled; everything else is omitted.

type caddyConfig struct {
	Admin *caddyAdmin `json:"admin"`
	Apps  caddyApps   `json:"apps"`
}

type caddyAdmin struct {
	Listen        string   `json:"listen"`
	EnforceOrigin bool     `json:"enforce_origin"`
	Origins       []string `json:"origins,omitempty"`
}

type caddyApps struct {
	HTTP caddyHTTP `json:"http"`
	TLS  *caddyTLS `json:"tls,omitempty"`
}

type caddyHTTP struct {
	Servers map[string]caddyServer `json:"servers"`
}

type caddyServer struct {
	Listen []string     `json:"listen"`
	Routes []caddyRoute `json:"routes"`
}

type caddyRoute struct {
	Match    []caddyMatch   `json:"match,omitempty"`
	Handle   []caddyHandler `json:"handle"`
	Terminal bool           `json:"terminal,omitempty"`
}

type caddyMatch struct {
	Host     []string       `json:"host,omitempty"`
	Path     []string       `json:"path,omitempty"`
	RemoteIP *caddyRemoteIP `json:"remote_ip,omitempty"`
}

type caddyRemoteIP struct {
	Ranges []string `json:"ranges"`
}

type caddyHandler struct {
	Handler string `json:"handler"`
	// reverse_proxy
	Upstreams     []caddyUpstream     `json:"upstreams,omitempty"`
	Transport     map[string]any      `json:"transport,omitempty"`
	Headers       *caddyProxyHeaders  `json:"headers,omitempty"`
	LoadBalancing *caddyLoadBalancing `json:"load_balancing,omitempty"`
	HealthChecks  *caddyHealthChecks  `json:"health_checks,omitempty"`
	// headers handler
	Response *caddyHeaderOps `json:"response,omitempty"`
	// static_response
	StatusCode int `json:"status_code,omitempty"`
}

// caddyLoadBalancing selects across a replica pool (least_conn for M14 edge pools).
type caddyLoadBalancing struct {
	SelectionPolicy map[string]any `json:"selection_policy,omitempty"`
}

// caddyHealthChecks holds the passive health policy applied to a pool — a replica
// that fails repeatedly is taken out until it recovers.
type caddyHealthChecks struct {
	Passive *caddyPassiveHealth `json:"passive,omitempty"`
}

type caddyPassiveHealth struct {
	FailDuration string `json:"fail_duration,omitempty"`
	MaxFails     int    `json:"max_fails,omitempty"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

type caddyProxyHeaders struct {
	Request  *caddyHeaderOps `json:"request,omitempty"`
	Response *caddyHeaderOps `json:"response,omitempty"`
}

type caddyHeaderOps struct {
	Set map[string][]string `json:"set,omitempty"`
}

type caddyTLS struct {
	// Certificates.automate is what makes Caddy PROACTIVELY obtain a cert for a name.
	// automation.policies only scopes the issuer; a cert-only subject (one no server
	// route references) is never obtained unless it's listed here (on-demand is off).
	Certificates *caddyCertificates `json:"certificates,omitempty"`
	Automation   caddyAutomation    `json:"automation"`
}

type caddyCertificates struct {
	Automate []string `json:"automate,omitempty"`
}

type caddyAutomation struct {
	Policies []caddyTLSPolicy `json:"policies,omitempty"`
}

type caddyTLSPolicy struct {
	Subjects []string      `json:"subjects,omitempty"`
	Issuers  []caddyIssuer `json:"issuers,omitempty"`
}

type caddyIssuer struct {
	Module       string   `json:"module"`
	CA           string   `json:"ca,omitempty"`
	Email        string   `json:"email,omitempty"`
	TrustedRoots []string `json:"trusted_roots_pem_files,omitempty"` // for a private CA's own https
}
