package edge

// The typed subset of the Caddy v2 admin-API config Helmsman emits. The config is
// ALWAYS marshalled from these structs (never string concat / loose maps for the
// security-relevant parts) so what Caddy runs is exactly Helmsman's typed render
// (SBD-7). Only the fields Helmsman uses are modelled; everything else is omitted.

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
	Upstreams []caddyUpstream    `json:"upstreams,omitempty"`
	Transport map[string]any     `json:"transport,omitempty"`
	Headers   *caddyProxyHeaders `json:"headers,omitempty"`
	// headers handler
	Response *caddyHeaderOps `json:"response,omitempty"`
	// static_response
	StatusCode int `json:"status_code,omitempty"`
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
	Automation caddyAutomation `json:"automation"`
}

type caddyAutomation struct {
	Policies []caddyTLSPolicy `json:"policies,omitempty"`
}

type caddyTLSPolicy struct {
	Subjects []string      `json:"subjects,omitempty"`
	Issuers  []caddyIssuer `json:"issuers,omitempty"`
}

type caddyIssuer struct {
	Module string `json:"module"`
	CA     string `json:"ca,omitempty"`
	Email  string `json:"email,omitempty"`
}
