// Package opsclient is the SSRF-safe outbound HTTP client for the App Ops
// Interface (plan §4.1, §15 §6.3). It is the load-bearing control for attacker
// class C (a compromised monitored app answering Mooring's polls).
//
// Invariants enforced here:
//   - The destination host is PINNED to the operator-configured base URL. A
//     compromised app's descriptor can only supply a RELATIVE path; it can never
//     move the outbound host (the "descriptor cannot move the outbound host"
//     abuse test).
//   - DNS-rebind-safe: the dialer re-resolves on EVERY connection (keep-alives
//     disabled) and dials the validated IP directly, refusing loopback /
//     link-local / metadata (169.254.169.254) / multicast / unspecified — which
//     covers cloud metadata and every loopback-bound control-plane service
//     (admin UI, socket-proxy, Caddy admin). Private container ranges are
//     allowed (that is where apps live); the systemd egress firewall (§15) is
//     the physical backstop.
//   - No redirect-follow; http/https scheme only; responses size-capped.
//   - The shared secret travels only in an operator-named header, server-side,
//     never to the browser, never logged (secret.Redacted).
package opsclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"time"

	"github.com/daboss2003/mooring/internal/secret"
)

// relPathRe is the §4.1 relative-path grammar: a single leading slash then a
// bounded safe charset. No scheme, host, query, or `//` authority can appear.
var relPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,128}$`)

// headerNameRe bounds the operator-chosen secret header name to token chars.
var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// ValidateRelPath reports whether p is a safe relative ops path (plan §4.1). It
// also rejects `//` (protocol-relative authority) and any `..` traversal segment.
func ValidateRelPath(p string) bool {
	if !relPathRe.MatchString(p) {
		return false
	}
	if len(p) >= 2 && p[1] == '/' { // "//..." protocol-relative
		return false
	}
	// reject any ".." path segment
	for _, seg := range splitSegments(p) {
		if seg == ".." {
			return false
		}
	}
	return true
}

func splitSegments(p string) []string {
	var segs []string
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			if i > start {
				segs = append(segs, p[start:i])
			}
			start = i + 1
		}
	}
	return segs
}

var (
	// ErrBlockedTarget means the pinned host resolved to a forbidden address.
	ErrBlockedTarget = errors.New("opsclient: target resolves to a blocked address")
	// ErrBadRelPath means the relative path failed the §4.1 grammar.
	ErrBadRelPath = errors.New("opsclient: invalid relative path")
	// ErrBadBase means the operator-configured base URL is not a usable origin.
	ErrBadBase = errors.New("opsclient: base URL must be http(s)://host[:port]")
	// ErrBadHeader means the secret header name is not a valid token.
	ErrBadHeader = errors.New("opsclient: invalid secret header name")
)

const (
	defaultMaxBytes = 1 << 20 // 1 MiB cap on untrusted app responses
	defaultTimeout  = 10 * time.Second
)

// Client performs pinned, rebind-safe requests.
type Client struct {
	hc       *http.Client
	maxBytes int64
}

// New returns a production Client (blocks loopback/link-local/metadata).
func New() *Client { return newClient(defaultLookup, prodBlocked, defaultTimeout) }

func newClient(lookup lookupFunc, blocked blockFunc, timeout time.Duration) *Client {
	d := &guardedDialer{
		lookup:  lookup,
		blocked: blocked,
		base:    &net.Dialer{Timeout: 5 * time.Second},
	}
	return &Client{
		hc: &http.Client{
			Timeout: timeout,
			// Never follow a redirect off the pinned host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				DialContext:           d.DialContext,
				DisableKeepAlives:     true, // re-resolve every request (rebind-safe)
				MaxIdleConns:          0,
				ResponseHeaderTimeout: 8 * time.Second,
				TLSHandshakeTimeout:   5 * time.Second,
			},
		},
		maxBytes: defaultMaxBytes,
	}
}

// Response is a size-capped ops response.
type Response struct {
	Status int
	Body   []byte
}

// Get fetches base+relPath with the secret header.
func (c *Client) Get(ctx context.Context, base, relPath, secretHeader string, sec secret.Redacted) (*Response, error) {
	return c.do(ctx, http.MethodGet, base, relPath, secretHeader, sec, nil)
}

// Post sends a body to base+relPath with the secret header.
func (c *Client) Post(ctx context.Context, base, relPath, secretHeader string, sec secret.Redacted, body []byte) (*Response, error) {
	return c.do(ctx, http.MethodPost, base, relPath, secretHeader, sec, body)
}

func (c *Client) do(ctx context.Context, method, base, relPath, secretHeader string, sec secret.Redacted, body []byte) (*Response, error) {
	u, err := pinnedURL(base, relPath)
	if err != nil {
		return nil, err
	}
	if secretHeader != "" && !headerNameRe.MatchString(secretHeader) {
		return nil, ErrBadHeader
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if secretHeader != "" && !sec.IsZero() {
		req.Header.Set(secretHeader, sec.Reveal())
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, classifyErr(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes))
	if err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Body: data}, nil
}

// pinnedURL builds a URL whose scheme+host come ONLY from base; relPath sets the
// path. The host can therefore never be moved by descriptor-supplied input.
func pinnedURL(base, relPath string) (*url.URL, error) {
	if !ValidateRelPath(relPath) {
		return nil, ErrBadRelPath
	}
	b, err := url.Parse(base)
	if err != nil {
		return nil, ErrBadBase
	}
	if (b.Scheme != "http" && b.Scheme != "https") || b.Host == "" {
		return nil, ErrBadBase
	}
	return &url.URL{Scheme: b.Scheme, Host: b.Host, Path: relPath}, nil
}

// classifyErr collapses dial/transport errors so a blocked target is reported
// clearly without leaking internal detail.
func classifyErr(err error) error {
	if errors.Is(err, ErrBlockedTarget) {
		return ErrBlockedTarget
	}
	return err
}

// --- guarded dialer ---

type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)
type blockFunc func(netip.Addr) bool

type guardedDialer struct {
	lookup  lookupFunc
	blocked blockFunc
	base    *net.Dialer
}

// DialContext re-resolves the host on every connection, refuses if ANY resolved
// address is blocked (conservative anti-rebind), and dials the validated IP
// directly so there is no resolve→dial TOCTOU.
func (d *guardedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// A literal IP in the host position is checked directly.
	if ip, perr := netip.ParseAddr(host); perr == nil {
		if d.blocked(ip.Unmap()) {
			return nil, ErrBlockedTarget
		}
		return d.base.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	ips, err := d.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("opsclient: no addresses for %q", host)
	}
	for _, ip := range ips {
		if d.blocked(ip.Unmap()) {
			return nil, ErrBlockedTarget
		}
	}
	return d.base.DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
}

func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// nat64WellKnown is the RFC 6052 NAT64 prefix. An address like 64:ff9b::a9fe:a9fe
// is the NAT64 encoding of 169.254.169.254 (cloud metadata) — netip treats it as
// an ordinary global IPv6 address, so we must unwrap the embedded IPv4 and re-check
// it (review #2), else an IPv6/NAT64 path to metadata slips past.
var nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")

// prodBlocked refuses loopback, link-local (incl. 169.254.169.254 metadata),
// multicast, and unspecified addresses — including IPv4 embedded via NAT64.
// Private/ULA container ranges are allowed (apps live there); the systemd egress
// firewall is the physical backstop (§15).
func prodBlocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && nat64WellKnown.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// IsBlockedAddr reports whether an address is one the SSRF-safe client refuses to
// dial. Exported so config-time validation can reuse the exact same predicate as
// the request-time dialer (no drift; review #3).
func IsBlockedAddr(ip netip.Addr) bool { return prodBlocked(ip) }

// ValidHeaderName reports whether s is a valid secret-header name (review #8).
func ValidHeaderName(s string) bool { return headerNameRe.MatchString(s) }
