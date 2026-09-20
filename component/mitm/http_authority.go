// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/component/plugin"
)

type httpAuthority struct {
	host string
	port uint16
}

func (a httpAuthority) String() string { return net.JoinHostPort(a.host, strconv.Itoa(int(a.port))) }

func parseAuthority(authority, scheme string) (httpAuthority, bool) {
	u, err := url.Parse(scheme + "://" + authority)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" {
		return httpAuthority{}, false
	}
	p := u.Port()
	if p == "" {
		p = "80"
		if scheme == "https" {
			p = "443"
		}
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil || port == 0 {
		return httpAuthority{}, false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	return httpAuthority{host: host, port: uint16(port)}, host != ""
}

func sameAuthority(authority, host string, port uint16, scheme string) bool {
	requested, ok := parseAuthority(authority, scheme)
	return ok && requested.matches(host, port)
}

func (a httpAuthority) matches(host string, port uint16) bool {
	if a.port != port {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return a.host == ip.Unmap().String()
	}
	return strings.EqualFold(a.host, strings.TrimSuffix(host, "."))
}

// HTTPS/H2/H3 authorities select middleware and upstream HTTP routing, not a
// new network destination. The connection's authenticated ingress stays fixed
// unless middleware explicitly rewrites the URL target.
func admitRequestAuthority(r *http.Request, scheme string, flow plugin.Flow) (plugin.Flow, string) {
	if requestScheme(r, scheme) != scheme {
		return flow, "scheme_mismatch"
	}
	authority, ok := parseAuthority(r.Host, scheme)
	if !ok {
		return flow, "invalid_authority"
	}
	if authority.matches(flow.Host, flow.Port) {
		return flow, ""
	}
	if scheme != "https" || r.ProtoMajor != 2 && r.ProtoMajor != 3 {
		return flow, "authority_mismatch"
	}
	if authority.port != flow.Port {
		return flow, "authority_port_mismatch"
	}
	flow.Host = authority.host
	return flow, ""
}

// HTTP/1 origin-form inherits the connection scheme; absolute-form and HTTP/3
// carry it in URL. Go's HTTP/2 server leaves URL.Scheme empty and sets TLS only
// for :scheme=https, even when :scheme=http arrives over a TLS connection.
func requestScheme(r *http.Request, connectionScheme string) string {
	if r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	if r.ProtoMajor == 2 {
		if r.TLS != nil {
			return "https"
		}
		return "http"
	}
	return connectionScheme
}

// Middleware belongs to each incoming authority, before any plugin rewrite.
// Keep the original chain and a bounded cache of coalesced chains. Wildcard
// scopes can admit more names; uncached chains are rebuilt rather than retained.
func (h *Host) chainsForFlow(original plugin.Flow, terminal func(plugin.Flow) plugin.Handler) func(plugin.Flow) plugin.Handler {
	const maxChains = 33 // Original authority plus 32 coalesced authorities.
	chains := map[string]plugin.Handler{original.Host: h.chain(original, terminal(original))}
	var mu sync.Mutex
	return func(flow plugin.Flow) plugin.Handler {
		mu.Lock()
		defer mu.Unlock()
		if chain := chains[flow.Host]; chain != nil {
			return chain
		}
		chain := h.chain(flow, terminal(flow))
		if len(chains) < maxChains {
			chains[flow.Host] = chain
		}
		return chain
	}
}
