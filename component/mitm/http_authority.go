// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"container/list"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/quic-go/http3"
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

// HTTP/3 preserves :scheme in the request context; HTTP/2 uses URL.Scheme,
// as does HTTP/1 absolute-form.
// HTTP/1 origin-form inherits the intercepted connection's scheme.
func requestScheme(r *http.Request, connectionScheme string) string {
	if scheme, ok := r.Context().Value(http3.RequestSchemeContextKey).(string); ok && scheme != "" {
		return scheme
	}
	if r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	return connectionScheme
}

// Middleware belongs to each incoming authority, before any plugin rewrite.
// Retain the original chain and the 32 most recently used coalesced chains.
func (h *Host) chainsForFlow(original plugin.Flow, terminal func(plugin.Flow) plugin.Handler) func(plugin.Flow) plugin.Handler {
	originalChain := h.chain(original, terminal(original))
	type cachedChain struct {
		host string
		get  func() plugin.Handler
	}
	chains := make(map[string]*list.Element)
	var recent list.List
	var mu sync.Mutex
	return func(flow plugin.Flow) plugin.Handler {
		if flow.Host == original.Host {
			return originalChain
		}
		mu.Lock()
		element := chains[flow.Host]
		if element == nil {
			chain := cachedChain{host: flow.Host, get: sync.OnceValue(func() plugin.Handler {
				return h.chain(flow, terminal(flow))
			})}
			element = recent.PushFront(chain)
			chains[flow.Host] = element
			if recent.Len() > 32 {
				oldest := recent.Back()
				delete(chains, oldest.Value.(cachedChain).host)
				recent.Remove(oldest)
			}
		} else {
			recent.MoveToFront(element)
		}
		get := element.Value.(cachedChain).get
		mu.Unlock()
		// Chain construction for one authority must not block unrelated streams.
		return get()
	}
}
