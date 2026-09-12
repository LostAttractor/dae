// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/daeuniverse/dae/common"
	outbound "github.com/daeuniverse/outbound/common"
)

// ResolverDialContext routes one DNS transport to a literal server address.
// The caller owns the returned connection; UDP Read/Write preserve datagrams.
type ResolverDialContext func(context.Context, string, netip.AddrPort) (net.Conn, error)

type resolverPolicy struct {
	server netip.AddrPort
	route  ResolverDialContext
}

// InternalResolver delegates DNS protocol, hosts lookup and UDP/TCP retry to
// net.Resolver. Its immutable policy snapshots can change across reload while
// net.DefaultResolver and the independent bootstrap resolver stay stable.
type InternalResolver struct {
	Resolver  *net.Resolver
	Bootstrap *net.Resolver
	direct    func(context.Context, string, string) (net.Conn, error)
	policy    atomic.Pointer[resolverPolicy]
}

// ParseDNSServer accepts an IP or IP:port. An omitted port is 53; an empty value
// selects the standard library's system DNS configuration.
func ParseDNSServer(value string) (netip.AddrPort, error) {
	if value == "" {
		return netip.AddrPort{}, nil
	}
	server, err := netip.ParseAddrPort(value)
	if err != nil {
		ip, ipErr := netip.ParseAddr(value)
		if ipErr != nil {
			return netip.AddrPort{}, fmt.Errorf("dns_resolver must be an IP or IP:port: %q", value)
		}
		server = netip.AddrPortFrom(ip, 53)
	}
	if server.Port() == 0 || server.Addr().Unmap().IsUnspecified() || server.Addr().Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("dns_resolver requires a nonzero port and a concrete, unzoned IP: %q", value)
	}
	return netip.AddrPortFrom(server.Addr().Unmap(), server.Port()), nil
}

func newInternalResolver(server netip.AddrPort, direct func(context.Context, string, string) (net.Conn, error)) *InternalResolver {
	r := &InternalResolver{direct: direct}
	r.Configure(server, nil)
	r.Resolver = &net.Resolver{PreferGo: true, Dial: r.dial}
	r.Bootstrap = &net.Resolver{PreferGo: true, Dial: r.dialBootstrap}
	return r
}

// InstallDefaultResolver is called once during single-threaded process startup,
// before libraries can read the process-global resolver pointers. Runtime
// changes use Configure/SetRoute, never replace these pointers.
func InstallDefaultResolver(mark uint32, server string) (*InternalResolver, error) {
	mark = common.EffectiveSoMarkFromDae(mark)
	if err := common.ValidateSoMarkFromDae(mark); err != nil {
		return nil, err
	}
	address, err := ParseDNSServer(server)
	if err != nil {
		return nil, err
	}
	dialer, err := newMarkedDialer(mark)
	if err != nil {
		return nil, err
	}
	r := newInternalResolver(address, dialer.DialContext)
	net.DefaultResolver = r.Resolver
	outbound.BootstrapResolver = r.Bootstrap
	return r, nil
}

// Configure is called by the daemon's startup/reload owner. A nil route selects
// direct bootstrap until the replacement control plane is ready.
func (r *InternalResolver) Configure(server netip.AddrPort, route ResolverDialContext) {
	r.policy.Store(&resolverPolicy{server, route})
}

func (r *InternalResolver) SetRoute(route ResolverDialContext) {
	r.Configure(r.policy.Load().server, route)
}

func (r *InternalResolver) dialBootstrap(ctx context.Context, network, address string) (net.Conn, error) {
	if server := r.policy.Load().server; server.IsValid() {
		address = server.String()
	}
	return r.direct(ctx, network, address)
}

func (r *InternalResolver) dial(ctx context.Context, network, address string) (net.Conn, error) {
	p := r.policy.Load()
	if !p.server.IsValid() {
		return r.direct(ctx, network, address)
	}
	if p.route == nil {
		return r.direct(ctx, network, p.server.String())
	}
	conn, err := p.route(ctx, network, p.server)
	if err != nil {
		return nil, err
	}
	if network == "udp" {
		// Go distinguishes datagrams from framed streams via net.PacketConn.
		// Outbound/accounting wrappers expose only net.Conn, so restore that
		// capability for this known connected UDP transport.
		return &resolverPacketConn{conn}, nil
	}
	return conn, nil
}

type resolverPacketConn struct{ net.Conn }

func (c *resolverPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c *resolverPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
