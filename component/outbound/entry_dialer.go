// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func (p *PathSpec) effectiveMark(option *dialer.GlobalOption) uint32 {
	if p.Entry.Mark != nil {
		return *p.Entry.Mark
	}
	return option.SoMarkFromDae
}

func (p *PathSpec) entryResolver(option *dialer.GlobalOption) (*net.Resolver, error) {
	socket := direct.Option{Mark: int(p.effectiveMark(option)), Interface: p.Entry.Interface}
	dns := direct.NewDirectDialer(socket)
	localDNS := direct.NewDirectDialer(direct.Option{Mark: socket.Mark})
	return netutils.NewBootstrapResolver(option.DNSResolver, func(ctx context.Context, network, address string) (net.Conn, error) {
		// Local DNS stubs must be reached over loopback, not the proxy's WAN.
		// Select using the final DNS server (system or override), retaining the
		// entry mark. External DNS never falls back to an unbound connection.
		// net.Resolver.Dial guarantees a literal IP and numeric port.
		server, _ := netip.ParseAddrPort(address)
		if server.Addr().IsLoopback() {
			return localDNS.DialContext(ctx, network, address)
		}
		return dns.DialContext(ctx, network, address)
	})
}

func (p *PathSpec) entryDialer(option *dialer.GlobalOption) (netproxy.Dialer, error) {
	resolver, err := p.entryResolver(option)
	if err != nil {
		return nil, err
	}
	return direct.NewDirectDialer(direct.Option{
		Resolver: resolver, Mark: int(p.effectiveMark(option)), Interface: p.Entry.Interface,
		Mptcp: option.Mptcp, IPVersion: p.IPVersion,
	}), nil
}

func (p *PathSpec) entryLabel() string {
	var labels []string
	if p.showIPVersion {
		labels = append(labels, fmt.Sprintf("IPv%d", p.IPVersion))
	}
	if p.Entry.Mark != nil {
		labels = append(labels, fmt.Sprintf("mark=%#x", *p.Entry.Mark))
	}
	if p.Entry.Interface != "" {
		labels = append(labels, "interface="+p.Entry.Interface)
	}
	if len(labels) == 0 {
		return ""
	}
	return " [" + strings.Join(labels, ", ") + "]"
}
