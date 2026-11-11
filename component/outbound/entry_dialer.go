// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
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

// entryDialer shares what it learns about nodes through pool, if given.
func (p *PathSpec) entryDialer(option *dialer.GlobalOption, pool *PathPool) (netproxy.Dialer, error) {
	resolver, err := p.entryResolver(option)
	if err != nil {
		return nil, err
	}
	entry := direct.Option{
		Resolver: resolver, Mark: int(p.effectiveMark(option)), Interface: p.Entry.Interface,
		Mptcp: option.Mptcp, IPVersion: p.IPVersion,
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 3},
		// Linux times out a silent zero window with in-flight data at twice this
		// cap. Keep that threshold at 30s without USER_TIMEOUT's backpressure abort.
		TCPMaxRTO: 15 * time.Second,
		// Node carriers are always written first, so a deferred SYN is sent.
		TCPFastOpen: option.TCPFastOpen,
	}
	if pool != nil {
		// entryResolver's DNS transport depends on exactly these inputs.
		entry.Lookup = pool.addresses.Lookup(resolver.LookupNetIP, fmt.Sprintf("%s\x00%d\x00%s", option.DNSResolver, entry.Mark, entry.Interface))
		entry.Multipath = &pool.multipath
	}
	return direct.NewDirectDialer(entry), nil
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
