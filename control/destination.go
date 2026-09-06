// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

// Rewritten destinations must reach userspace even when routed direct. The
// capture action is skipped when reconstructing the original route.
func (p *preparedRules) enableDestinationRewrites(rules routing.DestinationRewrites) {
	var ips []netip.Addr
	for _, rule := range rules {
		ips = append(ips, rule.From)
	}
	if len(ips) == 0 {
		return
	}
	if p.capture == nil {
		p.capture = &routingCapture{}
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	p.capture.ips = slices.Compact(ips)
}

// Preserve the original kernel route when an IP rewrite or MITM hostname
// brought an otherwise direct connection into userspace.
func (c *ControlPlane) capturedRoutingBitmaps(ip netip.Addr, proto consts.L4ProtoType) (bump, routing []uint32, err error) {
	if c.destinationRewrites.Lookup(ip) != nil {
		if c.core != nil && c.core.domainRegistry != nil {
			bump, routing = c.core.domainRegistry.kernelRoutingBitmaps(ip)
		}
		// Literal IPs need no DNS registration. Non-nil empty bitmaps select
		// kernel simulation with no domain matches.
		if routing == nil {
			bump, routing = []uint32{}, []uint32{}
		}
		return bump, routing, nil
	}
	if c.surge == nil || proto != consts.L4ProtoType_TCP || c.core == nil || c.core.domainRegistry == nil || c.routingMatcher == nil {
		return nil, nil, nil
	}
	captureIndex := c.routingMatcher.captureIndex
	if captureIndex < 0 {
		return nil, nil, nil
	}
	bump, routing = c.core.domainRegistry.kernelRoutingBitmaps(ip)
	if len(bump) <= captureIndex/32 {
		return nil, nil, fmt.Errorf("surge: cannot preserve original routing for %s without a current DNS registration", ip)
	}
	if bump[captureIndex/32]&(uint32(1)<<uint(captureIndex%32)) == 0 {
		return nil, nil, nil
	}
	return bump, routing, nil
}

func (c *ControlPlane) dialTarget(outbound consts.OutboundIndex, dst netip.AddrPort, domain string, override bool) string {
	if outbound != consts.OutboundBlock {
		if target, ok := c.destinationRewrites.Rewrite(dst, outbound != consts.OutboundDirect); ok {
			return target.String()
		}
	}
	if !override {
		return dst.String()
	}
	if _, _, err := net.SplitHostPort(domain); err == nil {
		return domain
	}
	return net.JoinHostPort(strings.Trim(domain, "[]"), strconv.Itoa(int(dst.Port())))
}

// Each rewritten UDP association owns a socket and a fixed destination. This
// keeps replies unambiguous even if multiple original IPs map to the same peer.
type destinationPacketConn struct {
	net.PacketConn
	original, target netip.AddrPort
}

func (c *destinationPacketConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(data, net.UDPAddrFromAddrPort(c.target))
}

func (c *destinationPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(data)
		if err != nil {
			return n, from, err
		}
		if common.ConvergeAddrPort(addrPortOf(from)) == c.target {
			return n, net.UDPAddrFromAddrPort(c.original), nil
		}
	}
}
