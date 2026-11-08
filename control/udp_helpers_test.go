// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// Test entry points into the UDP datapath, outside a pool worker.

func writePacket(ctx context.Context, conn net.PacketConn, data []byte, dst net.Addr) (n int, err error) {
	deadline, _ := ctx.Deadline()
	return writePacketUntil(ctx, deadline, nil, conn, data, dst)
}

func (c *ControlPlane) handlePkt(ctx context.Context, data []byte, src, dst netip.AddrPort, routingResult *routingResult) (err error) {
	deadline, _ := ctx.Deadline()
	return c.handlePktUntil(ctx, deadline, nil, data, src, dst, routingResult)
}

func (c *ControlPlane) handlePktUntil(ctx context.Context, deadline time.Time, slot *udpWriteSlot, data []byte, src, dst netip.AddrPort, routingResult *routingResult) error {
	if slot == nil {
		slot = new(udpWriteSlot)
	}
	packet := udpPacket{data: data, deadline: deadline}
	return c.handleUDPPacket(ctx, slot, &packet, src, dst, routingResult)
}

func (c *ControlPlane) writeUDP(ctx context.Context, ue *UdpEndpoint, src, dst netip.AddrPort, data []byte) error {
	deadline, _ := ctx.Deadline()
	return c.writeUDPUntil(ctx, deadline, nil, ue, src, dst, data)
}

func (c *ControlPlane) writeUDPUntil(ctx context.Context, deadline time.Time, slot *udpWriteSlot, ue *UdpEndpoint, src, dst netip.AddrPort, data []byte) error {
	packet := udpPacket{data: data, deadline: deadline}
	return c.writeUDPPacket(ctx, slot, ue, src, dst, &packet)
}

// executeData runs w as the pool does, with data as its owned packet.
func (w udpPacketWork) executeData(slot *udpWriteSlot, data []byte) {
	if slot == nil {
		slot = new(udpWriteSlot)
	}
	w.packet = &udpPacket{data: data, deadline: w.deadline}
	w.execute(slot, data)
}

// UdpHandler sends replies that may block.
type UdpHandler func(data []byte, from netip.AddrPort) error

func (h UdpHandler) send(data []byte, from netip.AddrPort) error { return h(data, from) }
func (UdpHandler) trySend([]byte, netip.AddrPort) error          { return errReplyWouldBlock }

type UdpEndpointOptions struct {
	PacketConn net.PacketConn
	Handler    UdpHandler
	NatTimeout time.Duration

	Dialer *dialer.Dialer
	Path   stats.Path
}
