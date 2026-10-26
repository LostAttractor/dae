// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A packet whose deadline passed in the queue is counted as expired; one its
// retired generation cancels is not.
func TestUDPExpiryIsCountedButCancellationIsNot(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	p := newUdpTaskPool(func(udpPacketWork, *udpWriteSlot, []byte) {})
	t.Cleanup(p.close)
	work := udpPacketWork{plane: &ControlPlane{ctx: ctx, udpTaskPool: p}, deadline: time.Now()}
	expired := dropExpired.Load()
	work.execute(nil, nil)
	require.EqualValues(t, 1, dropExpired.Load()-expired)
	cancel()
	work.execute(nil, nil)
	require.EqualValues(t, 1, dropExpired.Load()-expired, "a canceled packet was counted as expired")
}

// A packet whose association setup outlives its deadline is counted as
// expired once, by setup rather than by execute.
func TestUDPSetupPastDeadlineIsCountedExpired(t *testing.T) {
	core := newTestUDPCore(t)
	option := new(dialer.GlobalOption)
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: blockingPacketDialer{dialed: make(chan context.Context, 1)}}), option, &dialer.Property{Name: "slow"}, false, "slow")
	g := outbound.NewDialerGroup(option, "slow", outbound.GroupKindSingleAlwaysAlive,
		[]*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
	t.Cleanup(func() { _ = g.Close() })
	endpoints := new(UdpEndpointPool)
	t.Cleanup(endpoints.closeAll)
	tasks := newUdpTaskPool(func(udpPacketWork, *udpWriteSlot, []byte) {})
	t.Cleanup(tasks.close)
	c := &ControlPlane{ctx: t.Context(), core: core, deviceRoutes: newTestDeviceRoutes(t), udpTaskPool: tasks, udpEndpoints: endpoints,
		outbounds: []*outbound.DialerGroup{nil, nil, g}}
	work := udpPacketWork{plane: c, src: netip.MustParseAddrPort("192.0.2.2:30000"), dst: netip.MustParseAddrPort("192.0.2.3:5000"),
		routingResult: &routingResult{Outbound: 2, Mac: [6]byte{2, 0, 0, 0, 0, 10}}, deadline: time.Now().Add(200 * time.Millisecond)}
	expired, all := dropExpired.Load(), countedDrops()
	work.execute(nil, []byte("datagram"))
	require.EqualValues(t, 1, dropExpired.Load()-expired)
	require.EqualValues(t, 1, countedDrops()-all)
}

// A setup the packet resource limit refuses counts its packet as
// packet_resource_limit, once.
func TestUDPSetupBeyondPacketResourcesIsCounted(t *testing.T) {
	core := newTestUDPCore(t)
	option := new(dialer.GlobalOption)
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: blockingPacketDialer{dialed: make(chan context.Context, 1)}}), option, &dialer.Property{Name: "full"}, false, "full")
	g := outbound.NewDialerGroup(option, "full", outbound.GroupKindSingleAlwaysAlive,
		[]*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
	t.Cleanup(func() { _ = g.Close() })
	budget := netproxy.NewPacketBudget(1)
	held, err := budget.Open(t.Context(), "", func(context.Context, string) (net.PacketConn, error) { return newTestPacketConn(false), nil })
	require.NoError(t, err)
	t.Cleanup(func() { _ = held.Close() })
	endpoints := &UdpEndpointPool{resources: budget}
	t.Cleanup(endpoints.closeAll)
	tasks := newUdpTaskPool(func(udpPacketWork, *udpWriteSlot, []byte) {})
	t.Cleanup(tasks.close)
	c := &ControlPlane{ctx: t.Context(), core: core, deviceRoutes: newTestDeviceRoutes(t), udpTaskPool: tasks, udpEndpoints: endpoints,
		outbounds: []*outbound.DialerGroup{nil, nil, g}}
	work := udpPacketWork{plane: c, src: netip.MustParseAddrPort("192.0.2.2:30001"), dst: netip.MustParseAddrPort("192.0.2.3:5000"),
		routingResult: &routingResult{Outbound: 2, Mac: [6]byte{2, 0, 0, 0, 0, 10}}, deadline: time.Now().Add(time.Second)}
	limited, all := dropResourceLimit.Load(), countedDrops()
	work.execute(nil, []byte("datagram"))
	require.EqualValues(t, 1, dropResourceLimit.Load()-limited)
	require.EqualValues(t, 1, countedDrops()-all)
}

// A packet to a destination that needs a socket of its own, beyond the
// source's socket limit, is counted as packet_resource_limit.
func TestUDPDestinationSocketBeyondLimitIsCounted(t *testing.T) {
	dst := netip.MustParseAddrPort("198.51.100.1:443")
	ue := &UdpEndpoint{conn: newTestPacketConn(false), sockets: make(map[netip.AddrPort]*udpSocket),
		destinations: map[netip.AddrPort]udpDestination{dst: {netip.MustParseAddrPort("192.0.2.9:443"), time.Now()}}}
	for i := range maxUDPSocketsPerSource {
		ue.sockets[netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), uint16(i+1))] = &udpSocket{lastUsed: time.Now()}
	}
	plane := &ControlPlane{udpEndpoints: new(UdpEndpointPool)}
	limited, all := dropResourceLimit.Load(), countedDrops()
	require.NoError(t, plane.writeUDP(t.Context(), ue, netip.MustParseAddrPort("192.0.2.1:5000"), dst, []byte("packet")))
	require.EqualValues(t, 1, dropResourceLimit.Load()-limited)
	require.EqualValues(t, 1, countedDrops()-all)
}

// A source whose sniffing times out counts the datagrams it buffered as
// expired; closing a source while it sniffs counts nothing.
func TestUDPSniffingTimeoutCountsBufferedDatagrams(t *testing.T) {
	pending := func() *UdpEndpoint {
		setup := &udpSetup{sniffer: sniffing.NewPacketSniffer(nil)}
		require.True(t, setup.appendPacket(&udpPacket{data: []byte("first")}))
		require.True(t, setup.appendPacket(&udpPacket{data: []byte("second")}))
		return &UdpEndpoint{pending: setup, NatTimeout: 50 * time.Millisecond}
	}
	expired := dropExpired.Load()
	closed := new(UdpEndpointPool)
	closed.add(netip.MustParseAddrPort("192.0.2.1:5001"), pending())
	closed.closeAll()
	p := new(UdpEndpointPool)
	t.Cleanup(p.closeAll)
	p.add(netip.MustParseAddrPort("192.0.2.1:5000"), pending())
	require.Eventually(t, func() bool { _, ok := p.pool.Load(netip.MustParseAddrPort("192.0.2.1:5000")); return !ok },
		time.Second, 5*time.Millisecond, "the sniffing source did not expire")
	require.EqualValues(t, 2, dropExpired.Load()-expired)
}

// Each end of a MITM bridge counts the datagrams its full peer queue drops,
// in the direction they travel; WriteTo reports them as written.
func TestMITMBridgeDropsAreCountedByDirection(t *testing.T) {
	ingress, server := newMITMPacketPair(netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("198.51.100.1:443"), nil)
	t.Cleanup(func() { _ = ingress.Close() })
	for _, tc := range []struct {
		name           string
		writer, reader net.PacketConn
		drop, other    *netproxy.Drop
	}{
		{"upload", ingress, server, dropUploadMITM, dropDownloadMITM},
		{"download", server, ingress, dropDownloadMITM, dropUploadMITM},
	} {
		dropped, other := tc.drop.Load(), tc.other.Load()
		for range mitmPacketQueueSize + 1 {
			if _, err := tc.writer.WriteTo([]byte("packet"), tc.reader.LocalAddr()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tc.writer.(netproxy.NonBlockingWriter).TryWriteTo([]byte("packet"), tc.reader.LocalAddr()); err != netproxy.ErrPacketDropped {
			t.Fatalf("%s: TryWriteTo to a full queue = %v", tc.name, err)
		}
		if tc.drop.Load()-dropped != 2 || tc.other.Load() != other {
			t.Fatalf("%s: counted %d drops and %d in the other direction, want 2 and 0", tc.name, tc.drop.Load()-dropped, tc.other.Load()-other)
		}
	}
}

// A DNS query beyond the relay's capacity is counted; one a stopped relay
// refuses is not.
func TestDNSAdmissionDropIsCounted(t *testing.T) {
	r := newDNSRelay()
	for range cap(r.slots) {
		r.slots <- struct{}{}
	}
	plane := &ControlPlane{dnsRelay: r}
	src, dst := netip.MustParseAddrPort("192.0.2.1:5353"), netip.MustParseAddrPort("192.0.2.53:53")
	dropped := dropDNSAdmission.Load()
	plane.handleDNSUDP(nil, src, dst, routingResult{})
	require.EqualValues(t, 1, dropDNSAdmission.Load()-dropped)
	r.stop()
	plane.handleDNSUDP(nil, src, dst, routingResult{})
	require.EqualValues(t, 1, dropDNSAdmission.Load()-dropped, "a stopped relay counted a refused query")
}

// A queued packet whose endpoint is gone has no route to set up a new one.
func TestUDPPacketWithoutRouteIsCounted(t *testing.T) {
	endpoints := new(UdpEndpointPool)
	t.Cleanup(endpoints.closeAll)
	plane := &ControlPlane{udpEndpoints: endpoints}
	dropped := dropRouteMissing.Load()
	err := plane.handlePkt(t.Context(), []byte("packet"), netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("198.51.100.1:443"), nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, dropRouteMissing.Load()-dropped)
}

// A request-routed MITM source forwards only to the destination it was
// admitted for and counts the packets it drops for others.
func TestMITMRequestRoutingFiltersOtherDestinations(t *testing.T) {
	first := netip.MustParseAddrPort("198.51.100.1:443")
	ue := &UdpEndpoint{mitm: true, firstDst: first}
	dropped := dropUploadFiltered.Load()
	plane := &ControlPlane{udpEndpoints: new(UdpEndpointPool)}
	require.NoError(t, plane.writeUDP(t.Context(), ue, netip.MustParseAddrPort("192.0.2.1:5000"), netip.MustParseAddrPort("198.51.100.2:443"), []byte("packet")))
	require.EqualValues(t, 1, dropUploadFiltered.Load()-dropped)
}

// The socket's running total is counted by its increase, also across a
// wrap; a truncated datagram is counted and not delivered.
func TestIngressDropsAreCountedOnce(t *testing.T) {
	oob := func(total uint32) []byte {
		b := make([]byte, unix.CmsgSpace(4))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level, h.Type = unix.SOL_SOCKET, unix.SO_RXQ_OVFL
		h.SetLen(unix.CmsgLen(4))
		binary.NativeEndian.PutUint32(b[unix.CmsgLen(0):], total)
		return b
	}
	var reported uint32
	overflow, truncated := dropSocketOverflow.Load(), dropTruncated.Load()
	for _, total := range []uint32{0, 3, 3} {
		require.False(t, countIngressDrops(oob(total), 0, &reported))
	}
	require.EqualValues(t, 3, dropSocketOverflow.Load()-overflow)
	reported = math.MaxUint32
	require.False(t, countIngressDrops(oob(1), 0, &reported))
	require.EqualValues(t, 5, dropSocketOverflow.Load()-overflow)
	require.True(t, countIngressDrops(nil, unix.MSG_TRUNC, &reported))
	require.EqualValues(t, 1, dropTruncated.Load()-truncated)
	require.EqualValues(t, 5, dropSocketOverflow.Load()-overflow, "a datagram without the total reset it")
}

// A new source beyond the endpoint limit is counted.
func TestUDPEndpointLimitDropIsCounted(t *testing.T) {
	endpoints := &UdpEndpointPool{sourceLimit: 1}
	t.Cleanup(endpoints.closeAll)
	endpoints.add(netip.MustParseAddrPort("192.0.2.1:5000"), &UdpEndpoint{conn: newTestPacketConn(false), NatTimeout: time.Minute})
	c := &ControlPlane{core: newTestUDPCore(t), deviceRoutes: newTestDeviceRoutes(t), udpEndpoints: endpoints}
	dropped := dropEndpointLimit.Load()
	require.NoError(t, c.handlePkt(t.Context(), []byte("packet"), netip.MustParseAddrPort("192.0.2.2:5000"),
		netip.MustParseAddrPort("198.51.100.1:443"), &routingResult{Mac: [6]byte{2, 0, 0, 0, 0, 10}}))
	require.EqualValues(t, 1, dropEndpointLimit.Load()-dropped)
}

// The tproxy socket's receive queue reports its drops with the next
// datagram it queues.
func TestSocketDropsReportsReceiveQueueOverflow(t *testing.T) {
	config := tproxyListenConfig()
	packetConn, err := config.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if errors.Is(err, unix.EPERM) {
		t.Skip("a transparent socket requires CAP_NET_ADMIN")
	}
	require.NoError(t, err)
	conn := packetConn.(*net.UDPConn)
	t.Cleanup(func() { _ = conn.Close() })
	raw, err := conn.SyscallConn()
	require.NoError(t, err)
	var optErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1)
	}))
	require.NoError(t, optErr)
	sender, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sender.Close() })

	const sent = 64
	payload := make([]byte, 1000)
	for range sent {
		_, err := sender.Write(payload)
		require.NoError(t, err)
	}
	buf, oob := make([]byte, 2048), make([]byte, 120)
	received := 0
	read := func() (uint32, bool) {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, oobn, _, _, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			return 0, false
		}
		received++
		return socketDrops(oob[:oobn]), true
	}
	for {
		if _, ok := read(); !ok {
			break
		}
	}
	require.Less(t, received, sent, "the receive queue did not overflow")
	_, err = sender.Write(payload)
	require.NoError(t, err)
	drops, ok := read()
	require.True(t, ok)
	require.EqualValues(t, sent+1-received, drops)
}
