// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type noPacketDeadline struct{ *testPacketConn }

func (*noPacketDeadline) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

func TestPacketDeadlineFallsBackForUnsupportedTransport(t *testing.T) {
	conn := &noPacketDeadline{newTestPacketConn(true)}
	defer conn.Close()
	_, err := writePacketUntil(t.Context(), time.Now().Add(10*time.Millisecond), nil, conn, []byte("packet"), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fallback deadline: %v", err)
	}
	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("unsupported transport was not interrupted")
	}
}

func TestPacketDeadlineWithoutContextTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := newDeadlineInterruptPacketConn()
		defer close(conn.releaseClose)
		_, err := writePacketUntil(t.Context(), time.Now().Add(10*time.Millisecond), nil, conn, []byte("packet"), nil)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("socket deadline: %v", err)
		}
		synctest.Wait()
		select {
		case <-conn.closeStarted:
			t.Fatal("packet timeout closed supported transport")
		default:
		}
	})
}

type deadlineRecordingPacketConn struct {
	*testPacketConn
	deadlines []time.Time
}

func (c *deadlineRecordingPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}

func TestPacketWriteLeavesNoDeadline(t *testing.T) {
	conn := &deadlineRecordingPacketConn{testPacketConn: newTestPacketConn(false)}
	deadline := time.Now().Add(time.Hour)
	if _, err := writePacketUntil(t.Context(), deadline, new(udpWriteSlot), conn, []byte("packet"), nil); err != nil {
		t.Fatal(err)
	}
	if want := []time.Time{deadline, {}}; !slices.Equal(conn.deadlines, want) {
		t.Fatalf("write deadlines = %v, want %v", conn.deadlines, want)
	}
}

// startWorkerWrite blocks one packet write on a pool worker, as an established
// association does under transport backpressure. release unblocks the write if
// the test fails before interrupting it.
func startWorkerWrite(t *testing.T, conn net.PacketConn, release func()) (*udpTaskPool, <-chan error) {
	t.Helper()
	result := make(chan error, 1)
	var pool *udpTaskPool
	pool = newUdpTaskPool(func(_ udpPacketWork, slot *udpWriteSlot, data []byte) {
		_, err := writePacketUntil(pool.ctx, time.Now().Add(time.Hour), slot, conn, data, nil)
		result <- err
	})
	t.Cleanup(pool.close)
	t.Cleanup(release)
	if !pool.emit([]byte("packet"), udpPacketWork{src: testUdpKey(12010)}) {
		t.Fatal("packet rejected")
	}
	return pool, result
}

func TestPacketGenerationCancellationInterruptsWrite(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		// Close blocks: interruption must not wait for it.
		conn := newDeadlineInterruptPacketConn()
		t.Cleanup(func() { close(conn.releaseClose) })
		pool, result := startWorkerWrite(t, conn, func() { _ = conn.SetWriteDeadline(time.Now()) })
		<-conn.writeStarted
		pool.interrupt()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted write = %v, want context.Canceled", err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation waited for the packet deadline or Close")
		}
		select {
		case <-conn.closeStarted:
		case <-time.After(time.Second):
			t.Fatal("cancellation did not start connection cleanup")
		}
	})
	t.Run("close", func(t *testing.T) {
		// Only Close wakes this transport's write.
		conn := newTestPacketConn(true)
		pool, result := startWorkerWrite(t, conn, func() { _ = conn.Close() })
		<-conn.writeStarted
		pool.interrupt()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted write = %v, want context.Canceled", err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation did not close the blocked transport")
		}
	})
}

func TestPacketCancelledSlotDoesNotWrite(t *testing.T) {
	conn := newTestPacketConn(false)
	defer conn.Close()
	slot := new(udpWriteSlot)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := slot.begin(ctx, conn); !errors.Is(err, context.Canceled) {
		t.Fatalf("begin after cancellation = %v", err)
	}
	if slot.conn != nil {
		t.Fatal("cancelled write remained published")
	}
}

func TestPacketExpiredDeadlineDoesNotWrite(t *testing.T) {
	conn := newTestPacketConn(false)
	defer conn.Close()
	_, err := writePacketUntil(t.Context(), time.Now().Add(-time.Second), nil, conn, nil, &net.UDPAddr{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-conn.writeStarted:
		t.Fatal("expired packet reached transport")
	default:
	}
}

func TestPacketSourceContextDeadlinePreservesSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := newDeadlineInterruptPacketConn()
		defer close(conn.releaseClose)
		endpoints := new(UdpEndpointPool)
		defer endpoints.closeAll()
		source := netip.MustParseAddrPort("192.0.2.1:1234")
		destination := netip.MustParseAddrPort("192.0.2.2:443")
		endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: conn, NatTimeout: time.Hour})
		endpoints.add(source, endpoint)
		plane := &ControlPlane{udpEndpoints: endpoints}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()
		_ = plane.handlePkt(ctx, []byte("packet"), source, destination, nil)
		synctest.Wait()
		if endpoint.IsClosed() {
			t.Fatal("inherited packet deadline retired supported socket")
		}
		select {
		case <-conn.closeStarted:
			t.Fatal("inherited packet deadline closed supported transport")
		default:
		}
	})
}

type blockingPacketDialer struct {
	netproxy.Dialer
	dialed chan context.Context
}

func (d blockingPacketDialer) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	d.dialed <- ctx
	<-ctx.Done()
	return nil, ctx.Err()
}

// An established association takes no packet context, so opening a socket for
// a new destination must derive one from the work context and packet deadline.
func TestPacketNewDestinationSocketDial(t *testing.T) {
	for _, cancelWork := range []bool{false, true} {
		name := "deadline"
		if cancelWork {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				endpoints := new(UdpEndpointPool)
				defer endpoints.closeAll()
				source := netip.MustParseAddrPort("192.0.2.1:1234")
				first := netip.MustParseAddrPort("192.0.2.2:443")
				second := netip.MustParseAddrPort("192.0.2.3:443")
				dialed := make(chan context.Context, 1)
				endpoint := &UdpEndpoint{conn: newTestPacketConn(false), firstDst: first, NatTimeout: time.Hour,
					packetDialer: blockingPacketDialer{dialed: dialed}, sockets: make(map[netip.AddrPort]*udpSocket),
					destinations: map[netip.AddrPort]udpDestination{second: {second, time.Now()}}}
				endpoints.add(source, endpoint)
				plane := &ControlPlane{udpEndpoints: endpoints}
				work, cancel := context.WithCancel(t.Context())
				defer cancel()
				start := time.Now()
				deadline := start.Add(time.Second)
				done := make(chan struct{})
				go func() {
					defer close(done)
					_ = plane.handlePktUntil(work, deadline, new(udpWriteSlot), []byte("packet"), source, second, nil)
				}()
				dial := <-dialed
				if got, ok := dial.Deadline(); !ok || !got.Equal(deadline) {
					t.Fatalf("socket dial deadline = %v, %t; want packet deadline %v", got, ok, deadline)
				}
				if cancelWork {
					cancel()
				}
				<-done
				if active := plane.udpSlowWork.Load(); active != 0 {
					t.Fatalf("dial retained %d slow permits", active)
				}
				want := time.Second
				if cancelWork {
					want = 0
				}
				if elapsed := time.Since(start); elapsed != want {
					t.Fatalf("socket dial ended after %v, want %v", elapsed, want)
				}
			})
		})
	}
}

func TestPacketExpiredDeadlineDoesNotStartDNS(t *testing.T) {
	plane := new(ControlPlane)
	err := plane.handlePktUntil(t.Context(), time.Now().Add(-time.Second), nil, nil,
		netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.2:53"), new(routingResult))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired DNS packet: %v", err)
	}
}

// queueingPacketConn never blocks: it queues or drops, as smux UDP streams do.
type queueingPacketConn struct {
	deadlineRecordingPacketConn
	drop bool
	to   []string // where TryWriteTo queued datagrams
}

func (c *queueingPacketConn) TryWriteTo(b []byte, addr net.Addr) (int, error) {
	if c.drop {
		return 0, netproxy.ErrPacketDropped
	}
	c.to = append(c.to, addr.String())
	return len(b), nil
}

// A transport that never blocks needs no deadline or interruption, also
// behind the wrappers established associations use, and a destination socket
// still writes to its target.
func TestPacketWriteSkipsDeadlinesForNonBlockingTransport(t *testing.T) {
	conn := &queueingPacketConn{deadlineRecordingPacketConn: deadlineRecordingPacketConn{testPacketConn: newTestPacketConn(false)}}
	owned, err := netproxy.NewPacketBudget(1).Open(t.Context(), "", func(context.Context, string) (net.PacketConn, error) {
		return netproxy.TrackPacketConn(conn, func() {}), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	original, target := netip.MustParseAddrPort("198.51.100.1:443"), netip.MustParseAddrPort("192.0.2.1:443")
	wrapped := newDestinationPacketConn(owned, original, target)
	if _, err := writePacketUntil(t.Context(), time.Now().Add(time.Hour), new(udpWriteSlot), wrapped, []byte("packet"), net.UDPAddrFromAddrPort(original)); err != nil {
		t.Fatal(err)
	}
	if len(conn.deadlines) != 0 || len(conn.to) != 1 || conn.to[0] != target.String() {
		t.Fatalf("write deadlines = %v, queued to %v; want none, to %v", conn.deadlines, conn.to, target)
	}
	if _, ok := newDestinationPacketConn(conn.testPacketConn, original, target).(netproxy.NonBlockingWriter); ok {
		t.Fatal("destination socket over a blocking transport claims not to block")
	}
	if _, err := writePacketUntil(t.Context(), time.Now().Add(-time.Second), nil, wrapped, []byte("late"), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired packet = %v, want it not written", err)
	}
}

// waitingLayerPacketConn is a layer that never waits over a socket that
// can only wait: TryWriteTo leaves the datagram to WriteTo.
type waitingLayerPacketConn struct{ deadlineRecordingPacketConn }

func (*waitingLayerPacketConn) TryWriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.ErrUnsupported
}

// Such a layer is written as a transport that blocks: bounded by its deadline,
// which the write leaves behind cleared.
func TestPacketWriteWaitsWhereTheLayerCannotTry(t *testing.T) {
	conn := &waitingLayerPacketConn{deadlineRecordingPacketConn{testPacketConn: newTestPacketConn(false)}}
	deadline := time.Now().Add(time.Hour)
	if n, err := writePacketUntil(t.Context(), deadline, new(udpWriteSlot), conn, []byte("packet"), nil); n != 6 || err != nil {
		t.Fatalf("writePacketUntil = %d, %v", n, err)
	}
	if want := []time.Time{deadline, {}}; !slices.Equal(conn.deadlines, want) {
		t.Fatalf("write deadlines = %v, want %v", conn.deadlines, want)
	}
}

// countedDrops sums the drop counters of the reasons, or of all if none.
func countedDrops(reasons ...string) (n uint64) {
	for drop := range netproxy.Drops() {
		if len(reasons) == 0 || slices.Contains(reasons, drop.Reason()) {
			n += drop.Load()
		}
	}
	return n
}

// A datagram the transport queue drops is not a failure, an upload or a
// reason to end the association. The transport counts it; control does not.
func TestUDPTransportQueueDropIsNotAFailure(t *testing.T) {
	conn := &queueingPacketConn{deadlineRecordingPacketConn: deadlineRecordingPacketConn{testPacketConn: newTestPacketConn(false)}, drop: true}
	path := stats.Path{Dialer: t.Name()}
	p := new(UdpEndpointPool)
	defer p.closeAll()
	src := netip.MustParseAddrPort("192.0.2.10:30000")
	ue := &UdpEndpoint{conn: conn, NatTimeout: time.Minute, statsPath: path, traffic: stats.DefaultStore.OpenConnection(path, false)}
	p.add(src, ue)
	c := &ControlPlane{udpEndpoints: p}
	drops := countedDrops()
	for range 3 {
		if err := c.writeUDP(t.Context(), ue, src, netip.MustParseAddrPort("192.0.2.1:443"), []byte("packet")); err != nil {
			t.Fatalf("dropped datagram reported %v", err)
		}
	}
	if _, exists := p.pool.Load(src); !exists || countedDrops() != drops {
		t.Fatalf("endpoint present=%v, %d drops counted; want kept and none", exists, countedDrops()-drops)
	}
	if got := stats.DefaultStore.Snapshot()[path].UploadBytes; got != 0 {
		t.Fatalf("dropped datagrams counted %d uploaded bytes", got)
	}
}

// Users of an smux UDP socket that do not count drops, such as MITM and DNS
// upstreams, see a datagram its full queue drops as one lost on the way: no
// write error, so no relay or path error, and uploaded as it left dae's
// hands. smux counts it once.
func TestSmuxDatagramDropIsLossForOtherUsers(t *testing.T) {
	outbound, _ := smuxTestOutbound(t) // the carrier is not read: queues fill
	conn, err := outbound.ListenPacket(t.Context(), "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	path := stats.Path{Dialer: t.Name(), NodeID: time.Now().String()}
	traffic := stats.DefaultStore.OpenConnection(path, false)
	defer traffic.Close()
	upstream := &mitmUpstreamPacketConn{PacketConn: conn, httpUpstream: &httpUpstream{
		traffic: traffic, path: path, lease: netproxy.NewLease(netproxy.NewResourceRef())}}
	to := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:443"))
	payload := make([]byte, 1200)
	drops, all := countedDrops("flow_queue_full", "carrier_queue_full"), countedDrops()
	const writes = 200 // beyond a batch and the 64 KiB stream queue
	for range writes {
		if _, err := upstream.WriteTo(payload, to); err != nil {
			t.Fatalf("WriteTo = %v", err)
		}
	}
	dropped := countedDrops("flow_queue_full", "carrier_queue_full") - drops
	if uploaded := stats.DefaultStore.Snapshot()[path].UploadBytes; dropped == 0 || countedDrops()-all != dropped || uploaded != writes*uint64(len(payload)) {
		t.Fatalf("%d of %d datagrams dropped (%d counted), %d bytes uploaded; want drops counted once and every datagram uploaded",
			dropped, writes, countedDrops()-all, uploaded)
	}
}
