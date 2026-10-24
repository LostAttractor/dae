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
