// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

type noPacketDeadline struct{ *testPacketConn }

func (*noPacketDeadline) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

func TestPacketDeadlineFallsBackForUnsupportedTransport(t *testing.T) {
	conn := &noPacketDeadline{newTestPacketConn(true)}
	defer conn.Close()
	_, err := writePacketUntil(t.Context(), time.Now().Add(10*time.Millisecond), conn, []byte("packet"), nil)
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
		_, err := writePacketUntil(t.Context(), time.Now().Add(10*time.Millisecond), conn, []byte("packet"), nil)
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

func TestPacketDeadlineParentCancellation(t *testing.T) {
	conn := newDeadlineInterruptPacketConn()
	defer close(conn.releaseClose)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := writePacketUntil(ctx, time.Now().Add(time.Hour), conn, []byte("packet"), nil)
		done <- err
	}()
	<-conn.writeStarted
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("parent cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt socket")
	}
}

func TestPacketExpiredDeadlineDoesNotWrite(t *testing.T) {
	conn := newTestPacketConn(false)
	defer conn.Close()
	_, err := writePacketUntil(t.Context(), time.Now().Add(-time.Second), conn, nil, &net.UDPAddr{})
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

func TestPacketExpiredDeadlineDoesNotStartDNS(t *testing.T) {
	plane := new(ControlPlane)
	err := plane.handlePktUntil(t.Context(), time.Now().Add(-time.Second), nil,
		netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.2:53"), new(routingResult))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired DNS packet: %v", err)
	}
}
