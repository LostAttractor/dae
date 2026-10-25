package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/quic-go"
)

func TestRecoveryUDPTerminalCauseKeepsResourceAndScope(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	m := &udpSessionManager{ctx: ctx, cancel: cancel}
	parent := netproxy.NewLease(netproxy.NewResourceRef())
	sibling := parent.NewStream()
	var fatal atomic.Int32
	packet, err := m.NewUDP(parent.NewStream(), func(error) { fatal.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	remote := &quic.ApplicationError{Remote: true, ErrorCode: 42, ErrorMessage: "remote rejected transport"}
	cancel(remote)
	_, _, err = packet.ReadFrom(make([]byte, 1))
	f := netproxy.ClassifyFailure(err)
	if !errors.Is(err, remote) || f.Resource != parent.Resource() || f.Scope != netproxy.ScopeSharedResource || f.Code != "42" || f.Stream == nil || fatal.Load() != 1 {
		t.Fatalf("UDP hid terminal reason: %+v count=%d", f, fatal.Load())
	}
	// The protocol owner receives the fatal callback; this unit test's callback
	// records it without invalidating the unrelated sibling itself.
	if !sibling.Valid() {
		t.Fatal("datagram wrapper invalidated sibling without owner")
	}
}

func TestRecoveryUDPLocalCloseAndDeadlineStayLocal(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	m := &udpSessionManager{ctx: ctx, cancel: cancel}
	parent := netproxy.NewLease(netproxy.NewResourceRef())
	fatal := false
	packet, err := m.NewUDP(parent.NewStream(), func(error) { fatal = true })
	if err != nil {
		t.Fatal(err)
	}
	packet.SetReadDeadline(time.Now().Add(-time.Second))
	_, _, err = packet.ReadFrom(make([]byte, 1))
	f := netproxy.ClassifyFailure(err)
	if f.Reason != netproxy.ReasonDeadline || f.Scope != netproxy.ScopeOperation || !parent.Valid() || fatal {
		t.Fatalf("packet deadline killed session: %+v", f)
	}
	packet.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := packet.WriteTo([]byte("blocked"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:53"))); netproxy.ClassifyFailure(err).Reason != netproxy.ReasonDeadline {
		t.Fatalf("write deadline=%v", err)
	}
	packet.SetWriteDeadline(time.Time{})
	packet.SetReadDeadline(time.Time{})
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err = packet.ReadFrom(make([]byte, 1))
	f = netproxy.ClassifyFailure(err)
	if !errors.Is(err, net.ErrClosed) || f.Origin != netproxy.OriginLocalCleanup || f.Scope != netproxy.ScopeStream || !parent.Valid() || fatal {
		t.Fatalf("packet close killed session: %+v", f)
	}
}

// A datagram for a closed session or a full session queue is dropped and
// counted.
func TestUDPFeedCountsDrops(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	m := &udpSessionManager{ctx: ctx, cancel: cancel}
	packet, err := m.NewUDP(netproxy.NewLease(netproxy.NewResourceRef()).NewStream(), func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	closed, full := netproxy.DropClosedStream.Load(), netproxy.DropReceiveFull.Load()
	conn := packet.(*udpConn)
	m.feed(&protocol.UDPMessage{SessionID: conn.ID + 1})
	for range cap(conn.ReceiveCh) + 1 {
		m.feed(&protocol.UDPMessage{SessionID: conn.ID})
	}
	if netproxy.DropClosedStream.Load()-closed != 1 || netproxy.DropReceiveFull.Load()-full != 1 {
		t.Fatalf("counted %d closed and %d full, want 1 each", netproxy.DropClosedStream.Load()-closed, netproxy.DropReceiveFull.Load()-full)
	}
}
