package protocol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type targetPackets struct {
	addr         net.Addr
	lease        *netproxy.Lease
	input        chan []byte
	closed       chan struct{}
	once         sync.Once
	closeWait    <-chan struct{}
	writeStarted chan struct{}
	writeWait    <-chan struct{}
}

func newTargetPackets(address string) *targetPackets {
	return &targetPackets{addr: netproxy.NewAddr("udp", address), lease: netproxy.NewLease(netproxy.NewResourceRef()), input: make(chan []byte, 4), closed: make(chan struct{})}
}
func (c *targetPackets) DependencyLease() *netproxy.Lease { return c.lease }
func (c *targetPackets) LocalAddr() net.Addr              { return c.addr }
func (*targetPackets) SetDeadline(time.Time) error        { return nil }
func (*targetPackets) SetReadDeadline(time.Time) error    { return nil }
func (*targetPackets) SetWriteDeadline(time.Time) error   { return nil }
func (c *targetPackets) Close() error {
	c.once.Do(func() {
		close(c.closed)
		if c.closeWait != nil {
			<-c.closeWait
		}
	})
	return nil
}
func (c *targetPackets) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case data := <-c.input:
		return copy(p, data), c.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}
func (c *targetPackets) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr.String() != c.addr.String() {
		return 0, errors.New("wrong bound destination")
	}
	if c.writeStarted != nil {
		close(c.writeStarted)
		<-c.writeWait
	}
	c.input <- append([]byte(nil), p...)
	return len(p), nil
}

func TestPacketAssociationExpiryDoesNotInterruptWrite(t *testing.T) {
	child := newTargetPackets("target:53")
	child.writeStarted = make(chan struct{})
	release := make(chan struct{})
	child.writeWait = release
	conn, err := NewPacketAssociation(context.Background(), "target:53", func(context.Context, string) (net.PacketConn, error) {
		return child, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer close(release)
	written := make(chan error, 1)
	go func() { _, err := conn.WriteTo([]byte("reply"), child.addr); written <- err }()
	<-child.writeStarted
	conn.(*packetAssociation).expireIdleTargets(time.Now().Add(2 * packetTargetIdleTimeout))
	select {
	case <-child.closed:
		t.Fatal("expiry interrupted an active write")
	default:
	}
	// Let the write complete without closing the release channel twice.
	release <- struct{}{}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadFrom(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
}

func TestPacketBudgetIncludesNestedTargetsAndPendingClose(t *testing.T) {
	budget := netproxy.NewPacketBudget(3) // outer association plus two targets
	release := make(chan struct{})
	closing := make(chan struct{})
	open := func(ctx context.Context, address string) (net.PacketConn, error) {
		return NewPacketAssociation(ctx, address, func(_ context.Context, target string) (net.PacketConn, error) {
			conn := newTargetPackets(target)
			if target == "first:53" {
				conn.closeWait = release
				closing = conn.closed
			}
			return conn, nil
		})
	}
	conn, err := budget.Open(t.Context(), "first:53", open)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"first:53", "second:53"} {
		if _, err := conn.WriteTo([]byte("x"), netproxy.NewAddr("udp", target)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := conn.ReadFrom(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.WriteTo([]byte("x"), netproxy.NewAddr("udp", "third:53")); netproxy.ClassifyFailure(err).Reason != netproxy.ReasonCapacity {
		t.Fatalf("nested admission: %v", err)
	}
	done := make(chan struct{})
	go func() { conn.Close(); close(done) }()
	<-closing
	// Both the wrapper and its blocked target still own their permits.
	if _, err := budget.Open(t.Context(), "replacement:53", open); netproxy.ClassifyFailure(err).Reason != netproxy.ReasonCapacity {
		t.Fatalf("cleanup bypassed admission: %v", err)
	}
	close(release)
	<-done
	replacement, err := budget.Open(t.Context(), "replacement:53", open)
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPacketAssociationReusesTargetsAndPreservesReplies(t *testing.T) {
	opened := make(map[string]*targetPackets)
	conn, err := NewPacketAssociation(context.Background(), "192.0.2.1:53", func(_ context.Context, address string) (net.PacketConn, error) {
		if opened[address] != nil {
			t.Fatalf("opened %s twice", address)
		}
		c := newTargetPackets(address)
		opened[address] = c
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, target := range []string{"192.0.2.1:53", "[2001:db8::1]:123", "192.0.2.1:53"} {
		if _, err := conn.WriteTo([]byte("reply"), netproxy.NewAddr("udp", target)); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(-time.Second))
		if _, _, err := conn.ReadFrom(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("deadline = %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var buf [2]byte
		n, from, err := conn.ReadFrom(buf[:])
		if n != 2 || string(buf[:]) != "re" || from.String() != target || !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("reply = %q, %v, %v", buf, from, err)
		}
	}
	if len(opened) != 2 {
		t.Fatalf("opened %d targets", len(opened))
	}
	// A later target's failure is part of the same association lifetime.
	cause := errors.New("second target carrier failed")
	opened["[2001:db8::1]:123"].lease.Abort(cause)
	_ = conn.Close()
	if !errors.Is(netproxy.DependencyOf(conn).AbortCause(), cause) {
		t.Fatal("lost secondary target abort during cleanup")
	}
	for _, target := range opened {
		select {
		case <-target.closed:
		default:
			t.Fatal("association left a target open")
		}
	}
}

func TestPacketAssociationInterruptsTargetOpen(t *testing.T) {
	for _, action := range []string{"deadline", "close"} {
		t.Run(action, func(t *testing.T) {
			started, finished := make(chan struct{}), make(chan struct{})
			conn, err := NewPacketAssociation(context.Background(), "first:53", func(ctx context.Context, address string) (net.PacketConn, error) {
				if address == "first:53" {
					return newTargetPackets(address), nil
				}
				close(started)
				<-ctx.Done()
				close(finished)
				return nil, ctx.Err()
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			result := make(chan error, 1)
			go func() { _, err := conn.WriteTo([]byte("request"), netproxy.NewAddr("udp", "second:53")); result <- err }()
			<-started
			if action == "deadline" {
				_ = conn.SetWriteDeadline(time.Now())
			} else {
				_ = conn.Close()
				select {
				case <-finished:
				default:
					t.Fatal("Close returned while a target open still used the dialer")
				}
			}
			select {
			case err := <-result:
				if err == nil || action == "deadline" && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("interrupted open = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("target open did not stop")
			}
		})
	}
}

func TestPacketAssociationPreservesFailedTargetDependency(t *testing.T) {
	first := newTargetPackets("first:53")
	second := newTargetPackets("second:53")
	cause := netproxy.WrapFailure(errors.New("carrier failed while opening target"), netproxy.Failure{
		Layer: netproxy.LayerTCP, Scope: netproxy.ScopeSharedResource, Origin: netproxy.OriginPeer,
	})
	conn, err := NewPacketAssociation(context.Background(), "first:53", func(_ context.Context, address string) (net.PacketConn, error) {
		if address == "first:53" {
			return first, nil
		}
		// The owner can fail after the protocol has opened the target, but
		// before the association has accepted that target's connection.
		second.lease.Abort(cause)
		return second, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo([]byte("request"), second.addr); !errors.Is(err, cause) {
		t.Errorf("failed target lost its owner error: %v", err)
	}
	if !errors.Is(netproxy.DependencyOf(conn).AbortCause(), cause) {
		t.Error("failed target did not abort its association")
	}
	select {
	case <-second.closed:
	default:
		t.Error("unaccepted target was left open")
	}
	select {
	case <-first.closed:
	case <-time.After(time.Second):
		t.Error("owner abort did not close the existing target")
	}
}

func TestPacketAssociationAbortCancelsOpenBeforeCleanup(t *testing.T) {
	first := newTargetPackets("first:53")
	releaseClose := make(chan struct{})
	first.closeWait = releaseClose
	started, canceled := make(chan struct{}), make(chan struct{})
	conn, err := NewPacketAssociation(context.Background(), "first:53", func(ctx context.Context, address string) (net.PacketConn, error) {
		if address == "first:53" {
			return first, nil
		}
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer close(releaseClose)
	written := make(chan struct{})
	go func() {
		defer close(written)
		_, _ = conn.WriteTo([]byte("request"), netproxy.NewAddr("udp", "second:53"))
	}()
	<-started
	cause := errors.New("existing target carrier failed")
	first.lease.Abort(cause)
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("owner abort waited for cleanup before canceling target open")
	}
	if !errors.Is(netproxy.DependencyOf(conn).AbortCause(), cause) {
		t.Error("owner abort was not visible when target open was canceled")
	}
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("target write waited for unrelated target cleanup")
	}
}

func TestPacketAssociationBoundsAndExpiresTargets(t *testing.T) {
	var opened []*targetPackets
	conn, err := NewPacketAssociation(context.Background(), "target:0", func(_ context.Context, address string) (net.PacketConn, error) {
		child := newTargetPackets(address)
		opened = append(opened, child)
		return child, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := conn.(*packetAssociation)
	exchange := func(address string) {
		t.Helper()
		if _, err := conn.WriteTo([]byte("x"), netproxy.NewAddr("udp", address)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := conn.ReadFrom(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range maxPacketTargets {
		exchange(fmt.Sprintf("target:%d", i))
	}
	if _, err := conn.WriteTo([]byte("x"), netproxy.NewAddr("udp", "new:53")); netproxy.ClassifyFailure(err).Reason != netproxy.ReasonCapacity {
		t.Fatalf("capacity error = %v", err)
	}
	if len(opened) != maxPacketTargets || !c.lease.Valid() {
		t.Fatal("capacity changed association lifetime")
	}
	exchange("target:0") // Existing targets still work at capacity.

	c.mu.Lock()
	for _, target := range c.conns {
		target.lastUsed = time.Now().Add(-2 * packetTargetIdleTimeout)
	}
	// A reply refreshes the idle timer even without an outbound write.
	c.mu.Unlock()
	opened[0].input <- []byte("reply")
	if _, _, err := conn.ReadFrom(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	c.expireIdleTargets(time.Now())
	c.mu.Lock()
	retained := len(c.conns)
	c.mu.Unlock()
	if retained != 1 {
		t.Fatalf("retained %d targets after expiry", retained)
	}
	for _, child := range opened[1:] {
		select {
		case <-child.closed:
		default:
			t.Fatal("idle target remains open")
		}
		child.lease.Abort(errors.New("retired target failed"))
	}
	if !c.lease.Valid() {
		t.Fatal("local target expiry aborted the association")
	}
	exchange("target:1")
	if len(opened) != maxPacketTargets+1 {
		t.Fatal("expired target was not reopened")
	}

	cause := errors.New("active carrier failed")
	opened[len(opened)-1].lease.Abort(cause)
	_ = conn.Close()
	if !errors.Is(c.lease.AbortCause(), cause) {
		t.Fatal("lost active target failure")
	}
}
