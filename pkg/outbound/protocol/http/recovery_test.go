package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type negotiatedTestConn struct {
	net.Conn
	lease *netproxy.Lease
	proto string
}

func (c *negotiatedTestConn) NegotiatedProtocol() string       { return c.proto }
func (c *negotiatedTestConn) DependencyLease() *netproxy.Lease { return c.lease }

type h2Write struct {
	fn   func(*http2.Framer) error
	done chan error
}
type localH2Server struct {
	conn    net.Conn
	writer  chan h2Write
	streams chan uint32
	done    chan struct{}
}

func newLocalH2Server(conn net.Conn, maxStreams uint32) *localH2Server {
	s := &localH2Server{conn: conn, writer: make(chan h2Write, 32), streams: make(chan uint32, 32), done: make(chan struct{})}
	framer := http2.NewFramer(conn, conn)
	go func() {
		for {
			select {
			case job := <-s.writer:
				err := job.fn(framer)
				if job.done != nil {
					job.done <- err
				}
				if err != nil {
					_ = conn.Close()
					return
				}
			case <-s.done:
				return
			}
		}
	}()
	go func() {
		defer close(s.done)
		defer conn.Close()
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
			return
		}
		s.writer <- h2Write{fn: func(f *http2.Framer) error {
			return f.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: maxStreams})
		}}
		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				return
			}
			switch frame := frame.(type) {
			case *http2.SettingsFrame:
				if !frame.IsAck() {
					s.writer <- h2Write{fn: func(f *http2.Framer) error { return f.WriteSettingsAck() }}
				}
			case *http2.PingFrame:
				if !frame.IsAck() {
					data := frame.Data
					s.writer <- h2Write{fn: func(f *http2.Framer) error { return f.WritePing(true, data) }}
				}
			case *http2.HeadersFrame:
				id := frame.StreamID
				s.streams <- id
				s.writer <- h2Write{fn: func(f *http2.Framer) error {
					var buf bytes.Buffer
					enc := hpack.NewEncoder(&buf)
					_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					return f.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: buf.Bytes(), EndHeaders: true})
				}}
			}
		}
	}()
	return s
}

func (s *localH2Server) send(t *testing.T, fn func(*http2.Framer) error) {
	t.Helper()
	done := make(chan error, 1)
	select {
	case s.writer <- h2Write{fn: fn, done: done}:
	case <-s.done:
		t.Fatal("server closed")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("frame write blocked")
	}
}

type localH2Parent struct {
	count   atomic.Int32
	max     uint32
	servers chan *localH2Server
}

func (p *localH2Parent) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	p.count.Add(1)
	s := newLocalH2Server(server, p.max)
	p.servers <- s
	return &negotiatedTestConn{Conn: client, proto: "h2", lease: netproxy.NewLease(netproxy.NewResourceRef())}, nil
}
func (*localH2Parent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected packet dial")
}

func newRecoveryProxy(t *testing.T, max uint32) (*HttpProxy, *localH2Parent) {
	t.Helper()
	parent := &localH2Parent{max: max, servers: make(chan *localH2Server, 16)}
	proxy := &HttpProxy{ParentDialer: parent, https: true, Addr: "local:443", pool: newH2ConnsPool(parent, "local:443")}
	t.Cleanup(func() { _ = proxy.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := proxy.pool.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	return proxy, parent
}

func dialRecoveryStream(t *testing.T, proxy *HttpProxy, server *localH2Server) (net.Conn, uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, "tcp", "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-server.streams:
		return conn, id
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return nil, 0
	}
}

func waitRecoveryState(t *testing.T, p *h2ConnsPool, predicate func(netproxy.StateEvent) bool) netproxy.StateEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for event := range p.WatchState(ctx) {
		if predicate(event) {
			return event
		}
	}
	t.Fatalf("pool state did not converge: %+v", p.Snapshot())
	return netproxy.StateEvent{}
}

func TestH2RecoveryResetAndGoAwayPreserveOtherStreams(t *testing.T) {
	proxy, parent := newRecoveryProxy(t, 100)
	server := <-parent.servers
	first, firstID := dialRecoveryStream(t, proxy, server)
	defer first.Close()
	second, secondID := dialRecoveryStream(t, proxy, server)
	defer second.Close()
	old := proxy.pool.conns[0]
	server.send(t, func(f *http2.Framer) error { return f.WriteRSTStream(firstID, http2.ErrCodeCancel) })
	_, err := first.Read(make([]byte, 1))
	if failure := netproxy.ClassifyFailure(err); failure.Scope != netproxy.ScopeStream || failure.Resource != old.ref || failure.Reason != netproxy.ReasonReset || failure.Code != fmt.Sprint(uint32(http2.ErrCodeCancel)) {
		t.Fatalf("stream reset attribution: %+v", failure)
	}
	if !old.lease.Valid() || proxy.pool.Snapshot().State != netproxy.SessionConnected {
		t.Fatal("stream reset killed shared resource")
	}
	server.send(t, func(f *http2.Framer) error { return f.WriteGoAway(secondID, http2.ErrCodeNo, []byte("drain")) })
	waitRecoveryState(t, proxy.pool, func(e netproxy.StateEvent) bool { return e.RecoveryPhase == "draining" })
	if !old.lease.Valid() {
		t.Fatal("GOAWAY invalidated active stream leases")
	}
	server.send(t, func(f *http2.Framer) error { return f.WriteData(secondID, false, []byte("ok")) })
	buf := make([]byte, 2)
	if _, err := io.ReadFull(second, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("draining stream read=%q err=%v", buf, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := proxy.pool.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	newServer := <-parent.servers
	third, _ := dialRecoveryStream(t, proxy, newServer)
	defer third.Close()
	if parent.count.Load() != 2 {
		t.Fatalf("physical connections=%d", parent.count.Load())
	}
	proxy.pool.MarkDead(old.h2)
	if proxy.pool.Snapshot().State != netproxy.SessionConnected {
		t.Fatal("old draining slot invalidated replacement")
	}
	server.send(t, func(f *http2.Framer) error { return f.WriteData(secondID, false, []byte("go")) })
	if _, err := io.ReadFull(second, buf); err != nil || string(buf) != "go" {
		t.Fatalf("replacement truncated existing stream: %q %v", buf, err)
	}
	_ = server.conn.Close()
	_, err = second.Read(buf)
	if failure := netproxy.ClassifyFailure(err); failure.Scope != netproxy.ScopeSharedResource || failure.Resource != old.ref {
		t.Fatalf("socket failure attribution: %+v", failure)
	}
	if proxy.pool.Snapshot().State != netproxy.SessionConnected {
		t.Fatal("dead old socket disconnected healthy sibling")
	}
}

func TestH2RecoveryCapacityDoesNotDialOnDataPath(t *testing.T) {
	proxy, parent := newRecoveryProxy(t, 1)
	server := <-parent.servers
	first, _ := dialRecoveryStream(t, proxy, server)
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := proxy.DialContext(ctx, "tcp", "second.test:443")
	if failure := netproxy.ClassifyFailure(err); failure.Reason != netproxy.ReasonCapacity || failure.Scope != netproxy.ScopeOperation {
		t.Fatalf("capacity error=%+v", failure)
	}
	if parent.count.Load() != 1 {
		t.Fatal("business dial bypassed recovery controller")
	}
	if event := proxy.pool.Snapshot(); !event.Accepting || !event.RecoveryRequired {
		t.Fatalf("capacity state=%+v", event)
	}
	before := proxy.pool.Snapshot().Seq
	_, _ = proxy.DialContext(ctx, "tcp", "third.test:443")
	if proxy.pool.Snapshot().Seq != before {
		t.Fatal("capacity reports restarted recovery episode")
	}
	if err := proxy.pool.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if parent.count.Load() != 2 {
		t.Fatal("controller did not replenish capacity")
	}
	second, _ := dialRecoveryStream(t, proxy, <-parent.servers)
	defer second.Close()
}

func TestH2RecoveryLeaseInvalidationIsSlotSpecific(t *testing.T) {
	proxy, parent := newRecoveryProxy(t, 100)
	server := <-parent.servers
	stream, _ := dialRecoveryStream(t, proxy, server)
	defer stream.Close()
	slot := proxy.pool.conns[0]
	parentLease := netproxy.DependencyOf(slot.raw.(*h2ObservedConn).Conn)
	want := errors.New("actual lower stream failed")
	parentLease.Invalidate(want)
	waitRecoveryState(t, proxy.pool, func(e netproxy.StateEvent) bool { return !e.Accepting })
	if slot.lease.Valid() || netproxy.DependencyOf(stream).Valid() {
		t.Fatal("actual dependency invalidation did not gate derived H2 streams")
	}
}

func TestH2RecoveryHealthySiblingKeepsReadinessAndCause(t *testing.T) {
	proxy, parent := newRecoveryProxy(t, 1)
	first, _ := dialRecoveryStream(t, proxy, <-parent.servers)
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = proxy.DialContext(ctx, "tcp", "capacity.test:443")
	if err := proxy.pool.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	second, _ := dialRecoveryStream(t, proxy, <-parent.servers)
	defer second.Close()
	before := proxy.pool.Snapshot()
	proxy.pool.mu.Lock()
	old := proxy.pool.conns[0]
	proxy.pool.mu.Unlock()
	cause := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	proxy.pool.failSlot(old, cause, netproxy.OpRead)
	if !errors.Is(netproxy.DependencyOf(first).AbortCause(), cause) || netproxy.DependencyOf(second).AbortCause() != nil {
		t.Fatal("failed H2 slot did not abort only its own streams")
	}
	failed := proxy.pool.Snapshot()
	if !failed.Accepting || !failed.RecoveryRequired || failed.ReadinessVersion != before.ReadinessVersion || failed.Resource != before.Resource || failed.EpisodeID <= before.EpisodeID {
		t.Fatalf("healthy sibling lost readiness: before=%+v after=%+v", before, failed)
	}
	if f := netproxy.ClassifyFailure(failed.Cause); f.Resource != old.ref {
		t.Fatalf("lost concrete failed slot: %+v", f)
	}
	proxy.pool.stateMu.Lock()
	proxy.pool.connecting++
	proxy.pool.publishLocked(nil, "")
	proxy.pool.connecting--
	proxy.pool.stateMu.Unlock()
	if e := proxy.pool.Snapshot(); !errors.Is(e.Cause, cause) || e.ReadinessVersion != before.ReadinessVersion {
		t.Fatalf("begin reconnect erased cause/readiness: %+v", e)
	}
	if err := proxy.pool.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	after := proxy.pool.Snapshot()
	if after.RecoveryRequired || after.Cause != nil || after.ReadinessVersion != before.ReadinessVersion || after.Resource != before.Resource {
		t.Fatalf("replenish changed readiness: %+v", after)
	}
	seq := after.Seq
	proxy.pool.failSlot(old, errors.New("late stale failure"), netproxy.OpRead)
	if proxy.pool.Snapshot().Seq != seq {
		t.Fatal("stale slot republished failure")
	}
}

func TestH2RecoveryDrainedRetirementDoesNotStartNewIncident(t *testing.T) {
	proxy, parent := newRecoveryProxy(t, 100)
	server := <-parent.servers
	stream, id := dialRecoveryStream(t, proxy, server)
	old := proxy.pool.conns[0]
	server.send(t, func(f *http2.Framer) error { return f.WriteGoAway(id, http2.ErrCodeNo, nil) })
	waitRecoveryState(t, proxy.pool, func(e netproxy.StateEvent) bool { return e.RecoveryPhase == "draining" })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := proxy.pool.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	<-parent.servers
	before := proxy.pool.Snapshot()
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.lease.Done():
	case <-ctx.Done():
		t.Fatal("drained socket not retired")
	}
	f := netproxy.ClassifyFailure(old.lease.Cause())
	if f.Scope != netproxy.ScopeOperation || f.Origin != netproxy.OriginLocalCleanup || old.lease.AbortCause() != nil {
		t.Fatalf("normal drain became fatal: %+v", f)
	}
	after := proxy.pool.Snapshot()
	if after.RecoveryRequired || after.EpisodeID != before.EpisodeID || after.ReadinessVersion != before.ReadinessVersion {
		t.Fatalf("retirement created new recovery: before=%+v after=%+v", before, after)
	}
}

func TestH2RecoveryPassiveGoAwayObserverFragmentedAndBounded(t *testing.T) {
	p := newH2ConnsPool(nil, "")
	defer p.Close()
	ref := netproxy.NewResourceRef()
	slot := &h2Conn{ref: ref, pool: p, lease: netproxy.NewLease(ref)}
	p.stateMu.Lock()
	p.members[ref] = true
	p.publishLocked(nil, "")
	p.stateMu.Unlock()
	observed := &h2ObservedConn{slot: slot}
	var wire bytes.Buffer
	f := http2.NewFramer(&wire, nil)
	if err := f.WriteData(3, false, bytes.Repeat([]byte{7}, 3072)); err != nil {
		t.Fatal(err)
	}
	debug := bytes.Repeat([]byte("x"), 4096)
	if err := f.WriteGoAway(3, http2.ErrCodeEnhanceYourCalm, debug); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), wire.Bytes()...)
	for _, b := range wire.Bytes() {
		observed.observe([]byte{b})
	}
	if !bytes.Equal(wire.Bytes(), original) {
		t.Fatal("observer modified protocol bytes")
	}
	if !slot.draining.Load() || !slot.lease.Valid() || observed.received.payloadRead != len(observed.received.payload) {
		t.Fatalf("drain observation missing/unbounded: %+v", observed)
	}
	var away http2.GoAwayError
	if !errors.As(p.Snapshot().Cause, &away) || away.LastStreamID != 3 || away.ErrCode != http2.ErrCodeEnhanceYourCalm || len(away.DebugData) != 256 {
		t.Fatalf("lost bounded GOAWAY metadata: %+v", away)
	}
}

func TestH2RecoveryProtocolFatalKeepsActualCause(t *testing.T) {
	proxy, parent := newRecoveryProxy(t, 100)
	server := <-parent.servers
	stream, _ := dialRecoveryStream(t, proxy, server)
	defer stream.Close()
	old := proxy.pool.conns[0]
	// The library decides that a malformed SETTINGS payload is fatal.
	server.send(t, func(f *http2.Framer) error { return f.WriteRawFrame(http2.FrameSettings, 0, 0, []byte{1}) })
	event := waitRecoveryState(t, proxy.pool, func(e netproxy.StateEvent) bool { return !e.Accepting })
	episode, readiness := event.EpisodeID, event.ReadinessVersion
	_, err := stream.Read(make([]byte, 1))
	failure := netproxy.ClassifyFailure(err)
	if failure.Scope != netproxy.ScopeSharedResource || failure.Layer != netproxy.LayerH2 || failure.Resource != old.ref || errors.Is(failure.Cause, net.ErrClosed) {
		t.Fatalf("connection protocol error became generic close: %+v", failure)
	}
	event = proxy.pool.Snapshot()
	if event.EpisodeID != episode || event.ReadinessVersion != readiness || errors.Is(event.Cause, net.ErrClosed) {
		t.Fatalf("enrichment changed incident or lost cause: %+v", event)
	}
}

func TestH2RecoveryDrainedRetirementPreservesPendingCause(t *testing.T) {
	proxy, parent := newRecoveryProxy(t, 100)
	server := <-parent.servers
	stream, id := dialRecoveryStream(t, proxy, server)
	old := proxy.pool.conns[0]
	server.send(t, func(f *http2.Framer) error { return f.WriteGoAway(id, http2.ErrCodeNo, []byte("rotation")) })
	before := waitRecoveryState(t, proxy.pool, func(e netproxy.StateEvent) bool { return e.RecoveryPhase == "draining" })
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.lease.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("drained slot not retired")
	}
	after := proxy.pool.Snapshot()
	if !after.RecoveryRequired || after.EpisodeID != before.EpisodeID || after.Cause != before.Cause {
		t.Fatalf("normal cleanup overwrote pending recovery cause: before=%+v after=%+v", before, after)
	}
}

func TestH2ReadDeadlineKeepsLateBytesAndSibling(t *testing.T) {
	proxy, parent := newRecoveryProxy(t, 100)
	server := <-parent.servers
	first, firstID := dialRecoveryStream(t, proxy, server)
	defer first.Close()
	second, secondID := dialRecoveryStream(t, proxy, server)
	defer second.Close()
	_ = first.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := first.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	server.send(t, func(f *http2.Framer) error { return f.WriteData(firstID, false, []byte("late")) })
	server.send(t, func(f *http2.Framer) error { return f.WriteData(secondID, false, []byte("peer")) })
	_ = first.SetReadDeadline(time.Time{})
	for _, c := range []net.Conn{first, second} {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		data := make([]byte, 4)
		if _, err := io.ReadFull(c, data); err != nil {
			t.Fatal(err)
		}
		want := "late"
		if c == second {
			want = "peer"
		}
		if string(data) != want {
			t.Fatalf("late read %q", data)
		}
	}
	if !proxy.pool.Snapshot().Accepting || !netproxy.DependencyOf(first).Valid() || !netproxy.DependencyOf(second).Valid() {
		t.Fatal("stream deadline invalidated shared capacity")
	}
}
