package anytls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	quic "github.com/daeuniverse/quic-go"
)

type lateWriteConn struct {
	writes       atomic.Int32
	writeStarted chan struct{}
	releaseWrite chan struct{}
}

func (c *lateWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *lateWriteConn) Close() error                     { return nil }
func (c *lateWriteConn) LocalAddr() net.Addr              { return nil }
func (c *lateWriteConn) RemoteAddr() net.Addr             { return nil }
func (c *lateWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *lateWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *lateWriteConn) SetWriteDeadline(time.Time) error { return nil }
func (c *lateWriteConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) == 1 {
		close(c.writeStarted)
		<-c.releaseWrite
	}
	return len(p), nil
}

func TestSessionCloseWithActiveStreamDoesNotDeadlock(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	session := newSession(client, nil, nil)
	stream := newStream(session, 1)
	session.streams[stream.id] = stream

	done := make(chan error, 1)
	go func() { done <- session.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Session.Close deadlocked with an active stream")
	}
	if !stream.closed.Load() {
		t.Fatal("Session.Close left its stream open")
	}
	if session.lease.AbortCause() != nil || stream.lease.AbortCause() != nil {
		t.Fatal("intentional session close issued abort")
	}
}

func TestNewStreamCannotPublishAfterSessionClose(t *testing.T) {
	conn := &lateWriteConn{
		writeStarted: make(chan struct{}),
		releaseWrite: make(chan struct{}),
	}
	session := newSession(conn, nil, nil)
	session.sendPadding = false
	result := make(chan error, 1)
	go func() {
		_, err := session.newStreamContext(context.Background(), "example.com:443")
		result <- err
	}()
	<-conn.writeStarted
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	close(conn.releaseWrite)
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("newStream error = %v, want net.ErrClosed", err)
	}
	if len(session.streams) != 0 {
		t.Fatalf("closed session retained %d streams", len(session.streams))
	}
}

func TestDialerCloseWaitsForAdmittedOperation(t *testing.T) {
	dialer, err := NewDialer(testParentDialer{}, protocol.Header{})
	if err != nil {
		t.Fatal(err)
	}
	d := dialer
	_, finish, err := d.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before operation cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	finish()
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestDialerCloseWaitsForStreamWorker(t *testing.T) {
	d, err := NewDialer(testParentDialer{}, protocol.Header{})
	if err != nil {
		t.Fatal(err)
	}
	carrier := &lateWriteConn{writeStarted: make(chan struct{}), releaseWrite: make(chan struct{})}
	s := newSession(carrier, d.sessionIdle, nil)
	s.sendPadding = false
	d.sessions[s] = struct{}{}
	d.idleSessions[s] = struct{}{}
	opened := make(chan error, 1)
	go func() { _, err := d.DialContext(context.Background(), "tcp", "target.test:443"); opened <- err }()
	<-carrier.writeStarted
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	if err := <-opened; !errors.Is(err, context.Canceled) {
		t.Fatalf("pending open=%v", err)
	}
	select {
	case err := <-closed:
		t.Fatalf("Close skipped active carrier writer: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(carrier.releaseWrite)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

type testParentDialer struct{}

func (testParentDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}
func (testParentDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected listen")
}

func TestClosedStreamDoesNotKillSessionReader(t *testing.T) {
	client, server := net.Pipe()
	s := newSession(client, nil, nil)
	first, second := newStream(s, 1), newStream(s, 2)
	s.streams[1], s.streams[2] = first, second
	_ = first.Close()
	done := make(chan error, 1)
	go func() { done <- s.run() }()
	defer func() { _ = s.Close(); _ = server.Close(); <-done }()
	// An abandoned stream's payload must be discarded, then the next live stream
	// on that same carrier must still receive its data.
	go func() {
		_, _ = server.Write([]byte{cmdPSH, 0, 0, 0, 1, 0, 1, 'a'})
		_, _ = server.Write([]byte{cmdPSH, 0, 0, 0, 2, 0, 1, 'b'})
	}()
	received := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := second.Read(b[:])
		if err == nil && b[0] != 'b' {
			err = errors.New("wrong sibling payload")
		}
		received <- err
	}()
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("closed stream stopped sibling delivery")
	}
	if s.closed.Load() || !s.lease.Valid() {
		t.Fatal("closed stream invalidated shared session")
	}
}

func TestTargetRejectionDoesNotInvalidateSharedSession(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	s := newSession(client, nil, nil)
	defer s.Close()
	first, second := newStream(s, 1), newStream(s, 2)
	s.streams[1], s.streams[2] = first, second
	first.reject(errors.New("connection refused"))
	_, err := first.Read(make([]byte, 1))
	failure := netproxy.ClassifyFailure(err)
	if failure.Scope != netproxy.ScopeStream || failure.Origin != netproxy.OriginTarget {
		t.Fatalf("target rejection=%+v", failure)
	}
	if !s.lease.Valid() || !second.lease.Valid() {
		t.Fatal("target rejection invalidated shared session")
	}
}

type countingRecoveryParent struct {
	attempts atomic.Int32
	err      error
}

func (d *countingRecoveryParent) DialContext(context.Context, string, string) (net.Conn, error) {
	d.attempts.Add(1)
	return nil, d.err
}
func (d *countingRecoveryParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, d.err
}

func TestBusyAnyTLSPoolOnlyRequestsBackgroundExpansion(t *testing.T) {
	parent := &countingRecoveryParent{err: errors.New("recovery attempt failed")}
	d, err := NewDialer(parent, protocol.Header{})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer server.Close()
	s := newSession(client, nil, nil)
	d.sessions[s] = struct{}{}
	d.state.Transition(netproxy.SessionConnected, nil)
	defer d.Close()
	for range 3 {
		selected, err := d.getSession(context.Background())
		if err != nil || selected != s {
			t.Fatalf("ready allocation=%p,%v", selected, err)
		}
	}
	if parent.attempts.Load() != 0 {
		t.Fatal("business allocation started connection attempts")
	}
	snapshot := d.Snapshot()
	if !snapshot.Accepting || !snapshot.RecoveryRequired || snapshot.UsableCapacity != 1 {
		t.Fatalf("expansion request=%+v", snapshot)
	}
	if err := d.Connect(context.Background()); !errors.Is(err, parent.err) {
		t.Fatalf("owner recovery=%v", err)
	}
	if parent.attempts.Load() != 1 {
		t.Fatalf("recovery attempts=%d", parent.attempts.Load())
	}
	if _, err := d.getSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if parent.attempts.Load() != 1 {
		t.Fatal("business allocation bypassed recovery backoff")
	}
	if !d.Snapshot().Accepting {
		t.Fatal("failed expansion made healthy existing resource unavailable")
	}
}

func TestSessionCloseDoesNotSuppressIndependentProtocolFailure(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	s := newSession(client, nil, nil)
	_ = s.Close()
	failure := netproxy.ClassifyFailure(s.fail(&quic.TransportError{ErrorCode: 1}, netproxy.OpRead))
	if failure.Scope != netproxy.ScopeSharedResource || failure.Layer != netproxy.LayerQUIC || failure.Origin == netproxy.OriginLocalCleanup {
		t.Fatalf("suppressed independent failure: %+v", failure)
	}
}
func TestUnknownStreamFailureDoesNotInventCleanupOrigin(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	s := newSession(client, nil, nil)
	defer s.Close()
	failure := netproxy.ClassifyFailure(s.failure(errors.New("unknown peer failure"), netproxy.OpRead))
	if failure.Origin == netproxy.OriginLocalCleanup {
		t.Fatalf("invented cleanup cause: %+v", failure)
	}
}

func TestPoolResourceAndEpisodesStayStableAcrossMemberFailures(t *testing.T) {
	d, err := NewDialer(testParentDialer{}, protocol.Header{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.desired = 3
	members := make([]*session, 3)
	for i := range members {
		client, server := net.Pipe()
		defer server.Close()
		members[i] = newSession(client, nil, nil)
		d.sessions[members[i]] = struct{}{}
	}
	initial := d.Snapshot()
	if initial.Resource.OwnerID == 0 || initial.PublisherID == 0 {
		t.Fatal("missing stable pool publisher")
	}
	fail := func(s *session) error {
		err := s.fail(errors.New("carrier reset"), netproxy.OpRead)
		_ = s.Close()
		d.sessionClosed(s, err)
		return err
	}
	firstCause := fail(members[0])
	first := d.Snapshot()
	_ = fail(members[1])
	second := d.Snapshot()
	d.sessionClosed(members[0], firstCause)
	again := d.Snapshot()
	if first.EpisodeID != 1 || second.EpisodeID != 2 || again.EpisodeID != 2 {
		t.Fatalf("episodes=%d,%d,%d", first.EpisodeID, second.EpisodeID, again.EpisodeID)
	}
	for _, snapshot := range []netproxy.StateEvent{first, second, again} {
		if snapshot.Resource != initial.Resource || snapshot.PublisherID != initial.PublisherID || snapshot.ReadinessVersion != initial.ReadinessVersion || !snapshot.Accepting {
			t.Fatalf("member diagnostic changed pool identity/readiness: %+v", snapshot)
		}
	}
}
