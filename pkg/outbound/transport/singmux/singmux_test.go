package singmux

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
)

type pipeDialer struct {
	server     chan net.Conn
	mu         sync.Mutex
	dialCount  int
	dialError  func(int) error
	wrapClient func(int, net.Conn) net.Conn
}

func (d *pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	dialIndex := d.dialCount
	d.dialCount++
	dialError := d.dialError
	wrapClient := d.wrapClient
	d.mu.Unlock()
	if dialError != nil {
		if err := dialError(dialIndex); err != nil {
			return nil, err
		}
	}
	client, server := net.Pipe()
	if wrapClient != nil {
		client = wrapClient(dialIndex, client)
	}
	d.server <- server
	return client, nil
}
func (d *pipeDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected ListenPacket")
}

func acceptSmuxSessions(parent *pipeDialer, count int) <-chan *smuxtest.Session {
	accepted := make(chan *smuxtest.Session, count)
	go func() {
		defer close(accepted)
		for range count {
			server := <-parent.server
			if _, err := io.ReadFull(server, make([]byte, 2)); err != nil {
				_ = server.Close()
				accepted <- nil
				return
			}
			accepted <- smuxtest.Server(server)
		}
	}()
	return accepted
}

func waitForSmuxSessions(t *testing.T, accepted <-chan *smuxtest.Session, count int) []*smuxtest.Session {
	t.Helper()
	sessions := make([]*smuxtest.Session, 0, count)
	for range count {
		select {
		case session := <-accepted:
			if session == nil {
				t.Fatal("failed to accept smux session")
			}
			sessions = append(sessions, session)
		case <-time.After(time.Second):
			t.Fatal("timed out accepting smux session")
		}
	}
	return sessions
}

var errOpenStreamWrite = errors.New("open stream write failed")

// failingWriteConn fails every write once fail is set.
type failingWriteConn struct {
	net.Conn
	fail   atomic.Bool
	closed atomic.Bool
}

func (c *failingWriteConn) Write(p []byte) (int, error) {
	if c.fail.Load() {
		return 0, errOpenStreamWrite
	}
	return c.Conn.Write(p)
}

func (c *failingWriteConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type errorDialer struct{ err error }

func (d *errorDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func (*errorDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected ListenPacket")
}

type udpPassthroughDialer struct {
	dialNetwork   string
	dialAddress   string
	listenAddress string
}

var (
	errDialUDP   = errors.New("dial UDP")
	errListenUDP = errors.New("listen UDP")
)

func (d *udpPassthroughDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.dialNetwork = network
	d.dialAddress = address
	return nil, errDialUDP
}

func (d *udpPassthroughDialer) ListenPacket(_ context.Context, address string) (net.PacketConn, error) {
	d.listenAddress = address
	return nil, errListenUDP
}

func TestUDPPassthroughUsesParentDialer(t *testing.T) {
	parent := new(udpPassthroughDialer)
	dialer := &Mux{Dialer: parent, PassthroughUdp: true}

	if _, err := dialer.DialContext(context.Background(), "udp", "dns.example:53"); !errors.Is(err, errDialUDP) {
		t.Fatalf("DialContext error = %v, want %v", err, errDialUDP)
	}
	if parent.dialNetwork != "udp" || parent.dialAddress != "dns.example:53" {
		t.Fatalf("parent DialContext called with %q, %q", parent.dialNetwork, parent.dialAddress)
	}

	if _, err := dialer.ListenPacket(context.Background(), "0.0.0.0:0"); !errors.Is(err, errListenUDP) {
		t.Fatalf("ListenPacket error = %v, want %v", err, errListenUDP)
	}
	if parent.listenAddress != "0.0.0.0:0" {
		t.Fatalf("parent ListenPacket called with %q", parent.listenAddress)
	}
}

func TestIdleSessionRemainsUsableWithoutPeerHeartbeats(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent := &pipeDialer{server: make(chan net.Conn)}
		accepted := acceptSmuxSessions(parent, 1)
		dialer := &Mux{Dialer: parent, MaxConnections: 1}
		defer dialer.Close()

		if err := dialer.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		server := waitForSmuxSessions(t, accepted, 1)[0]
		defer server.Close()

		// sing-box peers do not send SMUX heartbeats. Idle sessions must
		// survive beyond the default timeout and accept another stream.
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if state := dialer.Snapshot(); !state.Accepting {
			t.Fatalf("idle session stopped accepting streams: %+v", state)
		}
		stream, err := dialer.pool().OpenStream(t.Context(), laneStream)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		peer, err := server.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()

		const payload = "after idle"
		if _, err := stream.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(peer, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != payload {
			t.Fatalf("stream payload = %q, want %q", got, payload)
		}
	})
}

// Opening a stream only queues it. A stream on a session whose carrier then
// fails reports that shared failure; the session is closed and later streams
// use another one.
func TestCarrierWriteFailureMovesStreamsToAnotherSession(t *testing.T) {
	var failing *failingWriteConn
	h := newPoolHarness(t, 2, func(index int, conn net.Conn) net.Conn {
		if index != 0 {
			return conn
		}
		failing = &failingWriteConn{Conn: conn}
		return failing
	})
	ctx := t.Context()
	base := h.open(ctx)
	h.replenish()
	// The emptied base session is a spare again, and preferred; its carrier
	// fails once the FIN of its stream is out.
	_ = base.Close()
	resource, err := h.dialer.pool().slots[0].lifecycle.Current()
	if err != nil {
		t.Fatal(err)
	}
	waitIdle(t, resource.session.(*smuxSession))
	failing.fail.Store(true)
	doomed := h.open(ctx)
	_ = doomed.SetDeadline(time.Now().Add(time.Second))
	_, err = doomed.Read(make([]byte, 1))
	if failure := netproxy.ClassifyFailure(err); !errors.Is(err, errOpenStreamWrite) || failure.Scope != netproxy.ScopeSharedResource {
		t.Fatalf("stream on the failed carrier: %v (%+v)", err, failure)
	}
	deadline := time.Now().Add(time.Second)
	for !failing.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !failing.closed.Load() {
		t.Fatal("session with a failed carrier was not closed")
	}
	h.open(ctx)
	if loads := h.loads(); loads[1] != 1 {
		t.Fatalf("stream did not move to the other session: loads=%v", loads)
	}
	if dials := h.dials(); dials != 2 {
		t.Fatalf("outer connection count = %d, want 2", dials)
	}
}

func TestBusinessDialDoesNotRetryFailedConnections(t *testing.T) {
	replacementErr := errors.New("replacement connection failed")
	parent := &pipeDialer{
		server: make(chan net.Conn),
		dialError: func(index int) error {
			if index == 1 {
				return replacementErr
			}
			return nil
		},
	}
	failing := new(failingWriteConn)
	parent.wrapClient = func(index int, conn net.Conn) net.Conn {
		if index == 0 {
			failing.Conn = conn
			return failing
		}
		return conn
	}
	accepted := acceptSmuxSessions(parent, 2)
	dialer := &Mux{Dialer: parent, MaxConnections: 3}
	t.Cleanup(func() { _ = dialer.Close() })

	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	failing.fail.Store(true)
	// Opening only queues the stream; its first read sees the failure.
	conn, err := dialer.DialContext(context.Background(), "tcp", "failover.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("failed stream unexpectedly succeeded")
	}
	_ = conn.Close()
	deadline := time.Now().Add(time.Second)
	for dialer.Snapshot().Accepting && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	parent.mu.Lock()
	attempts := parent.dialCount
	parent.mu.Unlock()
	if attempts != 1 {
		t.Fatalf("business dial started %d connections", attempts)
	}
	if err := dialer.Connect(context.Background()); !errors.Is(err, replacementErr) {
		t.Fatalf("recovery error=%v", err)
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "failover.example:443"); err == nil {
		t.Fatal("unready business dial succeeded")
	}
	parent.mu.Lock()
	attempts = parent.dialCount
	parent.mu.Unlock()
	if attempts != 2 {
		t.Fatalf("business dial bypassed backoff: %d attempts", attempts)
	}
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err = dialer.DialContext(context.Background(), "tcp", "failover.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	serverSessions := waitForSmuxSessions(t, accepted, 2)
	defer func() {
		for _, session := range serverSessions {
			_ = session.Close()
		}
	}()
	parent.mu.Lock()
	dialCount := parent.dialCount
	parent.mu.Unlock()
	if dialCount != 3 {
		t.Fatalf("outer connection attempts = %d, want 3", dialCount)
	}
}

func TestConnectReplacesKnownUnusableSession(t *testing.T) {
	parent := &pipeDialer{server: make(chan net.Conn)}
	accepted := acceptSmuxSessions(parent, 2)
	dialer := &Mux{Dialer: parent, MaxConnections: 2}
	t.Cleanup(func() { _ = dialer.Close() })

	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	resource, err := dialer.pool().slots[0].lifecycle.Current()
	if err != nil {
		t.Fatal(err)
	}
	resource.monitor.broken.Store(true)
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatalf("Connect did not replace unusable session: %v", err)
	}
	serverSessions := waitForSmuxSessions(t, accepted, 2)
	defer func() {
		for _, session := range serverSessions {
			_ = session.Close()
		}
	}()
	parent.mu.Lock()
	dialCount := parent.dialCount
	parent.mu.Unlock()
	if dialCount != 2 {
		t.Fatalf("outer connection count = %d, want 2", dialCount)
	}
}

func TestFastConnectFailurePublishesTransitions(t *testing.T) {
	establishErr := errors.New("establish failed")
	dialer := &Mux{Dialer: &errorDialer{err: establishErr}, MaxConnections: 1}
	t.Cleanup(func() { _ = dialer.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := dialer.WatchState(ctx)
	if initial := <-events; initial.State != netproxy.SessionDisconnected {
		t.Fatalf("initial state = %s, want disconnected", initial.State)
	}
	if err := dialer.Connect(context.Background()); !errors.Is(err, establishErr) {
		t.Fatalf("Connect error = %v, want %v", err, establishErr)
	}

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	var connecting *netproxy.StateEvent
	for {
		select {
		case event := <-events:
			switch event.State {
			case netproxy.SessionConnecting:
				// The slot watcher can report the failure before Connect returns
				// to the pool. This enriches the pending attempt's cause without
				// changing readiness or losing the subsequent disconnected event.
				if connecting != nil {
					if event.ReadinessVersion != connecting.ReadinessVersion || event.Seq <= connecting.Seq || !errors.Is(event.Cause, establishErr) {
						t.Fatalf("unexpected connecting metadata update: %+v after %+v", event, *connecting)
					}
				}
				connecting = &event
			case netproxy.SessionDisconnected:
				if connecting == nil {
					t.Fatal("disconnected event arrived without a connecting transition")
				}
				if !errors.Is(event.Cause, establishErr) {
					t.Fatalf("disconnect cause = %v, want %v", event.Cause, establishErr)
				}
				return
			default:
				t.Fatalf("unexpected state event: %+v", event)
			}
		case <-deadline.C:
			t.Fatal("timed out waiting for connecting and disconnected transitions")
		}
	}
}

func TestUnderlyingDisconnectPublishesState(t *testing.T) {
	parent := &pipeDialer{server: make(chan net.Conn, 1)}
	dialer := &Mux{Dialer: parent}
	accept := func() <-chan net.Conn {
		serverReady := make(chan net.Conn, 1)
		go func() {
			server := <-parent.server
			if _, err := io.ReadFull(server, make([]byte, 2)); err != nil {
				_ = server.Close()
				return
			}
			serverReady <- server
		}()
		return serverReady
	}
	serverReady := accept()
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := <-serverReady
	if state := dialer.Snapshot().State; state != netproxy.SessionConnected {
		t.Fatalf("state after Connect = %s", state)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for dialer.Snapshot().State != netproxy.SessionDisconnected && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state := dialer.Snapshot().State; state != netproxy.SessionDisconnected {
		t.Fatalf("state after underlay close = %s, want disconnected", state)
	}

	serverReady = accept()
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	server = <-serverReady
	if state := dialer.Snapshot().State; state != netproxy.SessionConnected {
		t.Fatalf("state after reconnect = %s, want connected", state)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolErrorPublishesState(t *testing.T) {
	parent := &pipeDialer{server: make(chan net.Conn, 1)}
	dialer := &Mux{Dialer: parent}
	serverReady := make(chan net.Conn, 1)
	go func() {
		server := <-parent.server
		if _, err := io.ReadFull(server, make([]byte, 2)); err != nil {
			_ = server.Close()
			return
		}
		serverReady <- server
	}()
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := <-serverReady
	defer server.Close()
	if _, err := server.Write(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for dialer.Snapshot().Cause == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state := dialer.Snapshot(); state.State != netproxy.SessionDisconnected || netproxy.ClassifyFailure(state.Cause).Reason != netproxy.ReasonProtocol {
		t.Fatalf("state after protocol error = %+v, want disconnected by a protocol failure", state)
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPoolEpisodeUsesBoundedSlotGenerationWatermarks(t *testing.T) {
	p := newSessionPool(&Mux{}, 2)
	defer p.Close()
	initial := p.Snapshot()
	first, second := netproxy.NewResourceRef(), netproxy.NewResourceRef()
	event := func(ref netproxy.ResourceRef) netproxy.StateEvent {
		return netproxy.StateEvent{Resource: ref, Cause: netproxy.WrapFailure(errors.New("carrier failed"), netproxy.Failure{Resource: ref, Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerTCP})}
	}
	p.observeSlotFailureLocked(p.slots[0], event(first))
	p.observeSlotFailureLocked(p.slots[0], event(first))
	if p.episode != 1 {
		t.Fatalf("duplicate root created %d episodes", p.episode)
	}
	newer := first
	newer.Generation++
	p.observeSlotFailureLocked(p.slots[0], event(newer))
	p.observeSlotFailureLocked(p.slots[0], event(first))
	p.observeSlotFailureLocked(p.slots[1], event(second))
	if p.episode != 3 {
		t.Fatalf("generation watermark episodes=%d", p.episode)
	}
	snapshot := p.Snapshot()
	if snapshot.Resource != initial.Resource || snapshot.Resource.OwnerID == 0 || snapshot.EpisodeID != 3 {
		t.Fatalf("pool publishing identity=%+v", snapshot)
	}
}
