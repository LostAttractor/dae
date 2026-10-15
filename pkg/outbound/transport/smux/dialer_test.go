package smux

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	xtacismux "github.com/xtaci/smux"
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

func acceptSmuxSessions(parent *pipeDialer, count int) <-chan *xtacismux.Session {
	accepted := make(chan *xtacismux.Session, count)
	go func() {
		defer close(accepted)
		for range count {
			server := <-parent.server
			if _, err := io.ReadFull(server, make([]byte, 2)); err != nil {
				_ = server.Close()
				accepted <- nil
				return
			}
			config := xtacismux.DefaultConfig()
			config.KeepAliveDisabled = true
			session, err := xtacismux.Server(server, config)
			if err != nil {
				_ = server.Close()
				accepted <- nil
				return
			}
			accepted <- session
		}
	}()
	return accepted
}

func waitForSmuxSessions(t *testing.T, accepted <-chan *xtacismux.Session, count int) []*xtacismux.Session {
	t.Helper()
	sessions := make([]*xtacismux.Session, 0, count)
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

type failAfterFirstWriteConn struct {
	net.Conn
	writes atomic.Int32
	closed atomic.Bool
}

func (c *failAfterFirstWriteConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) > 1 {
		return 0, errOpenStreamWrite
	}
	return c.Conn.Write(p)
}

func (c *failAfterFirstWriteConn) Close() error {
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
	dialer := &Smux{Dialer: parent, PassthroughUdp: true}

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
	// smux pools result channels globally. Run the virtual-time scenario in
	// its own process so channels never cross a synctest bubble boundary.
	const child = "DAE_SMUX_IDLE_TEST_CHILD"
	if os.Getenv(child) != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestIdleSessionRemainsUsableWithoutPeerHeartbeats$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), child+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated idle-session test: %v\n%s", err, output)
		}
		return
	}
	synctest.Test(t, func(t *testing.T) {
		parent := &pipeDialer{server: make(chan net.Conn)}
		accepted := acceptSmuxSessions(parent, 1)
		dialer := &Smux{Dialer: parent, MaxConnections: 1}
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
		stream, err := dialer.pool().OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		peer, err := server.AcceptStream()
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

func TestPoolExpandsAndDistributesConcurrentStreams(t *testing.T) {
	const (
		maxConnections = 4
		streamCount    = 8
	)
	parent := &pipeDialer{server: make(chan net.Conn)}
	accepted := acceptSmuxSessions(parent, maxConnections)
	dialer := &Smux{Dialer: parent, MaxConnections: maxConnections}
	t.Cleanup(func() { _ = dialer.Close() })

	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Provision the requested pool through the same Connect entry point used
	// by the recovery coordinator before distributing business streams.
	p := dialer.pool()
	p.mu.Lock()
	for _, slot := range p.slots[1:] {
		p.activateLocked(slot)
	}
	p.publishStateLocked(nil)
	p.mu.Unlock()
	for range maxConnections - 1 {
		if err := dialer.Connect(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	connections := make([]net.Conn, streamCount)
	errs := make([]error, streamCount)
	var wg sync.WaitGroup
	for i := range streamCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			connections[i], errs[i] = dialer.DialContext(context.Background(), "tcp", "speed.example:443")
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("DialContext %d: %v", i, err)
		}
		defer connections[i].Close()
	}
	serverSessions := waitForSmuxSessions(t, accepted, maxConnections)
	defer func() {
		for _, session := range serverSessions {
			_ = session.Close()
		}
	}()

	pool := dialer.pool()
	loads := make([]int, len(pool.slots))
	minLoad, total := streamCount, 0
	for i, slot := range pool.slots {
		resource, err := slot.lifecycle.Current()
		if err != nil {
			t.Fatalf("session %d is not connected: %v", i, err)
		}
		loads[i] = resource.session.NumStreams()
		minLoad = min(minLoad, loads[i])
		total += loads[i]
	}
	if total != streamCount || minLoad == 0 {
		t.Fatalf("session stream loads = %v, want %d streams using every session", loads, streamCount)
	}
}

func TestOpenStreamFailureUsesAnotherSession(t *testing.T) {
	var failedConn *failAfterFirstWriteConn
	parent := &pipeDialer{
		server: make(chan net.Conn),
		wrapClient: func(index int, conn net.Conn) net.Conn {
			if index != 0 {
				return conn
			}
			failedConn = &failAfterFirstWriteConn{Conn: conn}
			return failedConn
		},
	}
	accepted := acceptSmuxSessions(parent, 2)
	dialer := &Smux{Dialer: parent, MaxConnections: 2}
	t.Cleanup(func() { _ = dialer.Close() })

	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := dialer.pool()
	p.mu.Lock()
	p.activateLocked(p.slots[1])
	p.publishStateLocked(nil)
	p.mu.Unlock()
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(context.Background(), "tcp", "failover.example:443")
	if err != nil {
		t.Fatalf("DialContext did not fail over: %v", err)
	}
	defer conn.Close()
	serverSessions := waitForSmuxSessions(t, accepted, 2)
	defer func() {
		for _, session := range serverSessions {
			_ = session.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	for failedConn != nil && !failedConn.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if failedConn == nil || !failedConn.closed.Load() {
		t.Fatal("session with failed OpenStream was not closed")
	}
	parent.mu.Lock()
	dialCount := parent.dialCount
	parent.mu.Unlock()
	if dialCount != 2 {
		t.Fatalf("outer connection count = %d, want 2", dialCount)
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
		wrapClient: func(index int, conn net.Conn) net.Conn {
			if index == 0 {
				return &failAfterFirstWriteConn{Conn: conn}
			}
			return conn
		},
	}
	accepted := acceptSmuxSessions(parent, 2)
	dialer := &Smux{Dialer: parent, MaxConnections: 3}
	t.Cleanup(func() { _ = dialer.Close() })

	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "failover.example:443"); err == nil {
		t.Fatal("failed stream unexpectedly succeeded")
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
	conn, err := dialer.DialContext(context.Background(), "tcp", "failover.example:443")
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
	dialer := &Smux{Dialer: parent, MaxConnections: 2}
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
	dialer := &Smux{Dialer: &errorDialer{err: establishErr}, MaxConnections: 1}
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

	want := []netproxy.SessionState{netproxy.SessionConnecting, netproxy.SessionDisconnected}
	for _, state := range want {
		select {
		case event := <-events:
			if event.State != state {
				t.Fatalf("state event = %s, want %s", event.State, state)
			}
			if state == netproxy.SessionDisconnected && !errors.Is(event.Cause, establishErr) {
				t.Fatalf("disconnect cause = %v, want %v", event.Cause, establishErr)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %s state", state)
		}
	}
}

func TestPoolStaysConnectedWhenOneSessionFails(t *testing.T) {
	parent := &pipeDialer{server: make(chan net.Conn)}
	accepted := acceptSmuxSessions(parent, 3)
	dialer := &Smux{Dialer: parent, MaxConnections: 2}
	t.Cleanup(func() { _ = dialer.Close() })

	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := dialer.DialContext(context.Background(), "tcp", "first.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// Request the second slot, then let the owner establish it.
	requested, err := dialer.DialContext(context.Background(), "tcp", "request-expansion.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer requested.Close()
	if !dialer.Snapshot().RecoveryRequired {
		t.Fatal("pool did not request expansion")
	}
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := dialer.DialContext(context.Background(), "tcp", "second.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	serverSessions := waitForSmuxSessions(t, accepted, 2)
	defer serverSessions[0].Close()
	if err := serverSessions[1].Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for dialer.pool().slots[1].lifecycle.Snapshot().State != netproxy.SessionDisconnected && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state := dialer.Snapshot().State; state != netproxy.SessionConnected {
		t.Fatalf("pool state after one session failed = %s, want connected", state)
	}

	if !dialer.Snapshot().RecoveryRequired {
		t.Fatal("degraded pool did not request replenishment")
	}
	parent.mu.Lock()
	attempts := parent.dialCount
	parent.mu.Unlock()
	if attempts != 2 {
		t.Fatalf("unexpected data-plane connection attempts: %d", attempts)
	}
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	replacement, err := dialer.DialContext(context.Background(), "tcp", "replacement.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	replacementServer := waitForSmuxSessions(t, accepted, 1)[0]
	defer replacementServer.Close()
	if state := dialer.Snapshot().State; state != netproxy.SessionConnected {
		t.Fatalf("pool state after replacement = %s, want connected", state)
	}
}

func TestUnderlyingDisconnectPublishesState(t *testing.T) {
	parent := &pipeDialer{server: make(chan net.Conn, 1)}
	dialer := &Smux{Dialer: parent}
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
	dialer := &Smux{Dialer: parent}
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
	for dialer.Snapshot().State != netproxy.SessionDisconnected && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state := dialer.Snapshot().State; state != netproxy.SessionDisconnected {
		t.Fatalf("state after protocol error = %s, want disconnected", state)
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPoolEpisodeUsesBoundedSlotGenerationWatermarks(t *testing.T) {
	p := newSmuxPool(&Smux{}, 2)
	defer p.Close()
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
	if snapshot.Resource != p.ref || snapshot.Resource.OwnerID == 0 || snapshot.EpisodeID != 3 {
		t.Fatalf("pool publishing identity=%+v", snapshot)
	}
}
