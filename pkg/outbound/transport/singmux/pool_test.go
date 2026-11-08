package singmux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
)

// poolHarness serves every dialed session and drives the pool only through
// its public operations; Connect stands in for the recovery coordinator.
type poolHarness struct {
	t        *testing.T
	parent   *pipeDialer
	dialer   *Mux
	accepted chan *smuxtest.Session
	servers  []*smuxtest.Session
}

func newPoolHarness(t *testing.T, maxConnections int, wrapClient func(int, net.Conn) net.Conn) *poolHarness {
	h := &poolHarness{
		t:        t,
		parent:   &pipeDialer{server: make(chan net.Conn), wrapClient: wrapClient},
		accepted: make(chan *smuxtest.Session, 4*MaxConnectionsLimit),
	}
	h.dialer = &Mux{Dialer: h.parent, MaxConnections: maxConnections}
	served := make(chan struct{})
	go func() {
		defer close(served)
		for server := range h.parent.server {
			if _, err := io.ReadFull(server, make([]byte, 2)); err != nil {
				_ = server.Close()
				continue
			}
			h.accepted <- smuxtest.Server(server)
		}
	}()
	t.Cleanup(func() {
		_ = h.dialer.Close()
		close(h.parent.server)
		<-served
		close(h.accepted)
		for session := range h.accepted {
			h.servers = append(h.servers, session)
		}
		for _, session := range h.servers {
			_ = session.Close()
		}
	})
	if err := h.dialer.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	return h
}

// server returns the peer of the index-th dialed session.
func (h *poolHarness) server(index int) *smuxtest.Session {
	h.t.Helper()
	for len(h.servers) <= index {
		select {
		case session := <-h.accepted:
			h.servers = append(h.servers, session)
		case <-time.After(time.Second):
			h.t.Fatalf("session %d was not dialed", index)
		}
	}
	return h.servers[index]
}

func (h *poolHarness) open(ctx context.Context) net.Conn {
	h.t.Helper()
	conn, err := h.dialer.DialContext(ctx, "tcp", "target.example:443")
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// openUDP opens a UDP association, of QUIC if quic.
func (h *poolHarness) openUDP(ctx context.Context, quic bool) net.PacketConn {
	h.t.Helper()
	if quic {
		ctx = netproxy.WithQUIC(ctx)
	}
	conn, err := h.dialer.ListenPacket(ctx, "192.0.2.1:443")
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// lanes lists the lane of every active slot in slot order.
func (h *poolHarness) lanes() []lane {
	p := h.dialer.pool()
	p.mu.Lock()
	defer p.mu.Unlock()
	var lanes []lane
	for _, slot := range p.slots {
		if slot.lifecycle != nil {
			lanes = append(lanes, slot.lane)
		}
	}
	return lanes
}

func (h *poolHarness) openN(ctx context.Context, n int) []net.Conn {
	conns := make([]net.Conn, n)
	for i := range conns {
		conns[i] = h.open(ctx)
	}
	return conns
}

func (h *poolHarness) replenish() {
	h.t.Helper()
	for range MaxConnectionsLimit {
		if !h.dialer.Snapshot().RecoveryRequired {
			return
		}
		if err := h.dialer.Connect(h.t.Context()); err != nil {
			h.t.Fatal(err)
		}
	}
	h.t.Fatal("capacity recovery did not converge")
}

func (h *poolHarness) dials() int {
	h.parent.mu.Lock()
	defer h.parent.mu.Unlock()
	return h.parent.dialCount
}

// loads lists the streams of every active slot in slot order.
func (h *poolHarness) loads() []int {
	p := h.dialer.pool()
	p.mu.Lock()
	defer p.mu.Unlock()
	var loads []int
	for _, slot := range p.slots {
		if slot.lifecycle != nil {
			loads = append(loads, slot.streams)
		}
	}
	return loads
}

func (h *poolHarness) waitFor(what string, done func(netproxy.StateEvent) bool) {
	h.t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		state := h.dialer.Snapshot()
		if done(state) {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %s: %+v", what, state)
		}
		time.Sleep(time.Millisecond)
	}
}

func closeAll(conns []net.Conn) {
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// A lane's first stream takes the spare session and the pool asks for a new
// spare; a lane grows at the stream threshold. With no other lane seen, TCP
// spreads over every position but the spare.
func TestPoolExpandsAtStreamThreshold(t *testing.T) {
	h := newPoolHarness(t, DefaultMaxConnections, nil)
	ctx := t.Context()
	h.open(ctx)
	if !h.dialer.Snapshot().RecoveryRequired {
		t.Fatal("taking the spare did not ask for another")
	}
	h.replenish()
	h.openN(ctx, expandStreams-1)
	if h.dialer.Snapshot().RecoveryRequired {
		t.Fatalf("pool expanded below the stream threshold: loads=%v", h.loads())
	}
	h.open(ctx)
	if !h.dialer.Snapshot().RecoveryRequired {
		t.Fatal("loaded lane did not request another session")
	}
	h.replenish()
	h.openN(ctx, expandStreams)
	if loads := h.loads(); h.dials() != 3 || len(loads) != 3 || loads[2] != expandStreams || h.dialer.Snapshot().RecoveryRequired {
		t.Fatalf("new session was not filled before expanding again: dials=%d loads=%v", h.dials(), loads)
	}
	for range 8 * expandStreams {
		h.open(ctx)
		h.replenish()
	}
	loads, lanes := h.loads(), h.lanes()
	if h.dials() != DefaultMaxConnections || len(loads) != DefaultMaxConnections || lanes[1] != laneSpare || loads[1] != 0 {
		t.Fatalf("TCP did not grow around the spare: dials=%d loads=%v lanes=%v", h.dials(), loads, lanes)
	}
	for i, load := range loads {
		if i != 1 && load < expandStreams {
			t.Fatalf("streams were not distributed: %v", loads)
		}
	}
}

// A lane that opened a user stream within idleTimeout keeps a position for
// its return; once it has been gone for idleTimeout, a loaded lane takes it.
func TestPoolReservesForRecentLanes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newPoolHarness(t, DefaultMaxConnections, nil)
		ctx := t.Context()
		_ = h.openUDP(ctx, false).Close()
		h.replenish()
		synctest.Wait() // the game's session drains back to a spare
		for range 4 * expandStreams {
			h.open(ctx)
			h.replenish()
		}
		if lanes := h.lanes(); !slices.Equal(lanes, []lane{laneStream, laneSpare, laneStream}) {
			t.Fatalf("lanes=%v, want TCP to grow beside the spare and keep a position for the game", lanes)
		}
		time.Sleep(idleTimeout)
		h.open(ctx)
		h.replenish()
		if lanes := h.lanes(); !slices.Equal(lanes, []lane{laneStream, laneSpare, laneStream, laneStream}) {
			t.Fatalf("a lane gone for idleTimeout kept its position: lanes=%v", lanes)
		}
	})
}

// Each lane gets a session of its own, so that a game shares a carrier
// neither with a QUIC upload nor with TCP, and later streams stay in it.
func TestPoolSeparatesLanes(t *testing.T) {
	h := newPoolHarness(t, DefaultMaxConnections, nil)
	ctx := t.Context()
	counts := func(l lane) (own, spare, fallback uint64) {
		return placements[l][placeOwn].Load(), placements[l][placeSpare].Load(), placements[l][placeFallback].Load()
	}
	own, spare, _ := counts(laneInteractive)
	h.openUDP(ctx, false)
	h.replenish()
	h.open(ctx)
	h.replenish()
	h.openUDP(ctx, true)
	h.replenish()
	h.openUDP(ctx, false)
	h.openN(ctx, 2)
	if lanes, loads := h.lanes(), h.loads(); len(lanes) != 4 || lanes[0] != laneInteractive || lanes[1] != laneStream || lanes[2] != laneBulk || lanes[3] != laneSpare ||
		loads[0] != 2 || loads[1] != 3 || loads[2] != 1 || loads[3] != 0 || h.dialer.Snapshot().RecoveryRequired {
		t.Fatalf("lanes=%v loads=%v", lanes, loads)
	}
	if o, s, _ := counts(laneInteractive); o-own != 1 || s-spare != 1 {
		t.Fatalf("interactive placements: %d own, %d spare", o-own, s-spare)
	}
}

// A spare taken while another session was still connecting is replaced
// during recovery, before a late game can fall back onto QUIC.
func TestPoolReplacesSpareAfterCoalescedRequest(t *testing.T) {
	h := newPoolHarness(t, 6, nil)
	ctx := t.Context()
	h.open(ctx)
	h.replenish()
	h.openN(ctx, expandStreams) // the last asks for a second TCP session
	h.openUDP(ctx, true)        // QUIC takes the spare meanwhile
	h.replenish()
	if lanes := h.lanes(); !slices.Equal(lanes, []lane{laneStream, laneBulk, laneStream, laneSpare}) {
		t.Fatalf("recovery converged without replacing the spare: lanes=%v", lanes)
	}
	fallback := placements[laneInteractive][placeFallback].Load()
	h.openUDP(ctx, false)
	if lanes, loads := h.lanes(), h.loads(); lanes[3] != laneInteractive || loads[3] != 1 || placements[laneInteractive][placeFallback].Load() != fallback {
		t.Fatalf("late game did not get its own session: lanes=%v loads=%v", lanes, loads)
	}
	h.replenish()
	if lanes := h.lanes(); !slices.Contains(lanes, laneSpare) {
		t.Fatalf("lanes=%v, want a spare", lanes)
	}
}

func TestPoolSpareDemandIsIdempotent(t *testing.T) {
	h := newPoolHarness(t, DefaultMaxConnections, nil)
	h.open(t.Context())
	p := h.dialer.pool()
	for _, connected := range []bool{false, true} {
		if connected {
			h.replenish()
		}
		p.mu.Lock()
		spare := p.slots[1]
		before := spare.lastUsed
		p.expandLocked(laneSpare)
		unchanged := spare.lastUsed == before && p.slots[2].lifecycle == nil
		p.mu.Unlock()
		if !unchanged {
			t.Fatalf("connected=%v: repeated spare demand changed capacity or idle time", connected)
		}
	}
}

func TestPoolUsesHealthyFallbackBeforeSaturatedOwnLane(t *testing.T) {
	h := newPoolHarness(t, 2, nil)
	h.open(t.Context())
	h.replenish()
	h.openUDP(t.Context(), false)
	resource, err := h.dialer.pool().slots[0].lifecycle.Current()
	if err != nil {
		t.Fatal(err)
	}
	s := resource.session.(*smuxSession)
	s.budget.Store(0)
	defer func() { s.budget.Store(smuxReceiveBuffer); signal(s.budgetWake) }()
	before := placements[laneStream][placeFallback].Load()
	h.open(t.Context())
	if loads := h.loads(); loads[0] != 1 || loads[1] != 2 || placements[laneStream][placeFallback].Load() != before+1 {
		t.Fatalf("healthy fallback was not used: loads=%v", loads)
	}
}

// TCP that came first does not take the spare from a game that comes
// later: the game lands on a session of its own.
func TestPoolKeepsSpareForLateLane(t *testing.T) {
	h := newPoolHarness(t, DefaultMaxConnections, nil)
	ctx := t.Context()
	for range 20 {
		h.open(ctx)
		h.replenish()
	}
	h.openUDP(ctx, false)
	if lanes, loads := h.lanes(), h.loads(); lanes[1] != laneInteractive || loads[1] != 1 {
		t.Fatalf("the game shares a session: lanes=%v loads=%v", lanes, loads)
	}
}

// With fewer positions than lanes and a spare, streams fall back to other
// lanes' sessions, bulk ones to interactive sessions last, without errors.
func TestPoolFallsBackWithFewConnections(t *testing.T) {
	for _, maxConnections := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(maxConnections), func(t *testing.T) {
			h := newPoolHarness(t, maxConnections, nil)
			ctx := t.Context()
			fallback := placements[laneBulk][placeFallback].Load()
			h.openUDP(ctx, false)
			h.replenish()
			h.open(ctx)
			h.replenish()
			h.openUDP(ctx, true)
			h.replenish()
			lanes := h.lanes()
			if len(lanes) != maxConnections || h.dials() != maxConnections {
				t.Fatalf("lanes=%v dials=%d", lanes, h.dials())
			}
			// The QUIC association fell back unless it found a spare.
			if fell := placements[laneBulk][placeFallback].Load() - fallback; (fell == 1) != (maxConnections < 3) {
				t.Fatalf("lanes=%v: QUIC fell back %d times", lanes, fell)
			}
			if maxConnections == 2 && h.loads()[1] != 2 {
				t.Fatalf("QUIC fell back onto the interactive session: lanes=%v loads=%v", lanes, h.loads())
			}
		})
	}
}

func TestPoolCoalescesConcurrentExpansion(t *testing.T) {
	h := newPoolHarness(t, MaxConnectionsLimit, nil)
	h.open(t.Context())
	h.replenish()
	h.openN(t.Context(), expandStreams-1)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() { h.open(t.Context()) })
	}
	wg.Wait()
	if loads := h.loads(); len(loads) != 3 {
		t.Fatalf("concurrent opens activated %d slots (loads=%v), want one outstanding request", len(loads), loads)
	}
	h.replenish()
	if dials := h.dials(); dials != 3 {
		t.Fatalf("burst dialed %d sessions, want 3", dials)
	}
}

// Connectivity checks use an interactive session, else the spare, and
// neither give a session a lane nor grow the pool.
func TestPoolConnectivityChecksDoNotExpand(t *testing.T) {
	h := newPoolHarness(t, MaxConnectionsLimit, nil)
	check := netproxy.WithConnectivityCheck(t.Context())
	var wg sync.WaitGroup
	for range 2 * expandStreams {
		wg.Go(func() { h.open(check) })
	}
	wg.Wait()
	if loads, lanes := h.loads(), h.lanes(); h.dialer.Snapshot().RecoveryRequired || len(loads) != 1 || lanes[0] != laneSpare {
		t.Fatalf("connectivity checks expanded the pool: loads=%v lanes=%v", loads, lanes)
	}
	// Open check streams do not count towards the user stream threshold.
	h.open(t.Context())
	h.replenish()
	h.openN(t.Context(), expandStreams-1)
	if h.dialer.Snapshot().RecoveryRequired {
		t.Fatalf("check streams made user traffic expand the pool: loads=%v", h.loads())
	}
	h.open(t.Context())
	if !h.dialer.Snapshot().RecoveryRequired {
		t.Fatal("user stream on a loaded session did not expand the pool")
	}
	h.replenish()
	h.openUDP(t.Context(), false)
	h.replenish()
	before := h.loads()
	h.open(check)
	if loads := h.loads(); loads[1] != before[1]+1 || h.dialer.Snapshot().RecoveryRequired {
		t.Fatalf("check did not use the interactive session: lanes=%v loads %v then %v", h.lanes(), before, loads)
	}
}

// Idle extra sessions are retired, except one spare while a session has a
// lane; slot 0 is kept and serves as the spare once idle itself.
func TestPoolRetiresIdleExtraSessions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newPoolHarness(t, 4, nil)
		ctx := t.Context()
		game := h.openUDP(ctx, false)
		h.replenish()
		h.open(ctx).Close()
		h.replenish()
		synctest.Wait() // FIN must leave before the released slot becomes spare.
		if lanes := h.lanes(); len(lanes) != 3 || lanes[0] != laneInteractive || lanes[1] != laneSpare || lanes[2] != laneSpare {
			t.Fatalf("lanes=%v", lanes)
		}
		time.Sleep(idleTimeout)
		synctest.Wait()
		if lanes := h.lanes(); len(lanes) != 2 || lanes[1] != laneSpare {
			t.Fatalf("idle sessions kept, or the spare retired: lanes=%v", lanes)
		}
		select {
		case <-h.server(1).Done():
		case <-time.After(time.Second):
			t.Fatal("retired session is still open at the peer")
		}
		// The spare outlives the idle timeout while slot 0 carries the game.
		time.Sleep(2 * idleTimeout)
		synctest.Wait()
		if lanes := h.lanes(); len(lanes) != 2 {
			t.Fatalf("the spare was retired: lanes=%v", lanes)
		}
		// Once the game ends, slot 0 is the spare.
		_ = game.Close()
		time.Sleep(2 * idleTimeout)
		synctest.Wait()
		if state := h.dialer.Snapshot(); len(h.loads()) != 1 || !state.Accepting || state.EpisodeID != 0 || state.RecoveryRequired || h.dials() != 3 {
			t.Fatalf("base session changed: loads=%v dials=%d state=%+v", h.loads(), h.dials(), state)
		}
	})
}

func TestPoolRetiresFailedIdleSlotWhenSpareRemains(t *testing.T) {
	h := newPoolHarness(t, 3, nil)
	ctx := t.Context()
	h.open(ctx)
	h.replenish()
	busy := h.openUDP(ctx, false)
	h.replenish() // a spare remains when the game's session fails
	if err := h.server(1).Close(); err != nil {
		t.Fatal(err)
	}
	h.waitFor("busy failure", func(state netproxy.StateEvent) bool {
		return state.RecoveryRequired && state.UsableCapacity == 2
	})
	_ = busy.Close()
	h.waitFor("retirement", func(state netproxy.StateEvent) bool {
		return !state.RecoveryRequired && state.EpisodeID == 1
	})
	if err := h.dialer.Connect(ctx); err != nil || h.dials() != 3 || len(h.loads()) != 2 {
		t.Fatalf("drained failed session was refilled: err=%v dials=%d loads=%v", err, h.dials(), h.loads())
	}
}

func TestPoolKeepsSoleUsableIdleSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newPoolHarness(t, 2, nil)
		closeAll(h.openN(t.Context(), 1))
		h.replenish()
		// The base session fails while the idle extra session still works.
		if err := h.server(0).Close(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(idleTimeout)
		synctest.Wait()
		if state := h.dialer.Snapshot(); len(h.loads()) != 2 || !state.Accepting || state.UsableCapacity != 1 {
			t.Fatalf("idle retirement closed the only usable session: loads=%v state=%+v", h.loads(), state)
		}
		// Once the base session is refilled, the extra one is retired.
		h.replenish()
		time.Sleep(idleTimeout)
		synctest.Wait()
		if state := h.dialer.Snapshot(); len(h.loads()) != 1 || !state.Accepting || state.RecoveryRequired || h.dials() != 3 {
			t.Fatalf("extra session outlived the refill: loads=%v dials=%d state=%+v", h.loads(), h.dials(), state)
		}
	})
}

// A session whose receive buffer is full is saturated: new streams of its
// lane go to another session although it carries fewer.
func TestPoolAvoidsSaturatedSmuxSessions(t *testing.T) {
	for _, capacity := range []int{1, 2, DefaultMaxConnections, 6} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			h := newPoolHarness(t, capacity, nil)
			ctx := t.Context()
			h.open(ctx)
			h.replenish()
			h.open(ctx)
			resource, err := h.dialer.pool().slots[0].lifecycle.Current()
			if err != nil {
				t.Fatal(err)
			}
			s := resource.session.(*smuxSession)
			s.budget.Store(0) // as behind a stalled reader
			defer func() { s.budget.Store(smuxReceiveBuffer); signal(s.budgetWake) }()
			h.open(ctx)
			if loads := h.loads(); capacity > 1 && (loads[0] != 2 || loads[1] != 1) {
				t.Fatalf("new stream ignored a ready spare: loads=%v", loads)
			}
			h.replenish()
			h.openN(ctx, expandStreams+1)
			loads := h.loads()
			if capacity == 1 {
				if loads[0] != expandStreams+4 {
					t.Fatalf("single carrier stopped accepting streams: loads=%v", loads)
				}
			} else if loads[0] != 2 || loads[1] != expandStreams+2 {
				t.Fatalf("streams returned to the saturated session: loads=%v", loads)
			}
		})
	}
}

// leasedConn is a carrier that depends on a parent's lease.
type leasedConn struct {
	net.Conn
	lease *netproxy.Lease
}

func (c leasedConn) DependencyLease() *netproxy.Lease { return c.lease }

// Replacing a session whose peer stopped reading and never answers a
// half-close takes no time, whether it was aborted, and closes at once, or
// its carrier's lease ended without an abort (as an h2 GOAWAY ends it), and
// it closes in the background.
func TestLostSessionReplacedAtOnce(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolSmux, ProtocolYAMux} {
		for _, loss := range []string{"abort", "parent"} {
			t.Run(protocol.String()+"/"+loss, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					parentLease := netproxy.NewLease(netproxy.NewResourceRef())
					stop := make(chan struct{})
					parent := &pipeDialer{server: make(chan net.Conn), wrapClient: func(i int, conn net.Conn) net.Conn {
						if i == 0 {
							return silentPeerConn{leasedConn{conn, parentLease}}
						}
						return silentPeerConn{conn}
					}}
					go func() {
						for conn := range parent.server {
							go func() {
								_, _ = io.ReadFull(conn, make([]byte, 2))
								<-stop
								_ = conn.Close()
							}()
						}
					}()
					defer close(parent.server)
					defer close(stop)
					mux := &Mux{Dialer: parent, Protocol: protocol, MaxConnections: 1}
					defer mux.Close()
					if err := mux.Connect(t.Context()); err != nil {
						t.Fatal(err)
					}
					if loss == "abort" {
						pool := mux.pool()
						pool.mu.Lock()
						lifecycle := pool.slots[0].lifecycle
						pool.mu.Unlock()
						handle, err := lifecycle.CurrentHandle()
						if err != nil {
							t.Fatal(err)
						}
						handle.Abort(errors.New("aborted by its owner"))
					} else {
						parentLease.Invalidate(errors.New("parent retired"))
					}
					synctest.Wait()
					start := time.Now()
					if err := mux.Connect(t.Context()); err != nil {
						t.Fatal(err)
					}
					if waited := time.Since(start); waited != 0 {
						t.Fatalf("replacing the session took %v", waited)
					}
				})
			})
		}
	}
}

// heldConn is a carrier whose writes wait while it is held, as behind a
// peer that does not read yet; closing it fails them.
type heldConn struct {
	leasedConn
	held            *atomic.Bool
	release, closed <-chan struct{}
	close           func()
}

func (c heldConn) Write(p []byte) (int, error) {
	if c.held.Load() {
		select {
		case <-c.release:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	return c.leasedConn.Write(p)
}

func (c heldConn) Close() error { c.close(); return c.leasedConn.Close() }

// A stream closes normally with its upload still queued behind a carrier
// that cannot write yet; the carrier's lease then ends without an abort, as
// an h2 GOAWAY ends it, and Connect replaces the session at once. The old
// session still writes the upload and FIN once the carrier can, while a
// stream left open on it fails its writes instead of queueing them behind
// the session's end.
func TestLostSessionDeliversQueuedUpload(t *testing.T) {
	// Within what a smux stream queues without waiting for the carrier.
	const size = 48 << 10
	for _, protocol := range []Protocol{ProtocolSmux, ProtocolYAMux} {
		t.Run(protocol.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				got := make(chan error, 1)
				parent := serveSingMux(t, protocol, func(_ muxRequest, stream net.Conn) {
					if _, err := stream.Write([]byte{1}); err != nil {
						got <- err
						return
					}
					data, err := io.ReadAll(stream)
					if err == nil && len(data) != size {
						err = fmt.Errorf("server read %d of %d bytes", len(data), size)
					}
					got <- err
				})
				parentLease := netproxy.NewLease(netproxy.NewResourceRef())
				held, release := new(atomic.Bool), make(chan struct{})
				parent.wrapClient = func(i int, conn net.Conn) net.Conn {
					if i == 0 {
						closed := make(chan struct{})
						return heldConn{leasedConn{conn, parentLease}, held, release, closed, sync.OnceFunc(func() { close(closed) })}
					}
					return conn
				}
				mux := &Mux{Dialer: parent, Protocol: protocol, MaxConnections: 1}
				defer mux.Close()
				if err := mux.Connect(t.Context()); err != nil {
					t.Fatal(err)
				}
				conn, err := mux.DialContext(t.Context(), "tcp", "target.example:443")
				if err != nil {
					t.Fatal(err)
				}
				// The first byte carries the stream request; the reply shows
				// the server accepted the stream.
				if _, err := conn.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
				open, err := mux.DialContext(t.Context(), "tcp", "target.example:443")
				if err != nil {
					t.Fatal(err)
				}
				held.Store(true)
				if _, err := conn.Write(make([]byte, size-1)); err != nil {
					t.Fatal(err)
				}
				_ = netproxy.CloseWrite(conn)
				_ = conn.Close()
				parentLease.Invalidate(errors.New("parent got GOAWAY"))
				synctest.Wait()
				if _, err := open.Write([]byte{0}); err == nil {
					t.Fatal("a stream open on the closing session accepted a write")
				}
				start := time.Now()
				if err := mux.Connect(t.Context()); err != nil {
					t.Fatal(err)
				}
				if waited := time.Since(start); waited != 0 {
					t.Fatalf("replacing the session took %v", waited)
				}
				close(release)
				if err := <-got; err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

// Failure of the warm spare must request recovery even before another user
// arrives, otherwise the next lane would have to share a busy carrier.
func TestPoolRecoversFailedWarmSpare(t *testing.T) {
	h := newPoolHarness(t, DefaultMaxConnections, nil)
	h.open(t.Context())
	h.replenish()
	if err := h.server(1).Close(); err != nil {
		t.Fatal(err)
	}
	h.waitFor("spare recovery", func(e netproxy.StateEvent) bool {
		return e.RecoveryRequired && e.UsableCapacity == 1
	})
	h.replenish()
	h.openUDP(t.Context(), false)
	if lanes, loads := h.lanes(), h.loads(); lanes[1] != laneInteractive || loads[1] != 1 {
		t.Fatalf("game did not use recovered spare: lanes=%v loads=%v", lanes, loads)
	}
}
