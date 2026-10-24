package singmux

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	xtacismux "github.com/xtaci/smux"
)

// isolatedSynctest runs f in a synctest bubble in its own process. smux pools
// result channels globally, so channels must never cross bubble boundaries.
func isolatedSynctest(t *testing.T, f func(*testing.T)) {
	const child = "DAE_SINGMUX_SYNCTEST_CHILD"
	if os.Getenv(child) != t.Name() {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), child+"="+t.Name())
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated %s: %v\n%s", t.Name(), err, output)
		}
		return
	}
	synctest.Test(t, f)
}

// poolHarness serves every dialed session and drives the pool only through
// its public operations; Connect stands in for the recovery coordinator.
type poolHarness struct {
	t        *testing.T
	parent   *pipeDialer
	dialer   *Mux
	accepted chan *xtacismux.Session
	servers  []*xtacismux.Session
}

func newPoolHarness(t *testing.T, maxConnections int, wrapClient func(int, net.Conn) net.Conn) *poolHarness {
	h := &poolHarness{
		t:        t,
		parent:   &pipeDialer{server: make(chan net.Conn), wrapClient: wrapClient},
		accepted: make(chan *xtacismux.Session, 4*MaxConnectionsLimit),
	}
	h.dialer = &Mux{Dialer: h.parent, MaxConnections: maxConnections}
	served := make(chan struct{})
	go func() {
		defer close(served)
		for server := range h.parent.server {
			config := xtacismux.DefaultConfig()
			config.KeepAliveDisabled = true
			if _, err := io.ReadFull(server, make([]byte, 2)); err != nil {
				_ = server.Close()
				continue
			}
			session, err := xtacismux.Server(server, config)
			if err != nil {
				_ = server.Close()
				continue
			}
			h.accepted <- session
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
func (h *poolHarness) server(index int) *xtacismux.Session {
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

func TestPoolExpandsAtStreamThreshold(t *testing.T) {
	h := newPoolHarness(t, 4, nil)
	ctx := t.Context()
	h.openN(ctx, expandStreams)
	if h.dialer.Snapshot().RecoveryRequired {
		t.Fatalf("pool expanded below the stream threshold: loads=%v", h.loads())
	}
	h.open(ctx)
	if !h.dialer.Snapshot().RecoveryRequired {
		t.Fatal("loaded pool did not request another session")
	}
	h.replenish()
	h.openN(ctx, expandStreams)
	if loads := h.loads(); h.dials() != 2 || len(loads) != 2 || loads[1] != expandStreams || h.dialer.Snapshot().RecoveryRequired {
		t.Fatalf("new session was not filled before expanding again: dials=%d loads=%v", h.dials(), loads)
	}
	for range 8 * expandStreams {
		h.open(ctx)
		h.replenish()
	}
	loads := h.loads()
	if h.dials() != 4 || len(loads) != 4 {
		t.Fatalf("pool ignored its limit: dials=%d loads=%v", h.dials(), loads)
	}
	for _, load := range loads {
		if load < expandStreams {
			t.Fatalf("streams were not distributed: %v", loads)
		}
	}
}

func TestPoolCoalescesConcurrentExpansion(t *testing.T) {
	h := newPoolHarness(t, MaxConnectionsLimit, nil)
	h.openN(t.Context(), expandStreams)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() { h.open(t.Context()) })
	}
	wg.Wait()
	if loads := h.loads(); len(loads) != 2 {
		t.Fatalf("concurrent opens activated %d slots (loads=%v), want one outstanding request", len(loads), loads)
	}
	h.replenish()
	if dials := h.dials(); dials != 2 {
		t.Fatalf("burst dialed %d sessions, want 2", dials)
	}
}

func TestPoolConnectivityChecksDoNotExpand(t *testing.T) {
	h := newPoolHarness(t, 4, nil)
	check := netproxy.WithConnectivityCheck(t.Context())
	var wg sync.WaitGroup
	for range 2 * expandStreams {
		wg.Go(func() { h.open(check) })
	}
	wg.Wait()
	if loads := h.loads(); h.dialer.Snapshot().RecoveryRequired || len(loads) != 1 {
		t.Fatalf("connectivity checks expanded the pool: loads=%v", loads)
	}
	// Open check streams do not count towards the user stream threshold.
	h.openN(t.Context(), expandStreams)
	if h.dialer.Snapshot().RecoveryRequired {
		t.Fatalf("check streams made user traffic expand the pool: loads=%v", h.loads())
	}
	h.open(t.Context())
	if !h.dialer.Snapshot().RecoveryRequired {
		t.Fatal("user stream on a loaded session did not expand the pool")
	}
}

func TestPoolRetiresIdleExtraSessions(t *testing.T) {
	isolatedSynctest(t, func(t *testing.T) {
		h := newPoolHarness(t, 4, nil)
		ctx := t.Context()
		base := h.openN(ctx, expandStreams+1)
		h.replenish()
		h.open(ctx).Close()
		// A check stream on the extra session does not keep it alive.
		time.Sleep(idleTimeout - 10*time.Second)
		h.open(netproxy.WithConnectivityCheck(ctx)).Close()
		if loads := h.loads(); len(loads) != 2 || loads[1] != 0 {
			t.Fatalf("extra session retired early: loads=%v", loads)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		state := h.dialer.Snapshot()
		if loads := h.loads(); len(loads) != 1 || state.UsableCapacity != 1 || state.RecoveryRequired {
			t.Fatalf("idle extra session was kept: loads=%v state=%+v", loads, state)
		}
		peer := h.server(1)
		_ = peer.SetDeadline(time.Now().Add(time.Second))
		for {
			_, err := peer.AcceptStream()
			if err == xtacismux.ErrTimeout {
				t.Fatal("retired session is still open at the peer")
			}
			if err != nil {
				break
			}
		}
		// The base session is kept, and retirement is not an outage.
		closeAll(base)
		time.Sleep(2 * idleTimeout)
		synctest.Wait()
		if state := h.dialer.Snapshot(); len(h.loads()) != 1 || !state.Accepting || state.EpisodeID != 0 || h.dials() != 2 {
			t.Fatalf("base session changed: loads=%v dials=%d state=%+v", h.loads(), h.dials(), state)
		}
	})
}

func TestPoolRefillsOnlyBusyFailedSessions(t *testing.T) {
	h := newPoolHarness(t, 2, nil)
	ctx := t.Context()
	h.openN(ctx, expandStreams+1)
	h.replenish()
	busy := h.open(ctx)
	if loads := h.loads(); loads[1] != 1 {
		t.Fatalf("stream did not use the new session: %v", loads)
	}

	// A failed session carrying streams is refilled while they remain.
	if err := h.server(1).Close(); err != nil {
		t.Fatal(err)
	}
	h.waitFor("busy failure", func(state netproxy.StateEvent) bool {
		return state.RecoveryRequired && state.UsableCapacity == 1
	})
	if state := h.dialer.Snapshot(); state.State != netproxy.SessionConnected || !state.Accepting {
		t.Fatalf("one failed session took the pool down: %+v", state)
	}
	// Once its streams are gone it is retired, not refilled.
	_ = busy.Close()
	h.waitFor("retirement", func(state netproxy.StateEvent) bool { return !state.RecoveryRequired && state.EpisodeID == 1 })
	if err := h.dialer.Connect(ctx); err != nil || h.dials() != 2 || len(h.loads()) != 1 {
		t.Fatalf("drained failed session was refilled: err=%v dials=%d loads=%v", err, h.dials(), h.loads())
	}

	// An idle extra session that fails is retired at once.
	h.open(ctx)
	h.replenish()
	if h.dials() != 3 {
		t.Fatalf("load did not expand the pool again: dials=%d", h.dials())
	}
	if err := h.server(2).Close(); err != nil {
		t.Fatal(err)
	}
	h.waitFor("idle failure", func(state netproxy.StateEvent) bool {
		return state.EpisodeID == 2 && !state.RecoveryRequired
	})
	if err := h.dialer.Connect(ctx); err != nil || h.dials() != 3 || len(h.loads()) != 1 {
		t.Fatalf("idle failed session was refilled: err=%v dials=%d loads=%v", err, h.dials(), h.loads())
	}
}

func TestPoolKeepsSoleUsableIdleSession(t *testing.T) {
	isolatedSynctest(t, func(t *testing.T) {
		h := newPoolHarness(t, 2, nil)
		closeAll(h.openN(t.Context(), expandStreams+1))
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
