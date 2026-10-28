package control

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func newTestAnyfromPool(t *testing.T, limit int) *AnyfromPool {
	t.Helper()
	p := NewAnyfromPool()
	if p.limit != maxUDPSources {
		t.Fatalf("default reply socket limit = %d, want %d", p.limit, maxUDPSources)
	}
	p.limit = limit
	p.listen = func(netip.AddrPort) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	t.Cleanup(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, conn := range p.pool {
			conn.idleEvictTimer.Stop()
			_ = conn.Close()
		}
	})
	return p
}

func TestAnyfromPoolBoundsConcurrentCreators(t *testing.T) {
	p := newTestAnyfromPool(t, 3)
	cachedAddr := netip.MustParseAddrPort("192.0.2.1:53")
	cached, _, err := p.GetOrCreate(cachedAddr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	listen := p.listen
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var calls atomic.Int32
	p.listen = func(addr netip.AddrPort) (*net.UDPConn, error) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return listen(addr)
	}
	type result struct {
		conn  *Anyfrom
		isNew bool
		err   error
	}
	results := make(chan result, 3)
	create := func(addr netip.AddrPort) {
		conn, isNew, err := p.GetOrCreate(addr, time.Hour)
		results <- result{conn, isNew, err}
	}
	first := netip.MustParseAddrPort("192.0.2.2:53")
	second := netip.MustParseAddrPort("192.0.2.3:53")
	go create(first)
	go create(second)
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("another address's creation blocked behind ListenPacket")
		}
	}
	if p.TryGet(cachedAddr) != cached {
		t.Fatal("ListenPacket prevented reuse of an existing reply socket")
	}
	// A caller of the same address shares its reservation, even at capacity.
	go create(first)
	dropped := dropReplySocketLimit.Load()
	sender := &udpReplySender{pool: p, to: cachedAddr}
	if err := sender.send([]byte("reply"), netip.MustParseAddrPort("192.0.2.4:53")); !errors.Is(err, netproxy.ErrPacketDropped) {
		t.Fatalf("reply beyond capacity = %v", err)
	}
	if got := dropReplySocketLimit.Load() - dropped; got != 1 {
		t.Fatalf("counted %d admission drops, want 1", got)
	}
	unblock()
	unique := make(map[*Anyfrom]int)
	created := 0
	for range 3 {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatal(result.err)
			}
			unique[result.conn]++
			if result.isNew {
				created++
			}
		case <-time.After(time.Second):
			t.Fatal("reply socket creator or waiter did not finish")
		}
	}
	if len(unique) != 2 || created != 2 || calls.Load() != 2 {
		t.Fatalf("created %d sockets (%d unique) with %d listens", created, len(unique), calls.Load())
	}
	if got, isNew, err := p.GetOrCreate(cachedAddr, time.Second); err != nil || got != cached || isNew {
		t.Fatalf("reuse at capacity = %p, %v, %v", got, isNew, err)
	}
}

func TestAnyfromPoolFailedCreationReleasesReservation(t *testing.T) {
	p := newTestAnyfromPool(t, 1)
	listen := p.listen
	p.listen = func(netip.AddrPort) (*net.UDPConn, error) { return nil, syscall.EMFILE }
	addr := netip.MustParseAddrPort("192.0.2.1:53")
	if _, _, err := p.GetOrCreate(addr, time.Hour); !errors.Is(err, syscall.EMFILE) {
		t.Fatalf("creation failure = %v", err)
	}
	if len(p.creating) != 0 || len(p.pool) != 0 {
		t.Fatal("failed creation retained a slot")
	}
	p.listen = listen
	if _, _, err := p.GetOrCreate(addr, time.Hour); err != nil {
		t.Fatalf("retry after creation failure: %v", err)
	}
}

func TestAnyfromPoolCreationFailureWakesWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestAnyfromPool(t, 1)
		listen := p.listen
		release := make(chan struct{})
		calls := 0
		p.listen = func(addr netip.AddrPort) (*net.UDPConn, error) {
			calls++
			if calls == 1 {
				<-release
				return nil, syscall.EMFILE
			}
			return listen(addr)
		}
		results := make(chan error, 2)
		create := func() {
			_, _, err := p.GetOrCreate(netip.MustParseAddrPort("192.0.2.1:53"), time.Hour)
			results <- err
		}
		go create()
		synctest.Wait()
		go create()
		synctest.Wait()
		if calls != 1 {
			t.Fatalf("same-address waiter started a second listener: %d", calls)
		}
		close(release)
		errorsSeen := 0
		for range 2 {
			if err := <-results; errors.Is(err, syscall.EMFILE) {
				errorsSeen++
			} else if err != nil {
				t.Fatal(err)
			}
		}
		if errorsSeen != 1 || calls != 2 || len(p.pool) != 1 || len(p.creating) != 0 {
			t.Fatal("failed creator did not release its slot and wake its waiter")
		}
	})
}

func TestAnyfromPoolCloseReplacementAndExpiryReleaseCapacity(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			p := newTestAnyfromPool(t, 1)
			addr := netip.MustParseAddrPort("192.0.2.1:53")
			old, _, err := p.GetOrCreate(addr, ttl)
			if err != nil {
				t.Fatal(err)
			}
			if old.idleTTL != DefaultAnyfromCacheTTL {
				t.Fatalf("normalized TTL = %v", old.idleTTL)
			}
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			if p.TryGet(addr) != nil {
				t.Fatal("TryGet returned a closed socket")
			}
			next, isNew, err := p.GetOrCreate(addr, ttl)
			if err != nil || next == old || !isNew {
				t.Fatalf("closed socket replacement = %p, %v, %v", next, isNew, err)
			}
			p.expire(addr, old)
			if p.TryGet(addr) != next {
				t.Fatal("old callback removed its successor")
			}
			next.idleMu.Lock()
			next.idleDeadline = time.Now().Add(-time.Second)
			next.idleMu.Unlock()
			p.expire(addr, next)
			next.idleEvictTimer.Stop()
			if !next.closed.Load() {
				t.Fatal("expiry did not close the socket")
			}
			if _, _, err := p.GetOrCreate(netip.MustParseAddrPort("192.0.2.2:53"), time.Hour); err != nil {
				t.Fatalf("expiry did not release capacity: %v", err)
			}
		})
	}
}

func TestAnyfromRefreshSurvivesPendingExpiry(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	conn := &Anyfrom{conn: udp, idleTTL: time.Minute}
	conn.idleEvictTimer = time.AfterFunc(time.Hour, func() {})
	defer conn.idleEvictTimer.Stop()
	p := NewAnyfromPool()
	addr := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	p.pool[addr] = conn
	conn.refreshIdleDeadline()
	// The previous timer callback runs after new activity has refreshed it.
	p.expire(addr, conn)
	if p.pool[addr] != conn {
		t.Fatal("pending expiry removed a recently active reply socket")
	}
	if _, err := conn.WriteToUDPAddrPortWithDeadline([]byte("reply"), addr, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("reply socket was closed: %v", err)
	}
	conn.idleMu.Lock()
	conn.idleDeadline = time.Now().Add(-time.Second)
	conn.idleMu.Unlock()
	p.expire(addr, conn)
	if len(p.pool) != 0 {
		t.Fatal("idle reply socket was not evicted")
	}
}

func TestAnyfromTimerFollowsActivity(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	synctest.Test(t, func(t *testing.T) {
		conn := &Anyfrom{conn: udp, idleTTL: 10 * time.Second}
		p := NewAnyfromPool()
		addr := udp.LocalAddr().(*net.UDPAddr).AddrPort()
		p.pool[addr] = conn
		conn.refreshIdleDeadline()
		conn.idleEvictTimer = time.AfterFunc(conn.idleTTL, func() { p.expire(addr, conn) })
		defer conn.idleEvictTimer.Stop()

		time.Sleep(9 * time.Second)
		conn.refreshIdleDeadline()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		p.mu.Lock()
		active := p.pool[addr] == conn
		p.mu.Unlock()
		if !active {
			t.Fatal("old timer deadline evicted an active reply socket")
		}
		time.Sleep(8 * time.Second)
		synctest.Wait()
		p.mu.Lock()
		remaining := len(p.pool)
		p.mu.Unlock()
		if remaining != 0 {
			t.Fatal("reply socket remained after its refreshed deadline")
		}
	})
}
