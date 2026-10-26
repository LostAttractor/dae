package singmux

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type reviewPauseConn struct {
	net.Conn
	armed   atomic.Bool
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (c *reviewPauseConn) unblock() { c.once.Do(func() { close(c.resume) }) }
func (c *reviewPauseConn) Write(b []byte) (int, error) {
	if c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.resume
	}
	return c.Conn.Write(b)
}
func (c *reviewPauseConn) Close() error { c.unblock(); return c.Conn.Close() }
func reviewPool(t *testing.T, count int) (*poolHarness, *reviewPauseConn) {
	t.Helper()
	var held *reviewPauseConn
	h := newPoolHarness(t, count, func(i int, c net.Conn) net.Conn {
		if i != 0 {
			return c
		}
		held = &reviewPauseConn{Conn: c, entered: make(chan struct{}), resume: make(chan struct{})}
		return held
	})
	t.Cleanup(held.unblock)
	return h, held
}
func reviewOpen(t *testing.T, p *sessionPool, ctx context.Context, l lane) *leasedStream {
	t.Helper()
	c, err := p.OpenStream(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*leasedStream)
}

func TestDrainingSpareQueuedAndInFlightFIN(t *testing.T) {
	for _, phase := range []string{"queued-tail", "inflight-fin"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h, held := reviewPool(t, 4)
				p := h.dialer.pool()
				st := reviewOpen(t, p, t.Context(), laneStream)
				peer, err := h.server(0).Accept()
				if err != nil {
					t.Fatal(err)
				}
				h.replenish()
				synctest.Wait()
				payload := bytes.Repeat([]byte{0x5a}, 8192)
				if phase == "queued-tail" {
					held.armed.Store(true)
				}
				if _, err := st.Write(payload); err != nil {
					t.Fatal(err)
				}
				if phase == "queued-tail" {
					<-held.entered
					tail := bytes.Repeat([]byte{0xa5}, 4096)
					if _, err := st.Write(tail); err != nil {
						t.Fatal(err)
					}
					payload = append(payload, tail...)
				} else {
					synctest.Wait()
					held.armed.Store(true)
				}
				if err := st.Close(); err != nil {
					t.Fatal(err)
				}
				if phase == "inflight-fin" {
					<-held.entered
				}
				game := reviewOpen(t, p, t.Context(), laneInteractive)
				p.mu.Lock()
				clean, connected := p.connectedHandleLocked(p.slots[1])
				p.mu.Unlock()
				if !connected || game.Conn.(*smuxStream).session != clean.Resource().session {
					t.Fatal("game did not select clean slot 1")
				}
				held.unblock()
				got, err := io.ReadAll(peer)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("tail changed: got %d bytes, want %d, err=%v", len(got), len(payload), err)
				}
				synctest.Wait()
				if lanes := h.lanes(); lanes[0] != laneSpare {
					t.Errorf("drained carrier did not become spare: %v", lanes)
				}
				h.replenish()
				if h.dialer.Snapshot().RecoveryRequired {
					t.Fatal("coordinator did not converge after drain")
				}
			})
		})
	}
}

func TestBusyHealthSpareIsStillUsableFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, held := reviewPool(t, 1)
		p := h.dialer.pool()
		held.armed.Store(true)
		reviewOpen(t, p, netproxy.WithConnectivityCheck(t.Context()), laneStream)
		<-held.entered
		for _, check := range []bool{true, false} {
			ctx := t.Context()
			if check {
				ctx = netproxy.WithConnectivityCheck(ctx)
			}
			c, err := p.OpenStream(ctx, laneInteractive)
			if err != nil {
				t.Errorf("check=%v: healthy sole carrier cannot open: %v", check, err)
			} else {
				_ = c.Close()
			}
		}
		held.unblock()
	})
}

func TestPendingHealthReservationIsNotCleanSpare(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, held := reviewPool(t, 4)
		p := h.dialer.pool()
		st := reviewOpen(t, p, t.Context(), laneInteractive)
		h.replenish()
		synctest.Wait()
		// Reserve a health open, then suspend it before session.OpenStream queues SYN.
		slot, _, err := p.reserve(netproxy.WithConnectivityCheck(t.Context()), nil, false, laneStream)
		if err != nil {
			t.Fatal(err)
		}
		defer p.release(slot, false)
		held.armed.Store(true)
		_ = st.Close()
		<-held.entered
		held.unblock()
		synctest.Wait()
		game := reviewOpen(t, p, t.Context(), laneBulk)
		if game.Conn.(*smuxStream).session == st.Conn.(*smuxStream).session {
			t.Error("selected slot 0 with pending health reservation over clean slot 1")
		}
	})
}

// Block the actual pipe write, not a wrapper wait that ignores deadlines.
type deadlineStallConn struct {
	net.Conn
	blocked net.Conn
	armed   atomic.Bool
}

func (c *deadlineStallConn) Write(b []byte) (int, error) {
	if c.armed.Load() {
		return c.blocked.Write(b)
	}
	return c.Conn.Write(b)
}
func (c *deadlineStallConn) SetWriteDeadline(t time.Time) error {
	if err := c.blocked.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}
func (c *deadlineStallConn) Close() error { _ = c.blocked.Close(); return c.Conn.Close() }

func TestPoolBlockedExtraSlotExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var held *deadlineStallConn
		h := newPoolHarness(t, DefaultMaxConnections, func(i int, c net.Conn) net.Conn {
			if i != 1 {
				return c
			}
			local, remote := net.Pipe()
			t.Cleanup(func() { _ = remote.Close() })
			held = &deadlineStallConn{Conn: c, blocked: local}
			return held
		})
		p := h.dialer.pool()
		reviewOpen(t, p, t.Context(), laneInteractive)
		h.replenish()
		st := reviewOpen(t, p, t.Context(), laneBulk)
		synctest.Wait()
		held.armed.Store(true)
		if _, err := st.Write(make([]byte, 16<<10)); err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		synctest.Wait()
		p.mu.Lock()
		if p.slots[1].draining == nil || p.slots[1].streams != 0 {
			t.Error("extra slot was not draining without users")
		}
		p.mu.Unlock()
		time.Sleep(netproxy.DialTimeout)
		synctest.Wait()
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.slots[1].lifecycle != nil {
			t.Fatal("failed extra slot retained its lifecycle")
		}
	})
}
