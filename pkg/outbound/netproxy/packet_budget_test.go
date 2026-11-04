package netproxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"testing/synctest"
)

type budgetTestConn struct {
	net.PacketConn
	closing chan struct{}
	release chan struct{}
}

func (c *budgetTestConn) Close() error {
	close(c.closing)
	<-c.release
	return nil
}

func TestPacketBudgetUsageIncludesOpeningAndClosing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := NewPacketBudget(2)
		check := func(want int) {
			t.Helper()
			if used, limit := budget.Usage(); used != want || limit != 2 {
				t.Fatalf("usage = %d/%d, want %d/2", used, limit, want)
			}
		}
		check(0)
		opening, releaseOpen := make(chan struct{}), make(chan struct{})
		raw := &budgetTestConn{closing: make(chan struct{}), release: make(chan struct{})}
		unblockOpen := sync.OnceFunc(func() { close(releaseOpen) })
		unblockClose := sync.OnceFunc(func() { close(raw.release) })
		defer unblockOpen()
		defer unblockClose()
		var conn net.PacketConn
		go func() {
			var err error
			conn, err = budget.Open(t.Context(), "fixture", func(context.Context, string) (net.PacketConn, error) {
				close(opening)
				<-releaseOpen
				return raw, nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
		<-opening
		check(1)
		unblockOpen()
		synctest.Wait()
		check(1)
		go func() { _ = conn.Close() }()
		<-raw.closing
		check(1)
		unblockClose()
		synctest.Wait()
		check(0)
	})
}
