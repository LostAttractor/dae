package control

import (
	"net"
	"testing"
	"time"
)

func TestAnyfromRefreshSurvivesPendingExpiry(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	conn := &Anyfrom{UDPConn: udp, idleTTL: time.Minute}
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
	if _, err := conn.WriteToUDPAddrPort([]byte("reply"), addr); err != nil {
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
