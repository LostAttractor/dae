// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestUDPReplyCacheRefreshAndReplacement(t *testing.T) {
	listen := func(address netip.AddrPort) *net.UDPConn {
		t.Helper()
		socket, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(address))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		return socket
	}
	receiver := listen(netip.MustParseAddrPort("127.0.0.1:0"))
	original := listen(netip.MustParseAddrPort("127.0.0.1:0"))
	from := original.LocalAddr().(*net.UDPAddr).AddrPort()
	pool := NewAnyfromPool()
	first := &Anyfrom{conn: original, idleTTL: time.Hour}
	pool.pool[from] = first
	sender := &udpReplySender{pool: pool, to: receiver.LocalAddr().(*net.UDPAddr).AddrPort()}
	send := func() {
		t.Helper()
		if err := sender.send([]byte("reply"), from); err != nil {
			t.Fatal(err)
		}
	}
	read := func(want netip.AddrPort) {
		t.Helper()
		receiver.SetReadDeadline(time.Now().Add(time.Second))
		var buffer [32]byte
		n, source, err := receiver.ReadFromUDPAddrPort(buffer[:])
		if err != nil || source != want || string(buffer[:n]) != "reply" {
			t.Fatalf("reply from %s: %q, %v", source, buffer[:n], err)
		}
	}
	send()
	read(from)
	// A warm reference needs no global pool lock, and still refreshes idle time.
	pool.mu.Lock()
	sent := make(chan error, 1)
	go func() { sent <- sender.send([]byte("reply"), from) }()
	var err error
	select {
	case err = <-sent:
	case <-time.After(time.Second):
		pool.mu.Unlock()
		t.Fatal("cached reply waited for global pool lock")
	}
	pool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	read(from)
	if sender.cached.Load().socket != first {
		t.Fatal("first socket not retained")
	}
	// A second peer must not churn the first-peer cache on every alternating reply.
	other := listen(netip.MustParseAddrPort("127.0.0.1:0"))
	otherAddr := other.LocalAddr().(*net.UDPAddr).AddrPort()
	pool.pool[otherAddr] = &Anyfrom{conn: other, idleTTL: time.Hour}
	if err := sender.send([]byte("reply"), otherAddr); err != nil {
		t.Fatal(err)
	}
	read(otherAddr)
	if sender.cached.Load().from != from {
		t.Fatal("additional peer churned cache")
	}
	first.idleMu.Lock()
	first.idleDeadline = time.Now().Add(-time.Second)
	first.idleMu.Unlock()
	pool.expire(from, first)
	if !first.closed.Load() || pool.pool[from] != nil {
		t.Fatal("cached reference prevented idle eviction")
	}
	replacement := listen(from)
	next := &Anyfrom{conn: replacement, idleTTL: time.Hour}
	pool.pool[from] = next
	send()
	read(from)
	if sender.cached.Load().socket != next {
		t.Fatal("cached expired socket survived replacement")
	}
}
