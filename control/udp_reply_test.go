// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/trojanc"
)

func TestUDPDomainReplyReturnsError(t *testing.T) {
	for _, mode := range []string{"relay", "destination"} {
		t.Run(mode, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			var frame bytes.Buffer
			if err := socks5.WriteAddr("reply.example:443", &frame); err != nil {
				t.Fatal(err)
			}
			frame.Write(binary.BigEndian.AppendUint16(nil, 1))
			frame.WriteString("\r\nx")
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = right.Write(frame.Bytes())
				_ = right.Close()
			}()
			defer func() { _ = left.Close(); <-done }()
			packet := &trojanc.PacketConn{Conn: left}
			defer packet.Close()
			source := netip.MustParseAddrPort("192.0.2.1:1000")
			target := netip.MustParseAddrPort("192.0.2.2:443")
			var err error
			if mode == "destination" {
				conn := newDestinationConn(packet, target, target)
				_, _, err = conn.ReadFrom(make([]byte, 100))
			} else {
				endpoint := &UdpEndpoint{conn: packet, NatTimeout: time.Minute, replies: UdpHandler(func([]byte, netip.AddrPort) error {
					t.Error("forwarded a reply without an IP address")
					return nil
				})}
				defer endpoint.Close()
				err = endpoint.run(new(UdpEndpointPool), source, target, packet, nil)
			}
			if err == nil || !strings.Contains(err.Error(), "reply.example") {
				t.Fatalf("domain reply error = %v", err)
			}
		})
	}
}

// A dual-stack reader returns mapped IPv4; the shared reply pool must still
// use the same socket as proxied replies, and retain the first target's domain.
func TestUDPReplyMappedAddressUsesCanonicalPoolSocket(t *testing.T) {
	listen := func(network string, addr *net.UDPAddr) *net.UDPConn {
		t.Helper()
		conn, err := net.ListenUDP(network, addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	outbound := listen("udp", nil)
	peer := listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	client := listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: outbound.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteTo([]byte("reply"), to); err != nil {
		t.Fatal(err)
	}
	_ = outbound.SetReadDeadline(time.Now().Add(time.Second))
	var buf [16]byte
	n, raw, err := outbound.ReadFromUDP(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if !raw.AddrPort().Addr().Is4In6() {
		t.Fatalf("fixture returned %v, want mapped IPv4", raw)
	}
	from := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	src := client.LocalAddr().(*net.UDPAddr).AddrPort()
	pool := NewAnyfromPool()
	socket := &Anyfrom{conn: peer, idleTTL: time.Hour}
	pool.pool[from] = socket
	endpoints := new(UdpEndpointPool)
	defer endpoints.closeAll()
	sender := &udpReplySender{pool: pool, to: src}
	ue := &UdpEndpoint{conn: outbound, firstDst: from, domain: "cdn.example", activity: new(domainActivity),
		NatTimeout: time.Hour, replies: sender}
	endpoints.add(src, ue)
	failed := dropReplySendFailed.Load()
	for _, mode := range []string{"pulled_udpaddr", "pulled_parsed", "pushed_inline", "pushed_queued"} {
		address := raw.AddrPort()
		if strings.HasPrefix(mode, "pulled_") {
			var addr net.Addr = raw
			if mode == "pulled_parsed" {
				addr = netproxy.NewAddr("udp", raw.String())
			}
			address, err = addrPortOf(addr)
			if err != nil || address != from {
				t.Fatalf("addrPortOf(%v) = %v, %v; want %v", addr, address, err, from)
			}
		}
		sender.cached.Store(nil)
		// An exclusive GetOrCreate would wait behind this read lock.
		pool.mu.RLock()
		sent := make(chan error, 1)
		go func() {
			if strings.HasPrefix(mode, "pushed_") {
				r := &udpPushReceiver{ue: ue, p: endpoints, src: src, conn: outbound, draining: mode == "pushed_queued"}
				r.onPacket(buf[:n], address)
				if mode == "pushed_queued" {
					r.drain()
				}
				sent <- nil
				return
			}
			done, err := ue.deliver(endpoints, src, outbound, nil, buf[:n], address, true)
			if done && err == nil {
				err = errors.New("reply ended the association")
			}
			sent <- err
		}()
		select {
		case err := <-sent:
			pool.mu.RUnlock()
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			pool.mu.RUnlock()
			t.Fatal("mapped reply entered GetOrCreate instead of using the pooled socket")
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		var reply [16]byte
		if n, source, err := client.ReadFromUDPAddrPort(reply[:]); err != nil || source != from || string(reply[:n]) != "reply" {
			t.Fatalf("reply from %v = %q, %v", source, reply[:n], err)
		}
	}
	if len(pool.pool) != 1 || sender.cached.Load().socket != socket || dropReplySendFailed.Load() != failed {
		t.Fatal("mapped reply created a second socket or counted a failed send")
	}
	if target := ue.activityTargets[from]; len(ue.activityTargets) != 1 || target.key.domain != "cdn.example." {
		t.Fatalf("reply lost its domain: %+v", ue.activityTargets)
	}
}

func TestUDPReplyMissingAddress(t *testing.T) {
	for _, address := range []net.Addr{nil, (*net.UDPAddr)(nil), new(net.UDPAddr)} {
		if _, err := addrPortOf(address); err == nil {
			t.Fatalf("accepted missing IP address: %v", address)
		}
	}
}

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

// trySend sends from an existing socket of the reply address, cached or
// pooled, and caches the first; it never creates a socket, falls back to raw
// sends or waits for the pool.
func TestUDPReplyTrySendUsesOnlyExistingSockets(t *testing.T) {
	listen := func() *net.UDPConn {
		t.Helper()
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		return socket
	}
	receiver, first, second := listen(), listen(), listen()
	from := first.LocalAddr().(*net.UDPAddr).AddrPort()
	other := second.LocalAddr().(*net.UDPAddr).AddrPort()
	pool := NewAnyfromPool()
	sender := &udpReplySender{pool: pool, to: receiver.LocalAddr().(*net.UDPAddr).AddrPort()}
	if err := sender.trySend([]byte("reply"), netip.MustParseAddrPort("192.0.2.1:443")); !errors.Is(err, errReplyWouldBlock) || len(pool.pool) != 0 {
		t.Fatalf("trySend without a socket = %v, want slow path without creating a socket", err)
	}
	pool.pool[from] = &Anyfrom{conn: first, idleTTL: time.Hour}
	pool.pool[other] = &Anyfrom{conn: second, idleTTL: time.Hour}
	read := func(want netip.AddrPort) {
		t.Helper()
		var buffer [16]byte
		_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
		if n, source, err := receiver.ReadFromUDPAddrPort(buffer[:]); err != nil || source != want || string(buffer[:n]) != "reply" {
			t.Fatalf("reply from %s: %q, %v; want from %s", source, buffer[:n], err, want)
		}
	}
	for _, address := range []netip.AddrPort{from, other} {
		if err := sender.trySend([]byte("reply"), address); err != nil {
			t.Fatalf("trySend from the pooled socket of %s: %v", address, err)
		}
		read(address)
	}
	if cached := sender.cached.Load(); cached == nil || cached.from != from {
		t.Fatal("trySend did not cache only the first reply address")
	}
	// A locked pool, as while a socket is created, is not waited for.
	pool.mu.Lock()
	pooled, cached := sender.trySend([]byte("reply"), other), sender.trySend([]byte("reply"), from)
	pool.mu.Unlock()
	if !errors.Is(pooled, errReplyWouldBlock) || cached != nil {
		t.Fatalf("with the pool locked, trySend from the pool = %v, from the cache = %v", pooled, cached)
	}
	read(from)
}

// A reply that cannot be sent is lost, counted once, and the association
// goes on: the next reply is delivered and the reader keeps running.
func TestUDPReplySendFailureKeepsTheAssociation(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	results := []error{errors.New("no route to the client"), netproxy.ErrPacketDropped, nil}
	delivered := make(chan string, len(results))
	ue := &UdpEndpoint{conn: conn, NatTimeout: time.Minute, replies: UdpHandler(func(data []byte, _ netip.AddrPort) error {
		err := results[0]
		results = results[1:]
		if err == nil {
			delivered <- string(data)
		}
		return err
	})}
	p := new(UdpEndpointPool)
	src, dst := netip.MustParseAddrPort("192.0.2.1:1000"), peer.LocalAddr().(*net.UDPAddr).AddrPort()
	p.add(src, ue)
	ended := make(chan error, 1)
	failed, dropped := dropReplySendFailed.Load(), dropReplySocketFull.Load()
	go func() { ended <- ue.run(p, src, dst, conn, nil) }()
	for _, reply := range []string{"failed", "dropped", "delivered"} {
		if _, err := peer.WriteTo([]byte(reply), conn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case got := <-delivered:
		if got != "delivered" {
			t.Fatalf("delivered %q", got)
		}
	case err := <-ended:
		t.Fatalf("delivery ended: %v", err)
	case <-time.After(time.Second):
		t.Fatal("the reply after a failed one was not delivered")
	}
	if dropReplySendFailed.Load()-failed != 1 || dropReplySocketFull.Load() != dropped {
		t.Fatalf("counted %d failed sends and %d full sockets, want 1 and 0 (the sender counts its own)", dropReplySendFailed.Load()-failed, dropReplySocketFull.Load()-dropped)
	}
	p.remove(src, ue)
	if err := <-ended; err != nil {
		t.Fatalf("delivery ended with %v", err)
	}
}
