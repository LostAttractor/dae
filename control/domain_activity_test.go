// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
)

func TestTCPDomainActivityPreservesDataAndHalfClose(t *testing.T) {
	accepted, peer := relayTestTCPPair(t)
	now := time.Now()
	g, fake := newTestRegistry(1, time.Minute)
	ip := netip.MustParseAddr("192.0.2.1")
	domain, unrelated := "a.example.", "b.example."
	g.Upsert(domain, ip, testBitmap(0), 1, now)
	g.Upsert(unrelated, ip, testBitmap(), 1, now)
	request := "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"
	if _, err := io.WriteString(peer, request); err != nil {
		t.Fatal(err)
	}
	sniffer := sniffing.NewConnSniffer(accepted, time.Second)
	sniffed, err := sniffer.SniffTcp()
	if err != nil || sniffed != "a.example" {
		t.Fatalf("sniff=%q: %v", sniffed, err)
	}
	at := now.Add(50 * time.Second)
	activity := g.activity
	key := newDomainActivityKey(ip, sniffed)
	conn := &activitySniffer{sniffer, func() { activity.enqueue(key, at) }}
	defer conn.Close()
	buf := make([]byte, len(request))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != request {
		t.Fatalf("buffered client data changed: %q %v", buf, err)
	}
	g.flushActivity()
	if !g.retention(domain, ip).Equal(now.Add(110*time.Second)) || !g.retention(unrelated, ip).Equal(now.Add(time.Minute)) {
		t.Fatal("client I/O did not precisely refresh retention")
	}
	// Keep the actual accepted connection and its original callback across the
	// same handoff used by reload. The new window applies only to later I/O.
	activity.prepareHandoff()
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	next, _ := newTestRegistry(1, 2*time.Minute)
	next.kernel.update, next.kernel.remove = fake.update, fake.remove
	next.AdoptFrom(g, func(name string) []uint32 {
		if name == domain {
			return testBitmap(1)
		}
		return testBitmap()
	}, now.Add(55*time.Second))
	if !next.retention(domain, ip).Equal(now.Add(110 * time.Second)) {
		t.Fatal("reload changed an existing deadline")
	}
	at = now.Add(100 * time.Second)
	if _, err := conn.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	next.flushActivity()
	if !next.retention(domain, ip).Equal(now.Add(220*time.Second)) || !g.retention(domain, ip).Equal(now.Add(110*time.Second)) {
		t.Fatal("continued downstream I/O did not retain the long connection's evidence")
	}
	if unwrapSniffer(conn) != accepted {
		t.Fatal("native socket identity was hidden")
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := peer.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("half-close lost: %d %v", n, err)
	}
	next.Sweep(now.Add(220 * time.Second))
	if next.Size() != 0 {
		t.Fatal("idle connection kept extending evidence")
	}
}

func TestUDPContinuedActivityUsesEachOriginalDestination(t *testing.T) {
	g, _ := newTestRegistry(2, time.Minute)
	now := time.Now().Add(-50 * time.Second)
	first, other := netip.MustParseAddrPort("192.0.2.1:443"), netip.MustParseAddrPort("192.0.2.2:4443")
	a, b := "a.example.", "b.example."
	for _, ip := range []netip.Addr{first.Addr(), other.Addr()} {
		g.Upsert(a, ip, testBitmap(0), 1, now)
		g.Upsert(b, ip, testBitmap(), 1, now)
	}
	ue := &UdpEndpoint{conn: newTestPacketConn(false), activity: g.activity, firstDst: first, domain: "a.example"}
	defer ue.conn.Close()
	c := &ControlPlane{}
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	if err := c.writeUDP(context.Background(), ue, src, first, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if !g.retention(a, first.Addr()).After(now.Add(time.Minute)) || !g.retention(b, first.Addr()).Equal(now.Add(time.Minute)) {
		t.Fatal("first target lost precise sniff context")
	}
	if err := c.writeUDP(context.Background(), ue, src, other, []byte("other")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{a, b} {
		if !g.retention(name, other.Addr()).After(now.Add(time.Minute)) {
			t.Fatal("later unnamed destination did not refresh all its pairs")
		}
	}
	firstDeadline := g.retention(a, first.Addr())
	otherDeadline := g.retention(b, other.Addr())
	if err := c.writeUDP(context.Background(), ue, src, first, []byte("continued")); err != nil {
		t.Fatal(err)
	}
	// Receive-side accounting uses the same per-destination observation path.
	ue.observeDomain(other)
	if !g.retention(a, first.Addr()).Equal(firstDeadline) || !g.retention(b, other.Addr()).Equal(otherDeadline) {
		t.Fatal("continued UDP traffic applied synchronously")
	}
	g.flushActivity()
	if !g.retention(a, first.Addr()).After(firstDeadline) || !g.retention(b, other.Addr()).After(otherDeadline) || !g.retention(b, first.Addr()).Equal(now.Add(time.Minute)) {
		t.Fatal("continued UDP batch lost original target/name scope")
	}
}

func TestUnfinishedUDPSniffRetainsObservedActivity(t *testing.T) {
	g, _ := newTestRegistry(1, time.Minute)
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	name := "example.org."
	g.Upsert(name, ip, testBitmap(0), 1, now)
	ue := &UdpEndpoint{
		activity: g.activity, firstDst: netip.AddrPortFrom(ip, 443),
		pending: &udpSetup{sniffer: sniffing.NewPacketSniffer(nil), observedAt: now.Add(30 * time.Second)},
	}
	// A partial QUIC handshake may time out before routing. Retirement still
	// accounts for the received packet, using its timestamp rather than now.
	ue.retire()
	if !g.retention(name, ip).Equal(now.Add(90 * time.Second)) {
		t.Fatal("unfinished sniff lost client activity")
	}
}
