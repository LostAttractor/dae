// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type pressurePacketDialer struct {
	started, ended chan struct{}
	opened         atomic.Int32
}

func (*pressurePacketDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected TCP dial")
}
func (d *pressurePacketDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d.opened.Add(1)
	return &pressurePacketConn{PacketConn: conn, owner: d}, nil
}

type pressurePacketConn struct {
	net.PacketConn
	owner *pressurePacketDialer
}

func (c *pressurePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.owner.started <- struct{}{}
	defer func() { c.owner.ended <- struct{}{} }()
	return c.PacketConn.ReadFrom(p)
}

func TestUDPSocketPressurePlateausAndReleasesReaders(t *testing.T) {
	const capacity = 96
	countFDs := func() int {
		t.Helper()
		files, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(files)
	}
	// The fixed population exercises both the per-source and shared limits using
	// real sockets and blocked readers. Additional destinations must add neither.
	beforeFD, beforeG := countFDs(), runtime.NumGoroutine()
	dialer := &pressurePacketDialer{started: make(chan struct{}, capacity), ended: make(chan struct{}, capacity)}
	p := &UdpEndpointPool{resources: netproxy.NewPacketBudget(capacity)}
	defer p.closeAll()
	sources := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:30001"), netip.MustParseAddrPort("203.0.113.1:30002")}
	endpoints := make([]*UdpEndpoint, len(sources))
	for i, src := range sources {
		endpoint, _ := resourceUDPEndpoint(t, src)
		endpoint.packetDialer = dialer
		endpoints[i] = endpoint
		p.add(src, endpoint)
	}
	admit := func(n int) {
		for i, src := range sources {
			lock, _ := p.UdpEndpointKeyLocker.Lock(src)
			_, err := endpoints[i].socket(t.Context(), p, src, netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(n >> 8), byte(n)}), 443))
			p.UdpEndpointKeyLocker.Unlock(src, lock)
			if err != nil && netproxy.ClassifyFailure(err).Reason != netproxy.ReasonCapacity {
				t.Fatal(err)
			}
		}
	}
	for n := range 128 {
		admit(n)
	}
	for range capacity {
		select {
		case <-dialer.started:
		case <-time.After(5 * time.Second):
			t.Fatal("reader did not start")
		}
	}
	atCapacityFD, atCapacityG := countFDs(), runtime.NumGoroutine()
	for n := 128; n < 2048; n++ {
		admit(n)
	}
	if dialer.opened.Load() != capacity || countFDs() > atCapacityFD || runtime.NumGoroutine() > atCapacityG+2 {
		t.Fatalf("additional targets grew resources: sockets=%d fd=%d->%d goroutines=%d->%d", dialer.opened.Load(), atCapacityFD, countFDs(), atCapacityG, runtime.NumGoroutine())
	}
	for _, endpoint := range endpoints {
		if len(endpoint.sockets) > maxUDPSocketsPerSource || len(endpoint.destinations) > maxUDPDestinationsPerSource {
			t.Fatal("source exceeded cache/socket limits")
		}
	}
	p.closeAll()
	for range capacity {
		select {
		case <-dialer.ended:
		case <-time.After(5 * time.Second):
			t.Fatal("closed socket left a blocked reader")
		}
	}
	if after := countFDs(); after > beforeFD+2 {
		t.Fatalf("socket descriptors were not released: %d->%d", beforeFD, after)
	}
	t.Logf("fixed limit %d: fd delta=%d, reader/goroutine delta=%d; 4096 target attempts", capacity, atCapacityFD-beforeFD, atCapacityG-beforeG)
}
