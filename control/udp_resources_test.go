// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func resourceUDPEndpoint(t *testing.T, source netip.AddrPort) (*UdpEndpoint, *destinationUDPRecorder) {
	t.Helper()
	matcher, _ := destinationTestMatcher(t, "dip(192.0.0.0/16) -> dnat(198.51.100.1)")
	matcher.destinationProgram(matcher.defaultProfileID).predicates[0].targets = []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")}
	recorder := new(destinationUDPRecorder)
	return &UdpEndpoint{
		packetDialer: recorder, destinationMatcher: matcher.snapshotDestinations(),
		destinationParam: RouteParam{Src: source, networkType: *common.NetworkUDP4.NetworkType(), routingResult: &routingResult{}},
		sockets:          make(map[netip.AddrPort]*udpSocket), NatTimeout: time.Hour,
		lease:    netproxy.NewLease(netproxy.ResourceRef{}),
		activity: &domainActivity{},
	}, recorder
}

func TestUDPResourcesBoundedWithoutChangingSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := netip.MustParseAddrPort("203.0.113.1:30000")
		endpoint, recorder := resourceUDPEndpoint(t, source)
		var p UdpEndpointPool
		p.add(source, endpoint)
		defer p.closeAll()
		destination := func(n int) netip.AddrPort {
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(n >> 8), byte(n)}), 443)
		}
		first := destination(1)
		endpoint.firstDst = first
		lock, _ := p.UdpEndpointKeyLocker.Lock(source)
		for n := range maxUDPSocketsPerSource {
			conn, err := endpoint.socket(t.Context(), &p, source, destination(n+1))
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				endpoint.conn = conn
			}
		}
		originalTarget := endpoint.destinations[first].target
		if _, err := endpoint.socket(t.Context(), &p, source, destination(1000)); netproxy.ClassifyFailure(err).Reason != netproxy.ReasonCapacity {
			t.Fatalf("socket admission: %v", err)
		}
		for n := range maxUDPDestinationsPerSource * 2 {
			if _, err := endpoint.socketTarget(destination(n + 1000)); err != nil {
				t.Fatal(err)
			}
			endpoint.observeDomain(destination(n + 1000))
		}
		if len(endpoint.destinations) != maxUDPDestinationsPerSource || len(endpoint.activityTargets) != maxUDPDestinationsPerSource || len(recorder.opened) != maxUDPSocketsPerSource {
			t.Fatal("unbounded source resources")
		}
		delete(endpoint.destinations, first)
		if target, err := endpoint.socketTarget(first); err != nil || target != originalTarget {
			t.Fatalf("cache eviction remapped DNAT: %v %v", target, err)
		}
		// The first socket may expire while another target keeps the source alive.
		now := time.Now()
		endpoint.mu.Lock()
		for key, child := range endpoint.sockets {
			if key != destination(maxUDPSocketsPerSource) {
				child.lastUsed = now.Add(-2 * udpChildIdleTimeout)
			}
		}
		endpoint.mu.Unlock()
		p.UdpEndpointKeyLocker.Unlock(source, lock)
		p.expireAt(source, endpoint, now)
		synctest.Wait()
		if current, ok := p.pool.Load(source); !ok || current != endpoint || endpoint.IsClosed() || len(endpoint.sockets) != 1 {
			t.Fatal("child expiry ended source lifetime")
		}
		for _, conn := range recorder.opened[:maxUDPSocketsPerSource-1] {
			select {
			case <-conn.closed:
			default:
				t.Fatal("idle child left open")
			}
			conn.lease.Abort(netproxy.ErrDependencyInvalid)
		}
		synctest.Wait()
		if endpoint.IsClosed() {
			t.Fatal("retired child watcher ended source lifetime")
		}
		lock, _ = p.UdpEndpointKeyLocker.Lock(source)
		_, err := endpoint.socket(t.Context(), &p, source, first)
		p.UdpEndpointKeyLocker.Unlock(source, lock)
		if err != nil || recorder.targets[len(recorder.targets)-1] != originalTarget.String() {
			t.Fatalf("reopened target changed: %v", err)
		}
		if len(endpoint.sockets) != 2 {
			t.Fatal("target could not be recreated after expiry")
		}
	})
}

func TestUDPPacketCapacitySharedAcrossSources(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &UdpEndpointPool{resources: netproxy.NewPacketBudget(2)}
		defer p.closeAll()
		first, second := netip.MustParseAddrPort("203.0.113.1:1"), netip.MustParseAddrPort("203.0.113.1:2")
		a, _ := resourceUDPEndpoint(t, first)
		b, _ := resourceUDPEndpoint(t, second)
		p.add(first, a)
		p.add(second, b)
		dst := netip.MustParseAddrPort("192.0.2.1:443")
		if _, err := a.socket(t.Context(), p, first, dst); err != nil {
			t.Fatal(err)
		}
		if _, err := b.socket(t.Context(), p, second, dst); err != nil {
			t.Fatal(err)
		}
		other := netip.MustParseAddrPort("192.0.2.2:443")
		if _, err := b.socket(t.Context(), p, second, other); netproxy.ClassifyFailure(err).Reason != netproxy.ReasonCapacity {
			t.Fatalf("global admission: %v", err)
		}
		p.remove(first, a)
		synctest.Wait()
		if _, err := b.socket(t.Context(), p, second, other); err != nil {
			t.Fatal(err)
		}
	})
}

func TestUDPSourceCapacity(t *testing.T) {
	p := &UdpEndpointPool{sourceLimit: 1}
	defer p.closeAll()
	first, second := netip.MustParseAddrPort("192.0.2.1:1"), netip.MustParseAddrPort("192.0.2.1:2")
	a, b := &UdpEndpoint{NatTimeout: time.Hour}, &UdpEndpoint{NatTimeout: time.Hour}
	if !p.addLocked(first, a) || p.addLocked(second, b) {
		t.Fatal("source admission exceeded capacity")
	}
	p.remove(first, a)
	if !p.addLocked(second, b) || p.sources.Load() != 1 {
		t.Fatal("source permit was not released")
	}
}
