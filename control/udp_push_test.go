// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
)

// pushingPacketConn pushes replies, as smux UDP streams do; the test calls
// its handler in place of the transport's receive loop.
type pushingPacketConn struct {
	*testPacketConn
	onPacket func([]byte, netip.AddrPort)
	onClose  func(error)
}

func (c *pushingPacketConn) SetPacketHandler(onPacket func([]byte, netip.AddrPort), onClose func(error)) bool {
	c.onPacket, c.onClose = onPacket, onClose
	return true
}

// testReplies records replies; fast replies are sent by trySend, the others
// by send, which waits for gate when it is set.
type testReplies struct {
	mu   sync.Mutex
	fast bool
	gate chan struct{}
	sent []string
	from []netip.AddrPort
	slow atomic.Int32
}

func (r *testReplies) trySend(data []byte, from netip.AddrPort) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.fast {
		return errReplyWouldBlock
	}
	r.sent, r.from = append(r.sent, string(data)), append(r.from, from)
	return nil
}

func (r *testReplies) send(data []byte, from netip.AddrPort) error {
	r.slow.Add(1)
	r.mu.Lock()
	gate := r.gate
	r.mu.Unlock()
	if gate != nil {
		<-gate
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent, r.from = append(r.sent, string(data)), append(r.from, from)
	return nil
}

func (r *testReplies) set(fast bool, gate chan struct{}) {
	r.mu.Lock()
	r.fast, r.gate = fast, gate
	r.mu.Unlock()
}

func (r *testReplies) replies() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sent...)
}

func pushEndpoint(t *testing.T) (*UdpEndpointPool, *UdpEndpoint, *pushingPacketConn, *testReplies, netip.AddrPort) {
	t.Helper()
	conn := &pushingPacketConn{testPacketConn: newTestPacketConn(false)}
	replies := new(testReplies)
	src := netip.MustParseAddrPort("192.0.2.10:30000")
	// Traffic totals are process-wide: a path of its own per run.
	path := stats.Path{Outbound: t.Name(), NodeID: time.Now().String()}
	traffic := stats.DefaultStore.OpenConnection(path, false)
	t.Cleanup(func() { _ = traffic.Close() })
	ue := &UdpEndpoint{conn: conn, NatTimeout: time.Minute, replies: replies, statsPath: path, traffic: traffic}
	p := new(UdpEndpointPool)
	t.Cleanup(p.closeAll)
	p.add(src, ue)
	ue.startSocket(p, src, netip.MustParseAddrPort("192.0.2.1:443"), netip.AddrPort{}, conn)
	if conn.onPacket == nil {
		t.Fatal("pushing transport was read instead")
	}
	return p, ue, conn, replies, src
}

func waitReplies(t *testing.T, r *testReplies, want ...string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		got := r.replies()
		if len(got) == len(want) {
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("replies %q, want %q", got, want)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("replies %q, want %q", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// Replies that can go at once are sent on the receive loop; a reply that
// might block goes to a goroutine, and the replies after it follow it there
// in order while the receive loop moves on.
func TestUDPPushedRepliesNeverBlockTheReceiveLoop(t *testing.T) {
	_, ue, conn, replies, _ := pushEndpoint(t)
	dropped := dropReplyQueue.Load()
	from := netip.MustParseAddrPort("192.0.2.1:443")
	replies.set(true, nil)
	conn.onPacket([]byte("a"), from)
	if got := replies.replies(); len(got) != 1 || replies.slow.Load() != 0 {
		t.Fatalf("immediate reply took the slow path: %q", got)
	}
	gate := make(chan struct{})
	replies.set(false, gate)
	returned := make(chan struct{})
	go func() {
		conn.onPacket([]byte("b"), from)
		replies.set(true, gate)
		conn.onPacket([]byte("c"), from)
		for range udpTaskQueueLength + 1 {
			conn.onPacket([]byte("x"), from)
		}
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("a blocked reply held the receive loop")
	}
	if drops := dropReplyQueue.Load() - dropped; drops < 2 {
		t.Fatalf("%d replies beyond the queue dropped, want at least 2", drops)
	}
	close(gate)
	deadline := time.Now().Add(time.Second)
	for len(replies.replies()) < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := replies.replies(); got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("reply order %q", got[:3])
	}
	// Dropped replies are not downloaded.
	sent := 3 + udpTaskQueueLength + 1 - int(dropReplyQueue.Load()-dropped)
	waitDownload(t, ue, uint64(sent)) // one byte each
	if got := replies.replies(); len(got) != sent {
		t.Fatalf("%d replies sent, want %d", len(got), sent)
	}
}

// A reply the slow path cannot copy within the shared UDP packet memory is
// dropped, not downloaded, and the replies after it keep their order.
func TestUDPPushReplyBeyondPacketMemoryIsDropped(t *testing.T) {
	_, ue, conn, replies, _ := pushEndpoint(t)
	dropped := dropDownloadMemory.Load()
	from := netip.MustParseAddrPort("192.0.2.1:443")
	gate := make(chan struct{})
	replies.set(false, gate)
	conn.onPacket([]byte("first"), from) // its send waits for gate
	limit := udpPacketMemory.UseLimit(1)
	conn.onPacket([]byte("dropped"), from)
	limit.Close()
	conn.onPacket([]byte("last"), from)
	close(gate)
	waitReplies(t, replies, "first", "last")
	waitDownload(t, ue, uint64(len("first")+len("last")))
	if drops := dropDownloadMemory.Load() - dropped; drops != 1 {
		t.Fatalf("%d replies dropped, want 1", drops)
	}
}

func waitDownload(t *testing.T, ue *UdpEndpoint, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		got := stats.DefaultStore.Snapshot()[ue.statsPath].DownloadBytes
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("download bytes = %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// onClose may come from a closer holding the source lock; ending delivery
// takes that lock, so it happens on another goroutine, after the replies
// already queued.
func TestUDPPushCloseEndsDeliveryInBackground(t *testing.T) {
	p, ue, conn, replies, src := pushEndpoint(t)
	gate := make(chan struct{})
	replies.set(false, gate)
	conn.onPacket([]byte("queued"), netip.MustParseAddrPort("192.0.2.1:443"))
	lock, _ := p.UdpEndpointKeyLocker.Lock(src)
	conn.onClose(io.EOF)
	p.UdpEndpointKeyLocker.Unlock(src, lock)
	close(gate)
	waitReplies(t, replies, "queued")
	deadline := time.Now().Add(time.Second)
	for !ue.IsClosed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, exists := p.pool.Load(src); exists || !ue.IsClosed() {
		t.Fatal("end of delivery kept the endpoint")
	}
	closed := dropClosedStream.Load()
	conn.onPacket([]byte("late"), netip.MustParseAddrPort("192.0.2.1:443"))
	time.Sleep(10 * time.Millisecond)
	if got := replies.replies(); len(got) != 1 {
		t.Fatalf("reply delivered after the end: %q", got)
	}
	if n := dropClosedStream.Load() - closed; n != 1 {
		t.Fatalf("%d replies after the end counted, want 1", n)
	}
}

// A rewritten destination pushes only replies from its target, as from the
// original destination, and counts the others.
func TestUDPPushDestinationFiltersReplies(t *testing.T) {
	filtered := dropDownloadFiltered.Load()
	inner := &pushingPacketConn{testPacketConn: newTestPacketConn(false)}
	original, target := netip.MustParseAddrPort("198.51.100.1:443"), netip.MustParseAddrPort("192.0.2.1:443")
	conn := newDestinationConn(inner, original, target)
	var got []netip.AddrPort
	if !conn.SetPacketHandler(func(_ []byte, from netip.AddrPort) { got = append(got, from) }, func(error) {}) {
		t.Fatal("destination socket cannot push")
	}
	inner.onPacket(nil, netip.MustParseAddrPort("192.0.2.9:443"))
	inner.onPacket(nil, netip.MustParseAddrPort("[::ffff:192.0.2.1]:443"))
	if len(got) != 1 || got[0] != original || dropDownloadFiltered.Load()-filtered != 1 {
		t.Fatalf("pushed from %v with %d filtered, want only %v and 1", got, dropDownloadFiltered.Load()-filtered, original)
	}
}

// Once a destination socket is retired, its pushes do nothing and its end
// keeps the source.
func TestUDPPushRetiredSocketIsInert(t *testing.T) {
	conn := &pushingPacketConn{testPacketConn: newTestPacketConn(false)}
	replies := new(testReplies)
	replies.set(true, nil)
	src, dst := netip.MustParseAddrPort("192.0.2.10:30000"), netip.MustParseAddrPort("192.0.2.1:443")
	ue := &UdpEndpoint{conn: conn, NatTimeout: time.Minute, replies: replies, sockets: make(map[netip.AddrPort]*udpSocket)}
	p := new(UdpEndpointPool)
	t.Cleanup(p.closeAll)
	p.add(src, ue)
	ue.startSocket(p, src, dst, dst, conn)
	ue.mu.Lock()
	child := ue.sockets[dst]
	ue.mu.Unlock()
	child.retired.Store(true)
	closed := dropClosedStream.Load()
	conn.onPacket([]byte("late"), dst)
	conn.onClose(io.EOF)
	time.Sleep(10 * time.Millisecond)
	if _, exists := p.pool.Load(src); !exists || len(replies.replies()) != 0 {
		t.Fatalf("retired socket delivered %q or ended the source", replies.replies())
	}
	if n := dropClosedStream.Load() - closed; n != 1 {
		t.Fatalf("%d replies for the retired socket counted, want 1", n)
	}
}

// Observing a target the endpoint has not seen flushes the registry, which
// may wait: such a reply goes to the slow path, and the receive loop moves
// on. A reply that missed the fast path is still counted once.
func TestUDPPushUnseenTargetTakesTheSlowPath(t *testing.T) {
	_, ue, conn, replies, _ := pushEndpoint(t)
	registry := newDomainRegistry(16, time.Hour, func(netip.Addr, []uint32, []uint32) error { return nil }, func(netip.Addr) error { return nil })
	ue.activity = registry.activity
	replies.set(true, nil)
	from := netip.MustParseAddrPort("192.0.2.1:443")
	registry.mu.Lock() // a flush waits
	unlock := sync.OnceFunc(registry.mu.Unlock)
	defer unlock()
	returned := make(chan struct{})
	go func() {
		conn.onPacket([]byte("first"), from)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("the receive loop flushed the registry")
	}
	if got := replies.replies(); len(got) != 0 {
		t.Fatalf("unobserved target replied on the receive loop: %q", got)
	}
	unlock()
	waitReplies(t, replies, "first")
	conn.onPacket([]byte("second"), from)
	if got := replies.replies(); len(got) != 2 || replies.slow.Load() != 1 {
		t.Fatalf("observed target took the slow path: %q", got)
	}
	if got := stats.DefaultStore.Snapshot()[ue.statsPath].DownloadBytes; got != uint64(len("first")+len("second")) {
		t.Fatalf("download bytes = %d", got)
	}
}

// A reply whose transport was aborted is not sent: delivery ends with the
// abort cause, on the receive loop too.
func TestUDPPushAbortedTransportEndsDelivery(t *testing.T) {
	cause := errors.New("transport aborted")
	lease := netproxy.NewLease(netproxy.NewResourceRef())
	lease.Abort(cause)
	conn := &udpLifecyclePacket{testPacketConn: newTestPacketConn(false), lease: lease}
	replies := new(testReplies)
	replies.set(true, nil)
	src, from := netip.MustParseAddrPort("192.0.2.10:30000"), netip.MustParseAddrPort("192.0.2.1:443")
	ue := &UdpEndpoint{conn: conn, NatTimeout: time.Minute, replies: replies}
	p := new(UdpEndpointPool)
	t.Cleanup(p.closeAll)
	p.add(src, ue)
	if done, err := ue.deliver(p, src, conn, nil, []byte("reply"), from, false); !done || !errors.Is(err, cause) {
		t.Fatalf("deliver = %v, %v; want the abort cause", done, err)
	}
	r := &udpPushReceiver{ue: ue, p: p, src: src, dst: from, conn: conn}
	r.onPacket([]byte("reply"), from)
	r.mu.Lock()
	done := r.done
	r.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for !ue.IsClosed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !done || !ue.IsClosed() || len(replies.replies()) != 0 {
		t.Fatalf("aborted transport: ended=%v closed=%v replies %q", done, ue.IsClosed(), replies.replies())
	}
}

// The MITM bridge of an endpoint is read, never pushed.
func TestUDPPushSkipsMITMBridge(t *testing.T) {
	conn := &pushingPacketConn{testPacketConn: newTestPacketConn(false)}
	src, dst := netip.MustParseAddrPort("192.0.2.10:30000"), netip.MustParseAddrPort("192.0.2.1:443")
	ue := &UdpEndpoint{conn: conn, mitm: true, NatTimeout: time.Minute, replies: new(testReplies), sockets: make(map[netip.AddrPort]*udpSocket)}
	p := new(UdpEndpointPool)
	t.Cleanup(p.closeAll)
	p.add(src, ue)
	ue.startSocket(p, src, dst, dst, conn)
	if conn.onPacket != nil {
		t.Fatal("MITM bridge pushed")
	}
}

// Over an smux session, a destination socket opened as associations open
// them takes its push handler before the first datagram, which carries the
// stream request, and pushes only its target's replies.
func TestUDPPushOverSmux(t *testing.T) {
	outbound, server := smuxTestOutbound(t)
	session := smuxtest.Server(server)
	t.Cleanup(func() { _ = session.Close() })
	original, target := netip.MustParseAddrPort("198.51.100.1:443"), netip.MustParseAddrPort("192.0.2.1:443")
	p := new(UdpEndpointPool)
	t.Cleanup(p.closeAll)
	owned, err := p.packetBudget().Open(t.Context(), target.String(), outbound.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	conn := newDestinationPacketConn(owned, original, target)
	replies := new(testReplies)
	replies.set(true, nil)
	src := netip.MustParseAddrPort("192.0.2.10:30000")
	path := stats.Path{Outbound: t.Name(), NodeID: time.Now().String()}
	traffic := stats.DefaultStore.OpenConnection(path, false)
	t.Cleanup(func() { _ = traffic.Close() })
	ue := &UdpEndpoint{conn: conn, NatTimeout: time.Minute, replies: replies, traffic: traffic}
	p.add(src, ue)
	ue.startSocket(p, src, original, netip.AddrPort{}, conn)
	c := &ControlPlane{udpEndpoints: p}
	if err := c.writeUDP(t.Context(), ue, src, original, []byte("query")); err != nil {
		t.Fatal(err)
	}
	peer, err := session.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	var request bytes.Buffer
	if err := singmux.WriteStreamRequest(&request, &singmux.StreamRequest{Destination: target.String(), UDP: true, PacketAddr: true}); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, request.Len()+1+4+2+2+len("query"))
	if _, err := io.ReadFull(peer, got); err != nil || !bytes.HasPrefix(got, request.Bytes()) || !bytes.HasSuffix(got, []byte("query")) {
		t.Fatalf("stream received %q, %v", got, err)
	}
	wire := []byte{0} // the stream response
	for _, d := range []struct {
		from    netip.AddrPort
		payload string
	}{{netip.MustParseAddrPort("192.0.2.9:443"), "other"}, {target, "reply"}} {
		wire, _ = socks5.AppendNetAddr(wire, net.UDPAddrFromAddrPort(d.from))
		wire = binary.BigEndian.AppendUint16(wire, uint16(len(d.payload)))
		wire = append(wire, d.payload...)
	}
	if _, err := peer.Write(wire); err != nil {
		t.Fatal(err)
	}
	waitReplies(t, replies, "reply")
	if got := stats.DefaultStore.Snapshot()[path]; got.UploadBytes != uint64(len("query")) || got.DownloadBytes != uint64(len("reply")) {
		t.Fatalf("traffic %+v", got)
	}
}

// smuxReply writes the stream response, if first, and datagrams to a server
// stream: [SOCKS address][length][payload].
func smuxReply(t *testing.T, peer *smuxtest.Stream, first bool, from netip.AddrPort, payloads ...string) {
	t.Helper()
	var wire []byte
	if first {
		wire = append(wire, 0)
	}
	for _, payload := range payloads {
		wire, _ = socks5.AppendNetAddr(wire, net.UDPAddrFromAddrPort(from))
		wire = binary.BigEndian.AppendUint16(wire, uint16(len(payload)))
		wire = append(wire, payload...)
	}
	if _, err := peer.Write(wire); err != nil {
		t.Fatal(err)
	}
}

// Association setup over an smux outbound registers each socket's push
// handler before its first datagram: for the rewritten first destination,
// whose packets setup sends, and for a second one opened by a later packet.
// Both push their targets' replies as from the original destinations, and
// no goroutine reads them.
func TestUDPPushSetupOverSmuxKernelIntegration(t *testing.T) {
	bindings := newRoutingLayoutTestMap(t, "udp_bindings_map", 8)
	decisions := newRoutingLayoutTestMap(t, "udp_routing_cache_map", 8)
	var endpoints UdpEndpointPool
	defer endpoints.closeAll()
	mux, carrier := smuxTestOutbound(t)
	session := smuxtest.Server(carrier)
	t.Cleanup(func() { _ = session.Close() })
	source := netip.MustParseAddrPort("192.0.2.10:5000")
	originals := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.20:443"), netip.MustParseAddrPort("192.0.2.21:443")}
	targets := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:443"), netip.MustParseAddrPort("198.51.100.21:443")}
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t,
		"dip(192.0.2.20) -> dnat(198.51.100.20)\ndip(192.0.2.21) -> dnat(198.51.100.21)",
		"dip(192.0.2.0/24, 198.51.100.0/24) -> proxy"))
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("UDP association must use the selected packet dialer")
		return nil, net.ErrClosed
	})
	global := &dialer.GlobalOption{}
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: mux}), global, &dialer.Property{Name: t.Name()}, false, "")
	group := outbound.NewDialerGroup(global, "proxy", outbound.GroupKindSingleAlwaysAlive, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
	t.Cleanup(func() { _ = group.Close() })
	plane := &ControlPlane{udpEndpoints: &endpoints, routingMatcher: matcher, deviceRoutes: newTestDeviceRoutes(t),
		core:      &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{UdpBindingsMap: bindings, UdpRoutingCacheMap: decisions}}}},
		outbounds: []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), group},
	}
	replies := new(testReplies)
	replies.set(true, nil)
	var want []string
	for i, original := range originals {
		result := &routingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureDestination, Ifindex: 7, ProfileId: matcher.defaultProfileID}
		if err := plane.handlePkt(t.Context(), []byte("query"), source, original, result); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			ue, ok := endpoints.Get(source)
			if !ok {
				t.Fatal("no association")
			}
			ue.replies = replies // before any reply: the server answers below
		}
		peer, err := session.Accept()
		if err != nil {
			t.Fatal(err)
		}
		_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
		var request bytes.Buffer
		if err := singmux.WriteStreamRequest(&request, &singmux.StreamRequest{Destination: targets[i].String(), UDP: true, PacketAddr: true}); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, request.Len()+1+4+2+2+len("query"))
		if _, err := io.ReadFull(peer, got); err != nil || !bytes.HasPrefix(got, request.Bytes()) || !bytes.HasSuffix(got, []byte("query")) {
			t.Fatalf("stream %d received %q, %v", i, got, err)
		}
		smuxReply(t, peer, true, original, "foreign")
		want = append(want, fmt.Sprint("reply ", i))
		smuxReply(t, peer, false, targets[i], want[i])
		waitReplies(t, replies, want...)
	}
	replies.mu.Lock()
	from := replies.from
	replies.mu.Unlock()
	if len(from) != 2 || from[0] != originals[0] || from[1] != originals[1] {
		t.Fatalf("replies from %v, want %v", from, originals)
	}
	stacks := make([]byte, 1<<20)
	if bytes.Contains(stacks[:runtime.Stack(stacks, true)], []byte("(*UdpEndpoint).run")) {
		t.Fatal("a goroutine reads a pushing socket")
	}
}
