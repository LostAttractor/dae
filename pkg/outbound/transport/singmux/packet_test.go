package singmux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy/fq"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
)

func TestUDPWriteReportsPartialFrames(t *testing.T) {
	for _, established := range []bool{false, true} {
		for _, missing := range []int{0, 1, 8} {
			calls := 0
			conn := &UDPConn{Conn: Conn{Conn: streamWriteFunc{write: func(p []byte) (int, error) {
				calls++
				return len(p) - missing, nil
			}}, addr: "example.org:53", udp: true, packetAddr: true, onceWrite: established}}
			payload := []byte("payload")
			addr := netproxy.NewAddr("udp", "127.0.0.1:53")
			var wantErr error
			if missing > 0 {
				wantErr = io.ErrShortWrite
			}
			if n, err := conn.WriteTo(payload, addr); n != max(0, len(payload)-missing) || !errors.Is(err, wantErr) {
				t.Fatalf("established=%v missing=%d: WriteTo = %d, %v", established, missing, n, err)
			}
			if missing > 0 {
				if n, err := conn.WriteTo(payload, addr); n != 0 || !errors.Is(err, io.ErrShortWrite) || calls != 1 {
					t.Fatalf("write after incomplete datagram = %d, %v; carrier writes %d", n, err, calls)
				}
			}
		}
	}
}

func TestUDPReadPreservesDatagramBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		payload  []byte
		fragment bool
		capacity int
	}{
		{"coalesced", []byte("first"), false, 128},
		{"fragmented", []byte("first"), true, 128},
		{"large", bytes.Repeat([]byte{'x'}, 40000), false, 65535},
		{"short buffer", []byte("first"), false, 2},
		{"empty datagram", nil, false, 128},
		{"empty buffer", []byte("first"), false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stream, server := testLeasedStream(t)
			peer, err := server.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
			_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
			var wire bytes.Buffer
			wire.WriteByte(0) // Successful stream response.
			for _, payload := range [][]byte{tc.payload, []byte("next")} {
				if err := socks5.WriteAddr("192.0.2.1:53", &wire); err != nil {
					t.Fatal(err)
				}
				wire.Write(binary.BigEndian.AppendUint16(nil, uint16(len(payload))))
				wire.Write(payload)
			}
			done := make(chan error, 1)
			go func() {
				data := wire.Bytes()
				for len(data) > 0 {
					size := len(data)
					if tc.fragment {
						size = 1
					}
					if _, err := peer.Write(data[:size]); err != nil {
						done <- err
						return
					}
					data = data[size:]
				}
				done <- nil
			}()
			conn := &UDPConn{Conn: Conn{Conn: stream}}
			buf := make([]byte, tc.capacity)
			n, from, err := conn.ReadFrom(buf)
			var wantErr error
			if len(tc.payload) > len(buf) {
				wantErr = io.ErrShortBuffer
			}
			if !errors.Is(err, wantErr) || from == nil || from.String() != "192.0.2.1:53" || !bytes.Equal(buf[:n], tc.payload[:min(len(tc.payload), len(buf))]) {
				t.Fatalf("first datagram: n=%d from=%v err=%v", n, from, err)
			}
			buf = make([]byte, 128)
			n, from, err = conn.ReadFrom(buf)
			if err != nil || from == nil || from.String() != "192.0.2.1:53" || string(buf[:n]) != "next" {
				t.Fatalf("next datagram: n=%d from=%v err=%v payload=%q", n, from, err, buf[:n])
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// testSmuxPacketConn opens a datagram stream on s, as Mux.ListenPacket does.
func testSmuxPacketConn(t testing.TB, s *smuxSession) *smuxPacketConn {
	t.Helper()
	stream, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := netproxy.NewSingleSession(netproxy.SingleSessionConfig[*sessionResource]{
		Layer: netproxy.LayerSMUX,
		Establish: func(context.Context) (*sessionResource, error) {
			return &sessionResource{session: s, monitor: s.conn}, nil
		},
		IsConnected: (*sessionResource).connected,
		Close:       func(*sessionResource) error { return nil },
	})
	t.Cleanup(func() { _ = lifecycle.Close() })
	if err := lifecycle.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	handle, err := lifecycle.CurrentHandle()
	if err != nil {
		t.Fatal(err)
	}
	leased := &leasedStream{Conn: stream, layer: netproxy.LayerSMUX, handle: handle, lease: handle.NewStreamLease(), release: func() {}}
	conn, err := newSmuxPacketConn(leased, stream.(*smuxStream), netproxy.LayerSMUX, "udp.example:53")
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// dropCount returns the upload drops counted for reason so far.
func dropCount(reason string) uint64 {
	for drop := range netproxy.Drops() {
		if drop.Direction() == netproxy.DropUpload && drop.Reason() == reason {
			return drop.Load()
		}
	}
	panic("no drop counter " + reason)
}

// readDatagrams reads the stream request and then datagrams of a 4-byte
// sequence number and padding, returning their sequence numbers.
func readDatagrams(t *testing.T, peer net.Conn, n int) []uint32 {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := socks5.ReadAddr(peer); err != nil {
		t.Fatal(err)
	}
	var seqs []uint32
	for range n {
		var length uint16
		_, err := socks5.ReadAddr(peer)
		if err == nil {
			err = binary.Read(peer, binary.BigEndian, &length)
		}
		payload := make([]byte, length)
		if err == nil {
			_, err = io.ReadFull(peer, payload)
		}
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, binary.BigEndian.Uint32(payload))
	}
	return seqs
}

func datagram(seq uint32, size int) []byte {
	return binary.BigEndian.AppendUint32(make([]byte, 0, size), seq)[:size]
}

// Datagrams queue without waiting, even while the carrier is stuck. Beyond
// the stream's limit its oldest are dropped and counted, never the first,
// which carries the stream request, and the writer is not told: to it they
// are lost on the way. Only exhausted datagram memory refuses one, which
// TryWriteTo reports and WriteTo does not.
func TestSmuxDatagramsDropOldest(t *testing.T) {
	flowFull, memory := dropCount("flow_queue_full"), netproxy.DropUploadMemory.Load()
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	conn := testSmuxPacketConn(t, s)
	<-carrier.entered
	target := netproxy.NewAddr("udp", "192.0.2.1:53")
	const sent = 100
	for seq := range uint32(sent) {
		if n, err := conn.TryWriteTo(datagram(seq, 1200), target); n != 1200 || err != nil {
			t.Fatalf("TryWriteTo = %d, %v", n, err)
		}
	}
	// The first datagram carries the 16-byte request too.
	frame := smuxHeaderSize + 7 + 2 + 1200
	kept := (fq.FlowDatagramLimit - frame - 16) / frame
	if dropped := dropCount("flow_queue_full") - flowFull; dropped != sent-1-uint64(kept) {
		t.Fatalf("counted %d drops, want %d", dropped, sent-1-kept)
	}
	server := smuxtest.Server(remote)
	defer server.Close()
	close(carrier.gate)
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	seqs := readDatagrams(t, peer, 1+kept)
	if seqs[0] != 0 || seqs[1] != sent-uint32(kept) || seqs[kept] != sent-1 {
		t.Fatalf("received datagrams %v", seqs)
	}
	waitIdle(t, s)
	limit := netproxy.DatagramMemory.UseLimit(1) // exhausts it
	_, refused := conn.TryWriteTo(datagram(sent, 1200), target)
	bound := &netproxy.BindPacketConn{PacketConn: conn, Address: target}
	n, err := bound.Write(datagram(sent, 1200))
	limit.Close()
	if refused != netproxy.ErrPacketDropped || n != 1200 || err != nil || netproxy.DropUploadMemory.Load()-memory != 2 {
		t.Fatalf("without memory: TryWriteTo %v, Write %d, %v, %d counted", refused, n, err, netproxy.DropUploadMemory.Load()-memory)
	}
	if _, err := conn.WriteTo(datagram(0, 1200), target); err != nil {
		t.Fatalf("WriteTo with memory = %v", err)
	}
}

// The datagram streams of a session share one bound: the fattest gives way
// to a stream that queued nothing, whose admitted first datagram is protected from eviction.
func TestSmuxSessionDatagramQueue(t *testing.T) {
	carrierFull := dropCount("carrier_queue_full")
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	target := netproxy.NewAddr("udp", "192.0.2.1:53")
	for i := range fq.CarrierDatagramLimit / fq.FlowDatagramLimit {
		conn := testSmuxPacketConn(t, s)
		if i == 0 {
			<-carrier.entered // the writer holds only the first SYN
		}
		for seq := range uint32(16) {
			if _, err := conn.TryWriteTo(datagram(seq, 4060), target); err != nil {
				t.Fatal(err)
			}
		}
	}
	if dropCount("carrier_queue_full") != carrierFull {
		t.Fatal("dropped within the session's bound")
	}
	late := testSmuxPacketConn(t, s)
	if _, err := late.TryWriteTo(datagram(0, 4060), target); err != nil {
		t.Fatal(err)
	}
	if dropCount("carrier_queue_full") == carrierFull {
		t.Fatal("the session took a datagram beyond its bound")
	}
	server := smuxtest.Server(remote)
	defer server.Close()
	close(carrier.gate)
	for range fq.CarrierDatagramLimit/fq.FlowDatagramLimit + 1 {
		peer, err := server.Accept()
		if err != nil {
			t.Fatal(err)
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(peer, make([]byte, 2)); err != nil {
			t.Fatal(err)
		}
	}
}

// A datagram larger than a frame is split, and the peer reads it whole.
func TestSmuxLargeDatagramSpansFrames(t *testing.T) {
	local, remote := net.Pipe()
	s := newTestSmuxSession(local)
	defer s.Close()
	server := smuxtest.Server(remote)
	defer server.Close()
	conn := testSmuxPacketConn(t, s)
	payload := make([]byte, 65535)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := conn.WriteTo(payload, netproxy.NewAddr("udp", "[2001:db8::1]:53")); err != nil {
		t.Fatal(err)
	}
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := socks5.ReadAddr(peer); err != nil {
		t.Fatal(err)
	}
	addr, err := socks5.ReadAddr(peer)
	got := make([]byte, 2+len(payload))
	if err == nil {
		_, err = io.ReadFull(peer, got)
	}
	if err != nil || addr.String() != "[2001:db8::1]:53" || binary.BigEndian.Uint16(got) != 65535 || !bytes.Equal(got[2:], payload) {
		t.Fatalf("datagram from %v: %v", addr, err)
	}
}

// Writes to a closed stream or a failed session fail as stream writes do.
func TestSmuxDatagramWriteFailures(t *testing.T) {
	local, remote := net.Pipe()
	s := newTestSmuxSession(local)
	defer s.Close()
	go io.Copy(io.Discard, remote)
	conn := testSmuxPacketConn(t, s)
	target := netproxy.NewAddr("udp", "192.0.2.1:53")
	_ = conn.Close()
	if _, err := conn.WriteTo([]byte("x"), target); !errors.Is(err, io.ErrClosedPipe) || netproxy.ClassifyFailure(err).Origin != netproxy.OriginLocalCleanup {
		t.Fatalf("write after Close = %v (%+v)", err, netproxy.ClassifyFailure(err))
	}
	other := testSmuxPacketConn(t, s)
	_ = remote.Close()
	<-s.CloseChan()
	if _, err := other.WriteTo([]byte("x"), target); err == nil || netproxy.ClassifyFailure(err).Scope != netproxy.ScopeSharedResource {
		t.Fatalf("write on a failed session = %v (%+v)", err, netproxy.ClassifyFailure(err))
	}
}

func TestSmuxDatagramWriteDoesNotAllocate(t *testing.T) {
	local, remote := net.Pipe()
	s := newTestSmuxSession(local)
	defer s.Close()
	go io.Copy(io.Discard, remote)
	conn := testSmuxPacketConn(t, s)
	target := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	payload := make([]byte, 1200)
	if allocs := testing.AllocsPerRun(200, func() { _, _ = conn.WriteTo(payload, target) }); allocs > 0 {
		t.Fatalf("%v allocations per datagram", allocs)
	}
	var _ netproxy.NonBlockingWriter = conn
}

type pushedDatagram struct {
	from    netip.AddrPort
	payload string
}

// datagramWire encodes a response and datagrams as a server sends them.
func datagramWire(t *testing.T, status byte, datagrams ...pushedDatagram) []byte {
	t.Helper()
	wire := []byte{status}
	for _, d := range datagrams {
		var err error
		if wire, err = socks5.AppendNetAddr(wire, net.UDPAddrFromAddrPort(d.from)); err != nil {
			t.Fatal(err)
		}
		wire = binary.BigEndian.AppendUint16(wire, uint16(len(d.payload)))
		wire = append(wire, d.payload...)
	}
	return wire
}

// The parser delivers every datagram whole and in order, however the stream
// splits them, several to a payload or one across many.
func TestDatagramReaderSplits(t *testing.T) {
	want := []pushedDatagram{
		{netip.MustParseAddrPort("192.0.2.1:53"), "first"},
		{netip.MustParseAddrPort("[2001:db8::1]:443"), ""},
		{netip.MustParseAddrPort("192.0.2.2:53"), string(bytes.Repeat([]byte{'x'}, 40000))},
		{netip.MustParseAddrPort("[2001:db8::2]:53"), "last"},
	}
	wire := datagramWire(t, 0, want...)
	for _, step := range []int{1, 2, 7, 13, 1024, 32 << 10, len(wire)} {
		var got []pushedDatagram
		r := &datagramReader{onPacket: func(payload []byte, from netip.AddrPort) {
			got = append(got, pushedDatagram{from, string(payload)})
		}}
		for rest := wire; len(rest) > 0; {
			n := min(step, len(rest))
			if err := r.feed(rest[:n]); err != nil {
				t.Fatalf("step %d: %v", step, err)
			}
			rest = rest[n:]
		}
		if len(got) != len(want) {
			t.Fatalf("step %d: %d datagrams, want %d", step, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("step %d: datagram %d from %v with %d bytes, want %v with %d", step, i, got[i].from, len(got[i].payload), want[i].from, len(want[i].payload))
			}
		}
	}
}

func TestDatagramReaderRejectsInvalidAddresses(t *testing.T) {
	for name, wire := range map[string][]byte{
		"address type": {0, 9, 1, 2, 3},
		"empty name":   {0, 3, 0, 0, 53, 0, 0},
		"name":         append([]byte{0, 3, 7}, "example\x00\x35\x00\x01x"...),
	} {
		t.Run(name, func(t *testing.T) {
			r := &datagramReader{onPacket: func([]byte, netip.AddrPort) { t.Fatal("delivered a datagram from an invalid address") }}
			if err := r.feed(wire); err == nil || err != r.failed {
				t.Fatalf("feed = %v", err)
			}
			if name == "name" && !strings.Contains(r.failed.Error(), "example:53") {
				t.Fatalf("error %v does not name the address", r.failed)
			}
		})
	}
}

// pushConn opens a pushing datagram stream to a test server.
func pushConn(t *testing.T) (*smuxSession, *smuxtest.Session, <-chan pushedDatagram, <-chan error, *smuxPacketConn) {
	t.Helper()
	local, remote := net.Pipe()
	s := newTestSmuxSession(local)
	t.Cleanup(func() { _ = s.Close() })
	server := smuxtest.Server(remote)
	t.Cleanup(func() { _ = server.Close() })
	conn := testSmuxPacketConn(t, s)
	packets := make(chan pushedDatagram, 16)
	closed := make(chan error, 2)
	var ended atomic.Bool
	if !conn.SetPacketHandler(func(payload []byte, from netip.AddrPort) {
		if ended.Load() {
			t.Error("datagram pushed after onClose")
		}
		packets <- pushedDatagram{from, string(payload)}
	}, func(err error) {
		ended.Store(true)
		closed <- err
	}) {
		t.Fatal("smux datagram stream cannot push")
	}
	return s, server, packets, closed, conn
}

func waitClosed(t *testing.T, closed <-chan error) error {
	t.Helper()
	select {
	case err := <-closed:
		select {
		case <-closed:
			t.Fatal("onClose called twice")
		case <-time.After(10 * time.Millisecond):
		}
		return err
	case <-time.After(time.Second):
		t.Fatal("onClose not called")
	}
	return nil
}

// Pushed datagrams arrive in order from the receive loop; FIN ends delivery
// with io.EOF after them.
func TestSmuxDatagramPushAndFIN(t *testing.T) {
	_, server, packets, closed, conn := pushConn(t)
	from := netip.MustParseAddrPort("192.0.2.1:53")
	if _, err := conn.WriteTo([]byte("query"), net.UDPAddrFromAddrPort(from)); err != nil {
		t.Fatal(err)
	}
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	wire := datagramWire(t, 0, pushedDatagram{from, "one"}, pushedDatagram{from, "two"})
	// Split inside the second header.
	for _, part := range [][]byte{wire[:12], wire[12:]} {
		if err := server.WriteFrame(smuxVersion, smuxCmdPSH, peer.ID(), part); err != nil {
			t.Fatal(err)
		}
	}
	_ = peer.Close()
	for _, payload := range []string{"one", "two"} {
		select {
		case got := <-packets:
			if got.from != from || got.payload != payload {
				t.Fatalf("pushed %+v, want %q from %v", got, payload, from)
			}
		case <-time.After(time.Second):
			t.Fatal("datagram not pushed")
		}
	}
	if err := waitClosed(t, closed); err != io.EOF {
		t.Fatalf("FIN ended delivery with %v", err)
	}
}

// A rejection ends delivery with the target's message, as a read would.
func TestSmuxDatagramPushRejection(t *testing.T) {
	_, server, packets, closed, conn := pushConn(t)
	if _, err := conn.WriteTo([]byte("query"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("\x01no route")); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	err = waitClosed(t, closed)
	if failure := netproxy.ClassifyFailure(err); failure.Reason != netproxy.ReasonRejected || !strings.Contains(err.Error(), "no route") {
		t.Fatalf("rejection ended delivery with %v (%+v)", err, failure)
	}
	if len(packets) != 0 {
		t.Fatal("rejection pushed a datagram")
	}
}

// Closing the stream or losing the session ends delivery with the error a
// read would see, and no datagram follows.
func TestSmuxDatagramPushEnds(t *testing.T) {
	t.Run("close", func(t *testing.T) {
		_, _, _, closed, conn := pushConn(t)
		_ = conn.Close()
		if err := waitClosed(t, closed); !errors.Is(err, io.ErrClosedPipe) || netproxy.ClassifyFailure(err).Origin != netproxy.OriginLocalCleanup {
			t.Fatalf("Close ended delivery with %v", err)
		}
	})
	t.Run("session", func(t *testing.T) {
		_, server, _, closed, _ := pushConn(t)
		_ = server.Close()
		if err := waitClosed(t, closed); netproxy.ClassifyFailure(err).Scope != netproxy.ScopeSharedResource {
			t.Fatalf("session loss ended delivery with %v (%+v)", err, netproxy.ClassifyFailure(err))
		}
	})
}

// onClose may close the connection, also on the receive loop, which goes on
// serving the other streams of the session.
func TestSmuxDatagramPushOnCloseMayClose(t *testing.T) {
	local, remote := net.Pipe()
	s := newTestSmuxSession(local)
	t.Cleanup(func() { _ = s.Close() })
	server := smuxtest.Server(remote)
	t.Cleanup(func() { _ = server.Close() })
	conn := testSmuxPacketConn(t, s)
	closed := make(chan error, 1)
	conn.SetPacketHandler(func([]byte, netip.AddrPort) {}, func(error) { closed <- conn.Close() })
	if _, err := conn.WriteTo([]byte("query"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.Close() // FIN: onClose runs on the receive loop
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close from onClose = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("onClose did not return")
	}
	other, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if peer, err = server.Accept(); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	_ = other.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(other, make([]byte, 4)); err != nil {
		t.Fatalf("receive loop stopped: %v", err)
	}
}

func TestSmuxPacketHandlerAfterFirstWritePanics(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	go io.Copy(io.Discard, remote)
	s := newTestSmuxSession(local)
	defer s.Close()
	conn := testSmuxPacketConn(t, s)
	if _, err := conn.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("handler set after the first write")
		}
	}()
	conn.SetPacketHandler(func([]byte, netip.AddrPort) {}, func(error) {})
}

func TestSmuxRejectsOversizedDatagramBeforeRequest(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	go io.Copy(io.Discard, remote)
	s := newTestSmuxSession(local)
	defer s.Close()
	conn := testSmuxPacketConn(t, s)
	before := netproxy.DatagramMemory.Status().Used
	if _, err := conn.TryWriteTo(make([]byte, 1<<16), netproxy.NewAddr("udp", "192.0.2.1:53")); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversized UDP datagram: %v", err)
	}
	if conn.requested.Load() || netproxy.DatagramMemory.Status().Used != before {
		t.Fatal("invalid datagram consumed the request or reserved payload memory")
	}
}

func TestSmuxRequestAdmissionRetriesWithoutLosingHeader(t *testing.T) {
	local, remote := net.Pipe()
	s := newTestSmuxSession(local)
	defer s.Close()
	server := smuxtest.Server(remote)
	defer server.Close()
	conn := testSmuxPacketConn(t, s)
	target := netproxy.NewAddr("udp", "192.0.2.1:53")
	limit := netproxy.DatagramMemory.UseLimit(1)
	defer limit.Close()
	if n, err := conn.TryWriteTo(datagram(1, 1200), target); n != 0 || err != netproxy.ErrPacketDropped || conn.requested.Load() {
		t.Fatalf("refused first datagram: n=%d err=%v requested=%v", n, err, conn.requested.Load())
	}
	limit.Close()
	if n, err := conn.TryWriteTo(datagram(2, 1200), target); n != 1200 || err != nil {
		t.Fatalf("retry: %d %v", n, err)
	}
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if seqs := readDatagrams(t, peer, 1); len(seqs) != 1 || seqs[0] != 2 {
		t.Fatalf("retry sent %v", seqs)
	}
}
