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
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
)

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

// Datagrams queue without waiting, even while the carrier is stuck, up to
// the stream's queue; beyond it they are dropped and counted, and later ones
// queue again once the writer caught up. The request precedes the first
// datagram. Only TryWriteTo reports a drop: to other callers it is a
// datagram lost on the way.
func TestSmuxDatagramsQueueOrDrop(t *testing.T) {
	dropped := dropFlowQueueFull.Load()
	local, remote := net.Pipe()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	conn := testSmuxPacketConn(t, s)
	<-carrier.entered
	target := netproxy.NewAddr("udp", "192.0.2.1:53")
	payload := make([]byte, 1200)
	queued := 0
	for {
		n, err := conn.TryWriteTo(payload, target)
		if err == netproxy.ErrPacketDropped {
			break
		}
		if err != nil || n != len(payload) {
			t.Fatalf("TryWriteTo = %d, %v", n, err)
		}
		queued++
	}
	bound := &netproxy.BindPacketConn{PacketConn: conn, Address: target}
	if n, err := bound.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("dropped Write = %d, %v; want it written", n, err)
	}
	if n := dropFlowQueueFull.Load() - dropped; n != 2 {
		t.Fatalf("counted %d stream queue drops, want 2", n)
	}
	s.mu.Lock()
	backlog := conn.stream.queued
	s.mu.Unlock()
	if size := smuxHeaderSize + 7 + 2 + len(payload); backlog > smuxDatagramQueue || backlog+size <= smuxDatagramQueue {
		t.Fatalf("dropped with %d bytes queued (%d datagrams), bound %d", backlog, queued, smuxDatagramQueue)
	}
	request := len("\x00\x03\x03\x0budp.example\x00\x35")
	server := smuxtest.Server(remote)
	defer server.Close()
	close(carrier.gate)
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	header := make([]byte, request)
	if _, err := io.ReadFull(peer, header); err != nil || !bytes.Equal(header, []byte("\x00\x03\x03\x0budp.example\x00\x35")) {
		t.Fatalf("request = %q, %v", header, err)
	}
	for range queued {
		addr, err := socks5.ReadAddr(peer)
		var length uint16
		if err == nil {
			err = binary.Read(peer, binary.BigEndian, &length)
		}
		if err != nil || addr.String() != "192.0.2.1:53" || int(length) != len(payload) {
			t.Fatalf("datagram from %v, length %d, %v", addr, length, err)
		}
		if _, err := io.ReadFull(peer, payload); err != nil {
			t.Fatal(err)
		}
	}
	waitIdle(t, s)
	if _, err := conn.WriteTo(payload, target); err != nil {
		t.Fatalf("WriteTo after the queue drained = %v", err)
	}
}

// The datagram streams of a session share one queue bound.
func TestSmuxSessionDatagramQueue(t *testing.T) {
	dropped := dropCarrierQueueFull.Load()
	local, remote := net.Pipe()
	defer remote.Close()
	carrier := newGatedConn(local)
	s := newTestSmuxSession(carrier)
	defer s.Close()
	target := netproxy.NewAddr("udp", "192.0.2.1:53")
	payload := make([]byte, 4000)
	accepted := 0
	for i := range smuxSessionDatagramQueue/smuxDatagramQueue + 1 {
		conn := testSmuxPacketConn(t, s)
		if i == 0 {
			<-carrier.entered // the writer holds only the first SYN
		}
		for {
			if _, err := conn.TryWriteTo(payload, target); err != nil {
				if err != netproxy.ErrPacketDropped {
					t.Fatal(err)
				}
				break
			}
			accepted++
		}
	}
	s.mu.Lock()
	queued := s.datagrams
	s.mu.Unlock()
	// The last stream dropped below its own bound, at the session's.
	if size := smuxHeaderSize + 7 + 2 + len(payload); queued > smuxSessionDatagramQueue || queued+size <= smuxSessionDatagramQueue {
		t.Fatalf("session dropped with %d datagram bytes queued (%d datagrams), bound %d", queued, accepted, smuxSessionDatagramQueue)
	}
	if n := dropCarrierQueueFull.Load() - dropped; n != 1 {
		t.Fatalf("counted %d session queue drops, want 1", n)
	}
	// Let Close write the queue.
	go io.Copy(io.Discard, remote)
	close(carrier.gate)
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
