package singmux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
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
// the stream's queue; beyond it they are dropped, and later ones queue again
// once the writer caught up. The request precedes the first datagram. Only
// TryWriteTo reports a drop: to other callers it is a datagram lost on the
// way.
func TestSmuxDatagramsQueueOrDrop(t *testing.T) {
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
