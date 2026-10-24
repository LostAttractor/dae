package aeadframe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// countConn exposes its socket for receive tuning and counts reads, which
// return once per wakeup.
type countConn struct {
	*net.TCPConn
	reads int
	late  bool // expose the socket only after the first read
}

func (c *countConn) Read(p []byte) (int, error) {
	c.reads++
	return c.TCPConn.Read(p)
}

func (c *countConn) ReadPassthrough() net.Conn {
	if c.late && c.reads == 0 {
		return nil
	}
	return c.TCPConn
}

func sockopt(t *testing.T, conn *net.TCPConn, opt int) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	if err := raw.Control(func(fd uintptr) { value, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt) }); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// loopback connects over 127.0.0.1. A positive rcvbuf locks the client's
// receive buffer before the handshake sizes its window.
func loopback(t *testing.T, listenMPTCP, dialMPTCP bool, rcvbuf int) (client *net.TCPConn, server net.Conn) {
	t.Helper()
	var lc net.ListenConfig
	lc.SetMultipathTCP(listenMPTCP)
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var d net.Dialer
	d.SetMultipathTCP(dialMPTCP)
	if rcvbuf > 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var err error
			if controlErr := c.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbuf) }); controlErr != nil {
				return controlErr
			}
			return err
		}
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()
	conn, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client = conn.(*net.TCPConn)
	server = <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	if dialMPTCP && sockopt(t, client, unix.SO_PROTOCOL) != unix.IPPROTO_MPTCP {
		t.Skip("MPTCP unavailable")
	}
	if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return client, server
}

// trickle writes wire in segment-sized pieces with gaps, then tail at once,
// and keeps the connection open so that over-asking hangs until the deadline.
// Readers detect a failed write by the bytes missing.
func trickle(conn net.Conn, wire, tail []byte, gap time.Duration) {
	go func() {
		for len(wire) > 0 {
			n := min(1448, len(wire))
			if _, err := conn.Write(wire[:n]); err != nil {
				return
			}
			wire = wire[n:]
			time.Sleep(gap)
		}
		_, _ = conn.Write(tail)
	}()
}

func TestSocketWakesOncePerChunk(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		listenMPTCP, dialMPTCP bool
	}{{"tcp", false, false}, {"mptcp-fallback", false, true}, {"mptcp", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := loopback(t, tc.listenMPTCP, tc.dialMPTCP, 0)
			payloads := testPayloads(32<<10, 1)
			wire := seal(testAEAD(t), payloads...)
			split := len(wire) - (2 + 16 + 1 + 16)
			trickle(server, wire[:split], wire[split:], 200*time.Microsecond)
			conn := &countConn{TCPConn: client}
			r := newTestReader(t, conn)
			buf := make([]byte, 32<<10)
			if _, err := io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, payloads[0]) {
				t.Fatal(err)
			}
			// Without a receive demand every one of the 23 segments wakes the reader.
			if conn.reads > 6 {
				t.Fatalf("%d reads for one chunk", conn.reads)
			}
			if lowat, rcvbuf := sockopt(t, client, unix.SO_RCVLOWAT), sockopt(t, client, unix.SO_RCVBUF); lowat < minRaise || 4*lowat > rcvbuf {
				t.Fatalf("SO_RCVLOWAT %d for SO_RCVBUF %d", lowat, rcvbuf)
			}
			// The small frame behind it must not wait for more bytes.
			if n, err := r.Read(buf); n != 1 || err != nil {
				t.Fatalf("small frame = %d, %v", n, err)
			}
		})
	}
}

// MPTCP's EPOLLIN has no small-window escape: SO_RCVLOWAT above what the
// receive buffer can queue would hang the reader until its deadline. Loopback
// skbs queue nearly a byte per byte of buffer, so the bound is checked too.
func TestSocketDemandFitsReceiveBuffer(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		listenMPTCP, dialMPTCP bool
		rcvbuf                 int
	}{{"mptcp-fallback", false, true, 0}, {"mptcp-fallback/small", false, true, 4096}, {"mptcp/small", true, true, 4096}, {"tcp/small", false, false, 4096}} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := loopback(t, tc.listenMPTCP, tc.dialMPTCP, tc.rcvbuf)
			payloads := testPayloads(65535, 65535, 1)
			wire := seal(testAEAD(t), payloads...)
			split := len(wire) - (2 + 16 + 1 + 16)
			trickle(server, wire[:split], wire[split:], 50*time.Microsecond)
			r := newTestReader(t, client)
			want := bytes.Join(payloads, nil)
			got := make([]byte, len(want))
			if n, err := io.ReadFull(r, got[:2*65535]); err != nil {
				t.Fatalf("read %d bytes: %v", n, err)
			}
			if lowat, rcvbuf := sockopt(t, client, unix.SO_RCVLOWAT), sockopt(t, client, unix.SO_RCVBUF); 4*lowat > rcvbuf {
				t.Fatalf("SO_RCVLOWAT %d for SO_RCVBUF %d", lowat, rcvbuf)
			}
			if n, err := io.ReadFull(r, got[2*65535:]); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("small frame = %d, %v", n, err)
			}
		})
	}
}

// MPTCP's EPOLLIN compares queued bytes only with SO_RCVLOWAT, so the peer's
// FIN or RST must still wake a reader parked for the rest of a chunk.
func TestSocketPeerCloseWakesRaisedReader(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		listenMPTCP, dialMPTCP bool
	}{{"tcp", false, false}, {"mptcp-fallback", false, true}, {"mptcp", true, true}} {
		for _, reset := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reset=%t", tc.name, reset), func(t *testing.T) {
				client, server := loopback(t, tc.listenMPTCP, tc.dialMPTCP, 0)
				wire := seal(testAEAD(t), testPayloads(32<<10)...)
				go func() {
					_, _ = server.Write(wire[:8000])
					time.Sleep(100 * time.Millisecond)
					if reset {
						_ = server.(*net.TCPConn).SetLinger(0)
					}
					_ = server.Close()
				}()
				if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				want := error(io.ErrUnexpectedEOF)
				if reset {
					want = syscall.ECONNRESET
				}
				if _, err := io.ReadFull(newTestReader(t, client), make([]byte, 32<<10)); !errors.Is(err, want) {
					t.Fatalf("peer close returned %v, want %v", err, want)
				}
				if lowat := sockopt(t, client, unix.SO_RCVLOWAT); lowat < minRaise {
					t.Fatalf("reader waited with SO_RCVLOWAT %d", lowat)
				}
			})
		}
	}
}

// Adapters may turn transparent after their handshake; the reader picks up the
// socket on a later read.
func TestSocketProbesUntilExposed(t *testing.T) {
	client, server := loopback(t, false, false, 0)
	payloads := testPayloads(32 << 10)
	wire := seal(testAEAD(t), payloads...)
	trickle(server, wire, nil, 200*time.Microsecond)
	conn := &countConn{TCPConn: client, late: true}
	r := newTestReader(t, conn)
	buf := make([]byte, 32<<10)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	if r.sock.raw == nil || r.sock.lowat < minRaise {
		t.Fatalf("socket exposed after the first read was not tuned: lowat %d", r.sock.lowat)
	}
}

// A receive buffer grown by setting SO_RCVLOWAT means MPTCP clamped its
// subflow windows to that value: the reader halves it and never asks more.
func TestSocketHalvesDemandAfterKernelResize(t *testing.T) {
	client, _ := loopback(t, false, false, 0)
	var s socket
	if !s.probe(&countConn{TCPConn: client}) {
		t.Fatal("socket not found")
	}
	rcvbuf := sockopt(t, client, unix.SO_RCVBUF)
	if err := s.raw.Control(func(fd uintptr) {
		// A stale reading makes the current buffer look grown by the call.
		s.setCapped(int(fd), 8<<10, rcvbuf/2)
		s.setCapped(int(fd), 16<<10, rcvbuf)
	}); err != nil {
		t.Fatal(err)
	}
	if lowat := sockopt(t, client, unix.SO_RCVLOWAT); lowat != 4<<10 || s.lowat != lowat || s.ceiling != lowat {
		t.Fatalf("SO_RCVLOWAT %d, tracked %d, ceiling %d", lowat, s.lowat, s.ceiling)
	}
}

func TestSocketDemandDoesNotAllocate(t *testing.T) {
	const chunks = 64
	client, server := loopback(t, false, true, 0)
	payloads := make([][]byte, 2*chunks)
	for i := range payloads {
		payloads[i] = make([]byte, 65535)
	}
	trickle(server, seal(testAEAD(t), payloads...), nil, 0)
	r := newTestReader(t, client)
	buf := make([]byte, 65535)
	// One run reads every chunk, so even one allocation among them shows. A
	// collection would empty the buffer pool and count its refill.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	if allocs := testing.AllocsPerRun(1, func() {
		for range chunks {
			if _, err := io.ReadFull(r, buf); err != nil {
				t.Fatal(err)
			}
		}
	}); allocs != 0 {
		t.Fatalf("%v allocations in %d chunks", allocs, chunks)
	}
}
