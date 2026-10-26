package netproxy

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// tcpPair returns the client and server ends of a loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

func sockopt(t *testing.T, conn *net.TCPConn, level, name int) (n int) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) { n, optErr = unix.GetsockoptInt(int(fd), level, name) }); err != nil || optErr != nil {
		t.Fatal(err, optErr)
	}
	return n
}

// Wait holds the writer while the socket keeps half the limit unsent, and
// lets it go once the peer reads.
func TestCarrierGateWaitsForUnsentBytes(t *testing.T) {
	client, server := tcpPair(t)
	gate := NewCarrierGate(TrackConn(client, func() {}))
	if gate.Unit() != MinUnsent/2 || sockopt(t, client, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT) != MinUnsent {
		t.Fatalf("unit %d, lowat %d", gate.Unit(), sockopt(t, client, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT))
	}
	if err := gate.Wait(true); err != nil {
		t.Fatal(err)
	}
	// Fill the peer's receive buffer and then the send queue, without a
	// writer competing with the gate for the socket.
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 16<<10)
	for full := false; !full; {
		_ = raw.Control(func(fd uintptr) {
			_, err := unix.SendmsgN(int(fd), chunk, nil, nil, unix.MSG_DONTWAIT)
			full = err == unix.EAGAIN
		})
	}
	waits := GateWaits()
	passed := make(chan error, 1)
	go func() { passed <- gate.Wait(true) }()
	select {
	case err := <-passed:
		t.Fatalf("passed with half the limit unsent: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	go func() { _, _ = io.Copy(io.Discard, server) }()
	select {
	case err := <-passed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("still waiting after the peer read")
	}
	if GateWaits() != waits+1 || gate.passes != 2 || gate.waits != 1 {
		t.Fatalf("%d waits counted, %d of %d passes waited", GateWaits()-waits, gate.waits, gate.passes)
	}
}

// L follows the rate, rises while the writer holds the pace and decays
// otherwise, within MinUnsent and half the send buffer.
func TestCarrierGateAdaptsUnsentLimit(t *testing.T) {
	client, _ := tcpPair(t)
	_ = client.SetWriteBuffer(1 << 20)
	gate := NewCarrierGate(client)
	lowat := func() int { return sockopt(t, client, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT) }
	now := time.Now()
	gate.Adjust(now, 5e6) // 40 Mbit/s: 30 KB in 6 ms
	if lowat() != 30000 || gate.Unit() != 15000 {
		t.Fatalf("lowat %d, unit %d at 5 MB/s", lowat(), gate.Unit())
	}
	gate.Adjust(now, 5.5e6) // within a quarter: no system call
	if lowat() != 30000 || gate.unsent != 33000 {
		t.Fatalf("lowat %d after a small change", lowat())
	}
	// A writer slower than the carrier: busy passes do not wait, and its
	// measured rate shrinks.
	for i := range 3 {
		gate.passes, gate.waits = 10, 0
		now = now.Add(gateWindow)
		gate.Adjust(now, 1e5)
		if want := 33000 << (i + 1); lowat() != want {
			t.Fatalf("window %d: lowat %d, want %d", i, lowat(), want)
		}
	}
	gate.passes, gate.waits = 10, 6
	now = now.Add(gateWindow)
	gate.Adjust(now, 1e5)
	// L decays; the socket keeps its limit until L moved by a quarter.
	if want := 264000 * 7 / 8; gate.unsent != want || lowat() != 264000 {
		t.Fatalf("L %d, lowat %d after a carrier-bound window, want %d", gate.unsent, lowat(), want)
	}
	gate.floor = 1 << 30
	gate.Adjust(now, 0)
	if want := sockopt(t, client, unix.SOL_SOCKET, unix.SO_SNDBUF) / 2; lowat() != want {
		t.Fatalf("lowat %d, want half the send buffer %d", lowat(), want)
	}
	gate.floor = 0
	gate.Adjust(now, 0)
	if lowat() != MinUnsent {
		t.Fatalf("lowat %d without rate, want %d", lowat(), MinUnsent)
	}
}

// Without a TCP socket under the carrier the gate does nothing.
func TestCarrierGateWithoutSocket(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	gate := NewCarrierGate(local)
	gate.Adjust(time.Now(), 1e9)
	if err := gate.Wait(true); err != nil || gate.Unit() != MaxUnit {
		t.Fatalf("Wait = %v, unit %d", err, gate.Unit())
	}
}

func TestCarrierGateWriterFloorStopsAtSendBuffer(t *testing.T) {
	client, _ := tcpPair(t)
	gate := NewCarrierGate(client)
	now := time.Now()
	for range 100 {
		gate.passes = 10
		gate.waits = 0
		now = now.Add(gateWindow)
		gate.Adjust(now, 1)
	}
	ceiling := max(gate.sndbuf/2, MinUnsent)
	if gate.floor > float64(ceiling) {
		t.Fatalf("writer-bound floor %.0f exceeds ceiling %d", gate.floor, ceiling)
	}
	gate.passes, gate.waits = 10, 10
	gate.Adjust(now.Add(gateWindow), 1)
	if gate.floor != float64(ceiling)*7/8 {
		t.Fatalf("floor %.0f failed to decay after the writer recovered", gate.floor)
	}
}

// RawConn.Write uses the socket deadline too, so gate and Write share one
// budget rather than each getting a fresh timeout.
func TestCarrierGateUsesWriteDeadline(t *testing.T) {
	client, _ := tcpPair(t)
	gate := NewCarrierGate(client)
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 16<<10)
	for full := false; !full; {
		if err := raw.Control(func(fd uintptr) {
			_, err := unix.SendmsgN(int(fd), chunk, nil, nil, unix.MSG_DONTWAIT)
			full = err == unix.EAGAIN
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := gate.Wait(true); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("gate: %v", err)
	}
	if _, err := client.Write(chunk); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write got a fresh budget: %v", err)
	}
}
