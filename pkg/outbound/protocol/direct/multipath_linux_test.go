package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

const ipprotoMPTCP = 262

func rawProtocol(c syscall.RawConn) int {
	protocol := -1
	_ = c.Control(func(fd uintptr) {
		protocol, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
	})
	return protocol
}

func multipathTestListener(t testing.TB, multipath bool) string {
	t.Helper()
	var config net.ListenConfig
	config.SetMultipathTCP(multipath)
	listener, err := config.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return listener.Addr().String()
}

// dialProtocol reports the dialed socket's protocol and whether it negotiated MPTCP.
func dialProtocol(t *testing.T, dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}, address string) (int, bool) {
	t.Helper()
	conn, err := dialer.DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	negotiated, _ := conn.(*net.TCPConn).MultipathTCP()
	return rawProtocol(raw), negotiated
}

func TestMultipathMemoryDialsTCPAfterFallback(t *testing.T) {
	plain, multipath := multipathTestListener(t, false), multipathTestListener(t, true)
	memory := new(MultipathMemory)
	dialer := NewDirectDialer(Option{Mptcp: true, Multipath: memory})
	if protocol, negotiated := dialProtocol(t, dialer, plain); protocol != ipprotoMPTCP || negotiated {
		t.Skipf("MPTCP unavailable: first dial protocol=%d negotiated=%v", protocol, negotiated)
	}
	for range 2 {
		if protocol, _ := dialProtocol(t, dialer, plain); protocol != syscall.IPPROTO_TCP {
			t.Fatalf("fallen-back destination dialed with protocol %d", protocol)
		}
	}
	if _, negotiated := dialProtocol(t, dialer, multipath); !negotiated {
		t.Log("MPTCP does not negotiate on this loopback")
	} else if protocol, negotiated := dialProtocol(t, dialer, multipath); protocol != ipprotoMPTCP || !negotiated {
		t.Fatalf("MPTCP destination dialed with protocol %d, negotiated=%v", protocol, negotiated)
	}
	memory.Reset()
	if protocol, _ := dialProtocol(t, dialer, plain); protocol != ipprotoMPTCP {
		t.Fatalf("Reset kept the fallback; protocol %d", protocol)
	}
	// Without memory, as for direct outbounds, every dial uses MPTCP.
	always := NewDirectDialer(Option{Mptcp: true})
	for range 2 {
		if protocol, _ := dialProtocol(t, always, plain); protocol != ipprotoMPTCP {
			t.Fatalf("memoryless dialer used protocol %d", protocol)
		}
	}
	if protocol, _ := dialProtocol(t, NewDirectDialer(Option{Multipath: memory}), multipath); protocol != syscall.IPPROTO_TCP {
		t.Fatalf("disabled MPTCP dialed with protocol %d", protocol)
	}
}

// Dials that fail or are canceled teach nothing: an unknown destination stays
// unknown and a capable one stays capable.
func TestMultipathMemoryIgnoresFailedDials(t *testing.T) {
	plain, multipath := multipathTestListener(t, false), multipathTestListener(t, true)
	if protocol, _ := dialProtocol(t, NewDirectDialer(Option{Mptcp: true}), plain); protocol != ipprotoMPTCP {
		t.Skipf("MPTCP unavailable: protocol %d", protocol)
	}
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := closed.Addr().String()
	_ = closed.Close()
	memory := new(MultipathMemory)
	dialer := NewDirectDialer(Option{Mptcp: true, Multipath: memory})
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := dialer.DialContext(canceled, "tcp", plain); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial: %v", err)
	}
	if _, err := dialer.DialContext(t.Context(), "tcp", refused); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("refused dial: %v", err)
	}
	if len(memory.states) != 0 {
		t.Fatalf("failed dials were remembered: %v", memory.states)
	}
	for _, want := range []int{ipprotoMPTCP, syscall.IPPROTO_TCP} {
		if protocol, _ := dialProtocol(t, dialer, plain); protocol != want {
			t.Fatalf("dial after failures used protocol %d, want %d", protocol, want)
		}
	}
	if _, negotiated := dialProtocol(t, dialer, multipath); !negotiated {
		t.Skip("MPTCP does not negotiate on this loopback")
	}
	if _, err := dialer.DialContext(canceled, "tcp", multipath); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial: %v", err)
	}
	if protocol, negotiated := dialProtocol(t, dialer, multipath); protocol != ipprotoMPTCP || !negotiated {
		t.Fatalf("canceled dial forgot MPTCP: protocol %d, negotiated %v", protocol, negotiated)
	}
}

func TestMultipathMemoryProbesOnce(t *testing.T) {
	var memory MultipathMemory
	key := multipathKey{mark: 1, iface: "wan", addr: netip.MustParseAddrPort("192.0.2.1:443")}
	table, probe := memory.choose(key)
	if !probe {
		t.Fatal("unknown destination was not probed")
	}
	if _, concurrent := memory.choose(key); concurrent {
		t.Fatal("concurrent dial joined the probe")
	}
	if _, other := memory.choose(multipathKey{mark: 2, iface: "wan", addr: key.addr}); !other {
		t.Fatal("another mark shared the probe")
	}
	memory.settle(table, key, multipathUnknown)
	if table, probe = memory.choose(key); !probe {
		t.Fatal("failed probe was remembered")
	}
	memory.settle(table, key, multipathCapable)
	table, capable := memory.choose(key)
	if !capable {
		t.Fatal("capable destination dialed without MPTCP")
	}
	memory.settle(table, key, multipathUnknown)
	if table, capable = memory.choose(key); !capable {
		t.Fatal("failed dial forgot a capable destination")
	}
	memory.settle(table, key, multipathIncapable)
	if _, capable = memory.choose(key); capable {
		t.Fatal("fallback was not remembered")
	}
	memory.Reset()
	table, _ = memory.choose(key)
	memory.Reset()
	memory.settle(table, key, multipathIncapable)
	if _, probe = memory.choose(key); !probe {
		t.Fatal("probe from before Reset was remembered")
	}
	for port := range uint16(multipathMemoryLimit + 8) {
		other := multipathKey{addr: netip.AddrPortFrom(key.addr.Addr(), port)}
		table, probe := memory.choose(other)
		if !probe {
			t.Fatalf("destination %v was not probed at the limit", other.addr)
		}
		memory.settle(table, other, multipathIncapable)
	}
	if len(memory.states) > multipathMemoryLimit {
		t.Fatalf("memory holds %d destinations", len(memory.states))
	}
}

func TestEndedDialStartsNoTCPRetry(t *testing.T) {
	address := multipathTestListener(t, false)
	dialer := NewDirectDialer(Option{Mptcp: true}).(*directDialer)
	control := dialer.dialer.ControlContext
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var protocols []int
	var results []error
	dialer.dialer.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if len(protocols) == 0 {
			cancel() // As for a happy eyeballs attempt that lost the race.
		}
		protocols = append(protocols, rawProtocol(c))
		err := control(ctx, network, address, c)
		results = append(results, err)
		return err
	}
	if _, err := dialer.DialContext(ctx, "tcp", address); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial: %v", err)
	}
	if protocols[0] != ipprotoMPTCP {
		t.Skipf("MPTCP unavailable: protocol %d", protocols[0])
	}
	if len(protocols) != 2 || protocols[1] != syscall.IPPROTO_TCP || results[1] == nil {
		t.Fatalf("Go's TCP retry of a canceled dial: protocols %v, control results %v", protocols, results)
	}
}

// BenchmarkMultipathFallbackDial dials a TCP-only listener with MPTCP enabled.
// cpu-ns/op includes the local accept side.
func BenchmarkMultipathFallbackDial(b *testing.B) {
	for _, remember := range []bool{false, true} {
		b.Run(fmt.Sprintf("memory=%t", remember), func(b *testing.B) {
			option := Option{Mptcp: true}
			if remember {
				option.Multipath = new(MultipathMemory)
			}
			dialer, address := NewDirectDialer(option), multipathTestListener(b, false)
			var start, end syscall.Rusage
			_ = syscall.Getrusage(syscall.RUSAGE_SELF, &start)
			b.ReportAllocs()
			for b.Loop() {
				conn, err := dialer.DialContext(b.Context(), "tcp", address)
				if err != nil {
					b.Fatal(err)
				}
				_ = conn.(*net.TCPConn).SetLinger(0) // Avoid TIME_WAIT buildup.
				_ = conn.Close()
			}
			_ = syscall.Getrusage(syscall.RUSAGE_SELF, &end)
			cpu := end.Utime.Nano() + end.Stime.Nano() - start.Utime.Nano() - start.Stime.Nano()
			b.ReportMetric(float64(cpu)/float64(b.N), "cpu-ns/op")
		})
	}
}
