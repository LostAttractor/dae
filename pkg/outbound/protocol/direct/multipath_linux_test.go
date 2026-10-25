package direct

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

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

// serve hands the test each connection listener accepts.
func serve(t testing.TB, listener net.Listener) <-chan net.Conn {
	accepted := make(chan net.Conn, 4)
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		for conn := range accepted {
			_ = conn.Close()
		}
	})
	return accepted
}

// dialServed dials address and reports the dialed socket's protocol and
// how many connections the server accepted before it, each of which must
// be closed: a fallen-back probe connects before the dial replacing it.
func dialServed(t *testing.T, dialer netproxy.Dialer, address string, accepted <-chan net.Conn) (protocol, probes int) {
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
	for ; ; probes++ {
		served, ok := <-accepted
		if !ok {
			t.Fatal("listener stopped accepting")
		}
		if served.RemoteAddr().String() == conn.LocalAddr().String() {
			_ = served.Close()
			return rawProtocol(raw), probes
		}
		_ = served.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := served.Read(make([]byte, 1))
		_ = served.Close()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("probe left open: %v", err)
		}
	}
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

func requireMultipathNegotiation(t *testing.T, address string) {
	t.Helper()
	var independent net.Dialer
	independent.SetMultipathTCP(true)
	if protocol, negotiated := dialProtocol(t, &independent, address); protocol != unix.IPPROTO_MPTCP || !negotiated {
		t.Skipf("independent dial cannot negotiate MPTCP: protocol=%d negotiated=%v", protocol, negotiated)
	}
}

// countDials counts the MPTCP sockets dialer creates and the sockets its
// plain TCP dialer creates.
func countDials(dialer netproxy.Dialer) (probes, plain *int) {
	d := dialer.(*directDialer)
	probes, plain = new(int), new(int)
	multipath, tcp := d.multipath.ControlContext, d.dialer.ControlContext
	d.multipath.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if rawProtocol(c) == unix.IPPROTO_MPTCP {
			*probes++
		}
		return multipath(ctx, network, address, c)
	}
	d.dialer.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		*plain++
		return tcp(ctx, network, address, c)
	}
	return probes, plain
}

func TestMultipathMemoryDialsTCPAfterFallback(t *testing.T) {
	var config net.ListenConfig
	config.SetMultipathTCP(false)
	listener, err := config.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	plain, multipath, accepted := listener.Addr().String(), multipathTestListener(t, true), serve(t, listener)
	requireMultipathNegotiation(t, multipath)
	// Without memory, as for direct outbounds, every dial uses MPTCP.
	always := NewDirectDialer(Option{Mptcp: true})
	if protocol, probes := dialServed(t, always, plain, accepted); protocol != unix.IPPROTO_MPTCP || probes != 0 {
		t.Fatalf("memoryless dialer used protocol=%d after %d probes", protocol, probes)
	}
	if protocol, _ := dialServed(t, always, plain, accepted); protocol != unix.IPPROTO_MPTCP {
		t.Fatalf("memoryless dialer used protocol %d", protocol)
	}
	memory := new(MultipathMemory)
	dialer := NewDirectDialer(Option{Mptcp: true, Multipath: memory})
	probes, plains := countDials(dialer)
	// The probe falls back and is closed once a plain TCP dial replaces it.
	for i, want := range []int{1, 0, 0} {
		if protocol, closed := dialServed(t, dialer, plain, accepted); protocol != syscall.IPPROTO_TCP || closed != want || *probes != 1 || *plains != i+1 {
			t.Fatalf("fallen-back destination dialed with protocol %d after %d closed probes, %d probes and %d plain dials", protocol, closed, *probes, *plains)
		}
	}
	before := *plains
	for range 2 {
		if protocol, negotiated := dialProtocol(t, dialer, multipath); protocol != unix.IPPROTO_MPTCP || !negotiated || *plains != before {
			t.Fatalf("MPTCP destination dialed with protocol %d, negotiated=%v, plain dials=%d", protocol, negotiated, *plains-before)
		}
	}
	probed, replaced := *probes, *plains
	memory.Reset()
	if protocol, closed := dialServed(t, dialer, plain, accepted); protocol != syscall.IPPROTO_TCP || closed != 1 || *probes != probed+1 || *plains != replaced+1 {
		t.Fatalf("dial after Reset used protocol %d after %d closed probes, %d probes and %d plain dials", protocol, closed, *probes-probed, *plains-replaced)
	}
	if protocol, _ := dialProtocol(t, NewDirectDialer(Option{Multipath: memory}), multipath); protocol != syscall.IPPROTO_TCP {
		t.Fatalf("disabled MPTCP dialed with protocol %d", protocol)
	}
}

// Dials that fail or are canceled teach nothing: an unknown destination stays
// unknown and a capable one stays capable.
func TestMultipathMemoryIgnoresFailedDials(t *testing.T) {
	plain, multipath := multipathTestListener(t, false), multipathTestListener(t, true)
	requireMultipathNegotiation(t, multipath)
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := closed.Addr().String()
	_ = closed.Close()
	memory := new(MultipathMemory)
	dialer := NewDirectDialer(Option{Mptcp: true, Multipath: memory})
	probes, plains := countDials(dialer)
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
	failed := *probes
	for range 2 {
		if protocol, _ := dialProtocol(t, dialer, plain); protocol != syscall.IPPROTO_TCP || *probes != failed+1 {
			t.Fatalf("dial after failures used protocol %d after %d probes", protocol, *probes-failed)
		}
	}
	before := *plains
	if protocol, negotiated := dialProtocol(t, dialer, multipath); protocol != unix.IPPROTO_MPTCP || !negotiated || *plains != before {
		t.Fatalf("MPTCP destination dialed with protocol %d, negotiated=%v, plain dials=%d", protocol, negotiated, *plains-before)
	}
	if _, err := dialer.DialContext(canceled, "tcp", multipath); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial: %v", err)
	}
	if protocol, negotiated := dialProtocol(t, dialer, multipath); protocol != unix.IPPROTO_MPTCP || !negotiated || *plains != before {
		t.Fatalf("canceled dial forgot MPTCP: protocol %d, negotiated=%v, plain dials=%d", protocol, negotiated, *plains-before)
	}
}

// A probe that fell back is kept when plain TCP cannot replace it, also
// when that dial does not connect, without spending the caller's deadline.
func TestMultipathFallbackKeptWithoutPlainTCP(t *testing.T) {
	plain := multipathTestListener(t, false)
	if protocol, negotiated := dialProtocol(t, NewDirectDialer(Option{Mptcp: true}), plain); protocol != unix.IPPROTO_MPTCP || negotiated {
		t.Skipf("MPTCP unavailable: protocol=%d negotiated=%v", protocol, negotiated)
	}
	for name, control := range map[string]func(context.Context) error{
		"refused": func(context.Context) error { return syscall.ECONNREFUSED },
		// As for a SYN the server drops.
		"unanswered": func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
	} {
		t.Run(name, func(t *testing.T) {
			dialer := NewDirectDialer(Option{Mptcp: true, Multipath: new(MultipathMemory)}).(*directDialer)
			plains := 0
			dialer.dialer.ControlContext = func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
				plains++
				return control(ctx)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*synRetransmitTimeout)
			defer cancel()
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", plain)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			raw, err := conn.(*net.TCPConn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			// A closed probe reports protocol -1.
			if protocol := rawProtocol(raw); protocol != unix.IPPROTO_MPTCP || plains != 1 {
				t.Fatalf("dial returned protocol %d after %d plain dials; want the open probe after 1", protocol, plains)
			}
			if elapsed >= 2*synRetransmitTimeout || ctx.Err() != nil {
				t.Fatalf("dial took %v, caller context: %v", elapsed, ctx.Err())
			}
		})
	}
}

func TestMultipathFallbackLeavesHandshakeBudget(t *testing.T) {
	var config net.ListenConfig
	config.SetMultipathTCP(false)
	listener, err := config.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	t.Cleanup(server.Close)
	var independent net.Dialer
	independent.SetMultipathTCP(true)
	if protocol, negotiated := dialProtocol(t, &independent, listener.Addr().String()); protocol != unix.IPPROTO_MPTCP || negotiated {
		t.Skipf("MPTCP fallback unavailable: protocol=%d negotiated=%v", protocol, negotiated)
	}
	endpoint := netip.MustParseAddrPort(listener.Addr().String())
	for name, address := range map[string]string{
		"ip":       endpoint.String(),
		"hostname": net.JoinHostPort("mptcp.test", strconv.Itoa(int(endpoint.Port()))),
	} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name               string
				budget, probeDelay time.Duration
			}{
				{"short", 200 * time.Millisecond, 0},
				{"half-second", 500 * time.Millisecond, 0},
				{"slow-probe", 3 * time.Second, time.Second},
				{"long-slow-probe", 8 * time.Second, 3 * time.Second},
			} {
				t.Run(tc.name, func(t *testing.T) {
					dialer := NewDirectDialer(Option{
						Mptcp: true, Multipath: new(MultipathMemory),
						Lookup: func(context.Context, string, string) ([]netip.Addr, error) {
							return []netip.Addr{endpoint.Addr()}, nil
						},
					}).(*directDialer)
					control := dialer.multipath.ControlContext
					dialer.multipath.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
						timer := time.NewTimer(tc.probeDelay)
						defer timer.Stop()
						select {
						case <-timer.C:
							return control(ctx, network, address, c)
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					// As for a replacement SYN the server drops.
					dialer.dialer.ControlContext = func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
						<-ctx.Done()
						return ctx.Err()
					}
					probes, plains := countDials(dialer)
					ctx, cancel := context.WithTimeout(t.Context(), tc.budget)
					defer cancel()
					start := time.Now()
					conn, err := dialer.DialContext(ctx, "tcp", address)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					if !mptcpSocket(conn.(*net.TCPConn)) || *probes != 1 || *plains != 1 {
						t.Fatalf("did not keep the probe: MPTCP=%v, probes=%d, plain dials=%d", mptcpSocket(conn.(*net.TCPConn)), *probes, *plains)
					}
					if ctx.Err() != nil {
						t.Fatalf("dial exhausted caller's budget after %v: %v", time.Since(start), ctx.Err())
					}
					deadline, _ := ctx.Deadline()
					t.Logf("dial took %v, handshake budget remaining %v", time.Since(start), time.Until(deadline))
					if err := conn.SetDeadline(deadline); err != nil {
						t.Fatal(err)
					}
					tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
					tlsConfig.ServerName = endpoint.Addr().String()
					client := tls.Client(conn, tlsConfig)
					defer client.Close()
					if err := client.HandshakeContext(ctx); err != nil {
						t.Fatalf("fallback TLS handshake: %v", err)
					}
					if _, err := io.WriteString(client, "GET / HTTP/1.0\r\n\r\n"); err != nil {
						t.Fatal(err)
					}
					response, err := http.ReadResponse(bufio.NewReader(client), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					if body, err := io.ReadAll(response.Body); err != nil || string(body) != "ok" {
						t.Fatalf("fallback TLS response: %q, %v", body, err)
					}
				})
			}
		})
	}
}

// mptcpSYNs counts the MP_CAPABLE SYNs the calling thread's network
// namespace sent, or returns -1 without MPTCP.
func mptcpSYNs(t *testing.T) int64 {
	t.Helper()
	netstat, err := os.ReadFile("/proc/thread-self/net/netstat")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(netstat), "\n")
	for i := 0; i+1 < len(lines); i++ {
		keys, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		if j := slices.Index(keys, "MPCapableSYNTX"); j > 0 && keys[0] == "MPTcpExt:" && j < len(values) {
			count, err := strconv.ParseInt(values[j], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return count
		}
	}
	return -1
}

// The server's kernel has MPTCP disabled: the first dial probes with MPTCP,
// falls back, and returns plain TCP; later dials do not probe. A client
// kernel without MPTCP sends no probe to replace.
func TestMultipathMemoryReplacesFallbackFromServerWithoutMPTCP(t *testing.T) {
	// Sockets and sysctls belong to the namespace of this locked thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	previous, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer previous.Close()
	client, err := netns.New()
	if errors.Is(err, syscall.EPERM) {
		t.Skip("network namespace requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer func() {
		if err := netns.Set(previous); err != nil {
			t.Fatal(err)
		}
	}()
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "mptcpc"}, PeerName: "mptcps"}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	server, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := os.WriteFile("/proc/sys/net/mptcp/enabled", []byte("0"), 0); err != nil {
		t.Skipf("MPTCP unavailable: %v", err)
	}
	up := func(name, prefix string) {
		t.Helper()
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		addr, err := netlink.ParseAddr(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}
	if err := netns.Set(client); err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName(link.PeerName)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(peer, int(server)); err != nil {
		t.Fatal(err)
	}
	up(link.Name, "10.78.0.1/24")
	if err := netns.Set(server); err != nil {
		t.Fatal(err)
	}
	up(link.PeerName, "10.78.0.2/24")
	listener, err := net.Listen("tcp4", "10.78.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := serve(t, listener)
	if err := netns.Set(client); err != nil {
		t.Fatal(err)
	}
	if mptcpSYNs(t) < 0 {
		t.Skip("MPTCP unavailable")
	}
	memory := new(MultipathMemory)
	dialer := NewDirectDialer(Option{Mptcp: true, Multipath: memory})
	for i, probes := range []int{1, 0, 0} {
		if i == 2 {
			// The client's kernel now refuses MPTCP sockets: Go dials the
			// probe as plain TCP, which is kept.
			memory.Reset()
			if err := os.WriteFile("/proc/sys/net/mptcp/enabled", []byte("0"), 0); err != nil {
				t.Fatal(err)
			}
		}
		syns := mptcpSYNs(t)
		protocol, closed := dialServed(t, dialer, listener.Addr().String(), accepted)
		if sent := mptcpSYNs(t) - syns; protocol != syscall.IPPROTO_TCP || sent != int64(probes) || closed != probes {
			t.Fatalf("dial returned protocol %d after %d MPTCP SYNs and %d closed probes, want TCP after %d of each", protocol, sent, closed, probes)
		}
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
	if protocols[0] != unix.IPPROTO_MPTCP {
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
