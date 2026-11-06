package direct

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const tcpiOptSYNData = 0x20 // TCPI_OPT_SYN_DATA

func tcpInfo(t *testing.T, conn net.Conn) *unix.TCPInfo {
	t.Helper()
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var info *unix.TCPInfo
	_ = raw.Control(func(fd uintptr) { info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) })
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// fastOpenNamespace moves the test's thread, which then dies with the test,
// into a private network namespace with client and server Fast Open and an
// empty cookie cache. Its loopback delays packets, so a handshake deferred to
// the first write is still in progress when the write returns.
func fastOpenNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for a private network namespace")
	}
	runtime.LockOSThread()
	if _, err := netns.New(); err != nil {
		t.Fatal(err)
	}
	lo, err := netlink.LinkByName("lo")
	if err == nil {
		err = netlink.LinkSetUp(lo)
	}
	if err == nil {
		err = os.WriteFile("/proc/sys/net/ipv4/tcp_fastopen", []byte("3"), 0)
	}
	if err != nil {
		t.Fatal(err)
	}
	delay := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: lo.Attrs().Index, Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{Latency: 10_000})
	if err := netlink.QdiscAdd(delay); err != nil {
		t.Skipf("netem: %v", err)
	}
}

func fastOpenListener(t *testing.T, multipath bool, address string) net.Listener {
	t.Helper()
	config := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var err error
		_ = c.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 16) })
		return err
	}}
	config.SetMultipathTCP(multipath)
	listener, err := config.Listen(t.Context(), "tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

// The first connection to a server fetches its cookie in a full handshake;
// the next returns from the dial before its SYN, which carries the first
// write. CloseWrite right after that write waits for the handshake: Linux
// would disconnect the socket in SYN_SENT and discard the request.
func TestDirectDialerSendsFirstWriteInSYN(t *testing.T) {
	fastOpenNamespace(t)
	listener := fastOpenListener(t, false, "127.0.0.1:0")
	accepted := serve(t, listener)
	dialer := NewDirectDialer(Option{TCPFastOpen: true})
	for _, test := range []struct {
		state uint8
		inSYN bool
	}{{unix.BPF_TCP_ESTABLISHED, false}, {unix.BPF_TCP_SYN_SENT, true}} {
		conn, err := dialer.DialContext(t.Context(), "tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if state := tcpInfo(t, conn).State; state != test.state {
			t.Fatalf("state after dial = %d, want %d", state, test.state)
		}
		if netproxy.NativeTCPConn(conn) == nil {
			t.Fatal("dialed connection hides its native socket")
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		if err := netproxy.CloseWrite(conn); err != nil {
			t.Fatal(err)
		}
		server := <-accepted
		request, err := io.ReadAll(server)
		if err != nil || string(request) != "ping" {
			t.Fatalf("server read %q, %v", request, err)
		}
		if inSYN := tcpInfo(t, server).Options&tcpiOptSYNData != 0; inSYN != test.inSYN {
			t.Fatalf("first write in SYN = %v, want %v", inSYN, test.inSYN)
		}
		_, _ = server.Write([]byte("pong"))
		_ = server.Close()
		reply, err := io.ReadAll(conn)
		if err != nil || string(reply) != "pong" {
			t.Fatalf("client read %q, %v", reply, err)
		}
		_ = conn.Close()
	}
}

// A failed MPTCP probe teaches nothing, also when a Fast Open cookie for the
// address would let Go's plain TCP retry return before its handshake.
func TestMultipathProbeIgnoresFastOpenCookie(t *testing.T) {
	fastOpenNamespace(t)
	issuer := fastOpenListener(t, false, "127.0.0.1:0")
	accepted := serve(t, issuer)
	plain := NewDirectDialer(Option{TCPFastOpen: true})
	conn, err := plain.DialContext(t.Context(), "tcp4", issuer.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("cookie"))
	_ = conn.Close()
	_ = (<-accepted).Close()
	closed := fastOpenListener(t, true, "127.0.0.1:0")
	refused := closed.Addr().String()
	_ = closed.Close()
	// Cookies are per address: plain TCP to the closed port connects at once.
	conn, err = plain.DialContext(t.Context(), "tcp4", refused)
	if err != nil {
		t.Fatalf("no cookie for %s: %v", refused, err)
	}
	_ = conn.Close()
	dialer := NewDirectDialer(Option{Mptcp: true, Multipath: new(MultipathMemory), TCPFastOpen: true})
	if _, err := dialer.DialContext(t.Context(), "tcp4", refused); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("probe to a closed port: %v", err)
	}
	serve(t, fastOpenListener(t, true, refused))
	requireMultipathNegotiation(t, refused)
	conn, err = dialer.DialContext(t.Context(), "tcp4", refused)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	negotiated := false
	if tcp, ok := conn.(*net.TCPConn); ok {
		negotiated, _ = tcp.MultipathTCP()
	}
	if !negotiated {
		t.Fatal("a failed probe taught plain TCP")
	}
}

// An established Fast Open connection half-closes regardless of an expired
// write deadline, as a plain socket does; only a pending handshake waits.
func TestFastOpenCloseWriteIgnoresExpiredDeadline(t *testing.T) {
	fastOpenNamespace(t)
	listener := fastOpenListener(t, false, "127.0.0.1:0")
	accepted := serve(t, listener)
	dialer := NewDirectDialer(Option{TCPFastOpen: true})
	for range 2 { // The first connection fetches the cookie.
		conn, err := dialer.DialContext(t.Context(), "tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		server := <-accepted
		for deadline := time.Now().Add(5 * time.Second); tcpInfo(t, conn).State != unix.BPF_TCP_ESTABLISHED; {
			if time.Now().After(deadline) {
				t.Fatal("handshake did not complete")
			}
			time.Sleep(time.Millisecond)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(-time.Second))
		if err := netproxy.CloseWrite(conn); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		if request, err := io.ReadAll(server); err != nil || string(request) != "ping" {
			t.Fatalf("server read %q, %v", request, err)
		}
		_ = server.Close()
		_ = conn.Close()
	}
}
