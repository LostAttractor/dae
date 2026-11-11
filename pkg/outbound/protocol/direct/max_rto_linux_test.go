package direct

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func maxRTOTestPair(t *testing.T, network string, multipath bool) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 4096)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	config.SetMultipathTCP(multipath)
	address := "127.0.0.1:0"
	if network == "tcp6" {
		address = "[::1]:0"
	}
	listener, err := config.Listen(t.Context(), network, address)
	if err != nil {
		if network == "tcp6" {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		t.Fatal(err)
	}
	accepted := serve(t, listener)
	conn, err := NewDirectDialer(Option{
		Mptcp: multipath, TCPMaxRTO: 15 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 3},
	}).DialContext(t.Context(), network, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, peer := conn.(*net.TCPConn), (<-accepted).(*net.TCPConn)
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
	for _, c := range []*net.TCPConn{client, peer} {
		if err := c.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return client, peer
}

func tcpSocketOption(conn *net.TCPConn, option int) (value int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	if controlErr := raw.Control(func(fd uintptr) {
		value, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, option)
	}); controlErr != nil {
		return 0, controlErr
	}
	return value, err
}

func TestDirectDialerRetransmissionOptions(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, multipath := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mptcp=%v", network, multipath), func(t *testing.T) {
				t.Parallel()
				conn, _ := maxRTOTestPair(t, network, multipath)
				for option, want := range map[int]int{unix.TCP_KEEPIDLE: 15, unix.TCP_KEEPINTVL: 5, unix.TCP_KEEPCNT: 3} {
					if got, err := tcpSocketOption(conn, option); err != nil || got != want {
						t.Fatalf("TCP option %d = %d, %v; want %d", option, got, err, want)
					}
				}
				if mptcpSocket(conn) {
					return // Negotiated and fallen-back MPTCP both reject TCP_RTO_MAX_MS.
				}
				if got, err := tcpSocketOption(conn, unix.TCP_USER_TIMEOUT); err != nil || got != 0 {
					t.Fatalf("TCP_USER_TIMEOUT = %d, %v; want disabled", got, err)
				}
				if got, err := tcpSocketOption(conn, tcpRTOMaxMS); !errors.Is(err, unix.ENOPROTOOPT) && (err != nil || got != 15000) {
					t.Fatalf("TCP_RTO_MAX_MS = %d, %v; want 15000 or unsupported", got, err)
				}
			})
		}
	}
}

func TestMaxRTOUnsupportedOption(t *testing.T) {
	// UDP rejects TCP_RTO_MAX_MS like a TCP socket on an older kernel.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := setMaxRTO(raw, 15*time.Second); err != nil {
		t.Fatalf("unsupported option failed the socket: %v", err)
	}
	_ = conn.Close()
	if err := setMaxRTO(raw, 15*time.Second); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed socket error = %v", err)
	}
}

func TestMaxRTOPreservesOptionError(t *testing.T) {
	conn, peer := maxRTOTestPair(t, "tcp4", false)
	if _, err := tcpSocketOption(conn, tcpRTOMaxMS); errors.Is(err, unix.ENOPROTOOPT) {
		t.Skip("TCP_RTO_MAX_MS requires Linux 6.15 or newer")
	} else if err != nil {
		t.Fatal(err)
	}
	// Linux rejects a maximum RTO below one second; do not hide EINVAL.
	invalid := NewDirectDialer(Option{TCPMaxRTO: 500 * time.Millisecond})
	if c, err := invalid.DialContext(t.Context(), "tcp4", peer.LocalAddr().String()); c != nil || !errors.Is(err, unix.EINVAL) {
		if c != nil {
			_ = c.Close()
		}
		t.Fatalf("invalid TCP_RTO_MAX_MS: conn=%v, err=%v; want EINVAL", c, err)
	}
}

// queueZeroWindow leaves bytes buffered behind a peer that is alive but not
// reading. The writer is joined after socket cleanup, even when the test fails.
func queueZeroWindow(t *testing.T, conn *net.TCPConn) ([]byte, <-chan error) {
	t.Helper()
	payload := bytes.Repeat([]byte("x"), 1<<20)
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		defer close(done)
		_, err := conn.Write(payload)
		result <- err
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	deadline := time.Now().Add(3 * time.Second)
	for {
		info := tcpInfo(t, conn)
		if info.Snd_wnd == 0 && info.Notsent_bytes > 0 && info.Unacked == 0 {
			return payload, result
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not reach zero window: %+v", info)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDirectDialerPreservesLiveZeroWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("waits past the former 30s TCP_USER_TIMEOUT")
	}
	t.Parallel()
	conn, peer := maxRTOTestPair(t, "tcp4", false)
	payload, written := queueZeroWindow(t, conn)
	time.Sleep(32 * time.Second)
	if info := tcpInfo(t, conn); info.State != unix.BPF_TCP_ESTABLISHED {
		t.Fatalf("live zero-window connection closed: %+v", info)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("resumed transfer: write error=%v, payload equal=%v", err, bytes.Equal(got, payload))
	}
	if _, err := peer.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "ok" {
		t.Fatalf("reply after zero window = %q, %v", reply, err)
	}
}

// Model a peer shrinking its window before acknowledging in-flight data,
// without a packet injector. Repair is disabled before any timer is tested.
func shrinkTCPWindow(t *testing.T, conn *net.TCPConn) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
		if sockErr != nil {
			return
		}
		defer func() {
			sockErr = errors.Join(sockErr, unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF))
		}()
		// UAPI struct tcp_repair_window, preserving every field except snd_wnd.
		var window struct{ sndWL1, sndWnd, maxWindow, rcvWnd, rcvWup uint32 }
		size := uint32(unsafe.Sizeof(window))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_WINDOW, uintptr(unsafe.Pointer(&window)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			sockErr = errno
			return
		}
		if size != uint32(unsafe.Sizeof(window)) {
			sockErr = fmt.Errorf("unexpected TCP_REPAIR_WINDOW size: %d", size)
			return
		}
		window.sndWnd = 0
		_, _, errno = unix.Syscall6(unix.SYS_SETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_WINDOW, uintptr(unsafe.Pointer(&window)), uintptr(size), 0)
		if errno != 0 {
			sockErr = errno
		}
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
}

func TestDirectDialerBlackholes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for private network namespaces and netem")
	}
	if testing.Short() {
		t.Skip("waits for TCP retransmission and persist timeouts")
	}
	t.Parallel()
	for _, state := range []string{"idle", "unacked", "zero_window", "zero_window_inflight_recovery"} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			runtime.LockOSThread()
			previous, err := netns.Get()
			if err != nil {
				runtime.UnlockOSThread()
				t.Fatal(err)
			}
			namespace, err := netns.New()
			if err != nil {
				_ = previous.Close()
				runtime.UnlockOSThread()
				if errors.Is(err, unix.EPERM) {
					t.Skip("network namespace requires CAP_SYS_ADMIN")
				}
				t.Fatal(err)
			}
			t.Cleanup(func() {
				err := netns.Set(previous)
				_ = namespace.Close()
				_ = previous.Close()
				if err != nil {
					t.Fatal(err) // Do not return a thread in the test namespace to Go.
				}
				runtime.UnlockOSThread()
			})
			lo, err := netlink.LinkByName("lo")
			if err != nil {
				t.Fatal(err)
			}
			if err := netlink.LinkSetUp(lo); err != nil {
				t.Fatal(err)
			}
			retries, err := os.ReadFile("/proc/sys/net/ipv4/tcp_retries2")
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(retries)) != "15" {
				t.Skipf("timeout assertion requires default tcp_retries2=15, got %q", retries)
			}
			conn, peer := maxRTOTestPair(t, "tcp4", false)
			if err := conn.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
				t.Fatal(err)
			}
			if _, err := tcpSocketOption(conn, tcpRTOMaxMS); errors.Is(err, unix.ENOPROTOOPT) {
				t.Skip("TCP_RTO_MAX_MS requires Linux 6.15 or newer")
			} else if err != nil {
				t.Fatal(err)
			}
			if state == "zero_window" {
				queueZeroWindow(t, conn)
			}
			drop := netlink.NewNetem(netlink.QdiscAttrs{LinkIndex: lo.Attrs().Index, Parent: netlink.HANDLE_ROOT}, netlink.NetemQdiscAttrs{Loss: 100})
			if err := netlink.QdiscAdd(drop); err != nil {
				if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
					t.Skipf("netem unavailable: %v", err)
				}
				t.Fatal(err)
			}
			start := time.Now()
			if state == "unacked" || state == "zero_window_inflight_recovery" {
				if _, err := conn.Write([]byte("lost")); err != nil {
					t.Fatal(err)
				}
			}
			if state == "zero_window_inflight_recovery" {
				shrinkTCPWindow(t, conn)
				if info := tcpInfo(t, conn); info.Unacked == 0 || info.Snd_wnd != 0 {
					t.Fatalf("missing zero window with in-flight data: %+v", info)
				}
				// tcp_rtx_probe0_timed_out uses twice RTO_MAX, not tcp_retries2.
				time.Sleep(8 * time.Second)
				if info := tcpInfo(t, conn); info.State != unix.BPF_TCP_ESTABLISHED {
					t.Fatalf("transient outage killed the zero-window connection: %+v", info)
				}
				if err := netlink.QdiscDel(drop); err != nil {
					t.Fatal(err)
				}
				var payload [4]byte
				if _, err := io.ReadFull(peer, payload[:]); err != nil || string(payload[:]) != "lost" {
					t.Fatalf("recovered payload = %q, %v", payload, err)
				}
				if _, err := peer.Write([]byte("ok")); err != nil {
					t.Fatal(err)
				}
				var reply [2]byte
				if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "ok" {
					t.Fatalf("reply after recovery = %q, %v", reply, err)
				}
				return
			}
			var buf [1]byte
			_, err = conn.Read(buf[:])
			elapsed := time.Since(start)
			minimum, maximum := 2*time.Minute, 270*time.Second
			if state == "idle" {
				minimum, maximum = 15*time.Second, 40*time.Second
			}
			if !errors.Is(err, unix.ETIMEDOUT) || elapsed < minimum || elapsed > maximum {
				t.Fatalf("blackhole ended after %v with %v; want kernel ETIMEDOUT within %v–%v", elapsed, err, minimum, maximum)
			}
			t.Logf("kernel closed %s blackhole after %v: %v", state, elapsed, err)
		})
	}
}
