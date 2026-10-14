// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func nativeTestStart(t *testing.T, left, right net.Conn, monitor *tcpRelayMonitor, policy, route, owner *netproxy.Lease, direct bool) (<-chan error, stats.Path) {
	t.Helper()
	sniffer, ok := left.(sniffing.ConnSnifferInterface)
	if !ok {
		sniffer = sniffing.NewConnSniffer(left, 0)
		_, _ = sniffer.SniffTcp()
	}
	path := stats.Path{Dialer: t.Name(), NodeID: time.Now().String()}
	r := &tcpRelay{lConn: sniffer, rConn: right, direct: direct, monitor: monitor, policyLease: policy, routeLease: route, ownerLease: owner, statsPath: path, deviceMAC: [6]byte{2, 2}}
	done := make(chan error, 1)
	go func() { done <- r.run() }()
	return done, path
}

func nativeTestMonitor(t *testing.T) *tcpRelayMonitor {
	t.Helper()
	m := new(tcpRelayMonitor)
	m.setTimeouts(tcpIdleTimeouts{established: time.Minute, halfClosed: time.Minute})
	t.Cleanup(m.close)
	return m
}

func TestNativeTCPFullDuplexHalfCloseWithBacklog(t *testing.T) {
	for _, direct := range []bool{true, false} {
		name := "splice"
		if !direct {
			name = "ordinary"
		}
		t.Run(name, func(t *testing.T) {
			left, client := relayTestTCPPair(t)
			right, server := relayTestTCPPair(t)
			if err := right.SetWriteBuffer(32 << 10); err != nil {
				t.Fatal(err)
			}
			if err := server.SetReadBuffer(32 << 10); err != nil {
				t.Fatal(err)
			}
			payload := append([]byte("POST / HTTP/1.1\r\nHost: relay.example\r\n\r\n"), bytes.Repeat([]byte("payload"), 1<<17)...)
			written := make(chan error, 1)
			go func() { _, err := client.Write(payload); written <- errors.Join(err, client.CloseWrite()) }()
			sniffer := sniffing.NewConnSniffer(left, time.Second)
			if name, err := sniffer.SniffTcp(); err != nil || name != "relay.example" {
				t.Fatalf("sniff: %q %v", name, err)
			}
			// Exercise the actual production Runtime wrapper, including retirement.
			owner := netproxy.NewRuntime(netproxy.Layer{Data: tcpTestDialer{conn: right}})
			wrapped, err := owner.Dialer().DialContext(context.Background(), "tcp", "relay.example:80")
			if err != nil {
				t.Fatal(err)
			}
			done, path := nativeTestStart(t, sniffer, wrapped, nativeTestMonitor(t), nil, nil, nil, direct)
			owner.Retire()
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			reply := bytes.Repeat([]byte("reply"), 1<<17)
			serverDone := make(chan error, 1)
			go func() {
				// Reply and FIN precede consumption of the upload backlog. A shared
				// redirect/pass queue deadlocks here; independent TCP copies must progress.
				_, err := server.Write(reply)
				err = errors.Join(err, server.CloseWrite())
				got, readErr := io.ReadAll(server)
				if !bytes.Equal(got, payload) {
					readErr = errors.Join(readErr, errors.New("upload changed or prefix duplicated"))
				}
				serverDone <- errors.Join(err, readErr)
			}()
			got, err := io.ReadAll(client)
			if err != nil || !bytes.Equal(got, reply) {
				t.Fatalf("download: %d/%d, %v", len(got), len(reply), err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			if err := waitTCPRelayTest(t, done); err != nil {
				t.Fatal(err)
			}
			if err := owner.Wait(t.Context()); err != nil {
				t.Fatal(err)
			}
			gotStats := stats.DefaultStore.Snapshot()[path]
			if gotStats.UploadBytes != uint64(len(payload)) || gotStats.DownloadBytes != uint64(len(reply)) || gotStats.ActiveConnections != 0 {
				t.Fatalf("settled stats: %+v", gotStats)
			}
			devices, _ := stats.DefaultStore.DeviceSnapshot([6]byte{2, 2})
			if devices[path].TrafficCounters != gotStats.TrafficCounters {
				t.Fatal("device/global divergence")
			}
		})
	}
}

func TestNativeTCPAbortAndResetWithBacklog(t *testing.T) {
	for _, action := range []string{"reset", "owner_close", "policy", "route"} {
		t.Run(action, func(t *testing.T) {
			left, client := relayTestTCPPair(t)
			right, server := relayTestTCPPair(t)
			_ = right.SetWriteBuffer(4096)
			_ = server.SetReadBuffer(4096)
			policy, route := netproxy.NewLease(netproxy.NewResourceRef()), netproxy.NewLease(netproxy.NewResourceRef())
			m := nativeTestMonitor(t)
			tracked := new(tcpConnectionSet)
			tracked.add(left)
			defer tracked.remove(left)
			done, _ := nativeTestStart(t, left, right, m, policy, route, tracked.lease(left), true)
			if _, err := client.Write(bytes.Repeat([]byte("x"), 1<<20)); err != nil {
				t.Fatal(err)
			}
			_ = client.CloseWrite()
			waitNativeCondition(t, func() bool {
				raw, err := right.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var queued int
				_ = raw.Control(func(fd uintptr) { queued, _ = unix.IoctlGetInt(int(fd), unix.SIOCOUTQ) })
				return queued > 0
			})
			cause := netproxy.WrapFailure(errors.New("owner abort"), netproxy.Failure{Origin: netproxy.OriginLocalCleanup})
			switch action {
			case "reset":
				_ = server.SetLinger(0)
				_ = server.Close()
			case "owner_close":
				<-tracked.abort()
			case "policy":
				policy.Abort(cause)
			case "route":
				route.Abort(cause)
			}
			err := waitTCPRelayTest(t, done)
			if action == "reset" && (!errors.Is(err, syscall.ECONNRESET) || !strings.Contains(err.Error(), "TCP ")) {
				t.Fatalf("lost direction/errno: %v", err)
			}
			if action == "policy" || action == "route" {
				if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("owner abort did not reset client: %v", err)
				}
			}
		})
	}
}

func waitNativeCondition(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestNativeTCPIdleClosesBothWorkers(t *testing.T) {
	for _, direct := range []bool{true, false} {
		t.Run(map[bool]string{true: "splice", false: "ordinary"}[direct], func(t *testing.T) {
			left, client := relayTestTCPPair(t)
			right, server := relayTestTCPPair(t)
			m := nativeTestMonitor(t)
			m.setTimeouts(tcpIdleTimeouts{established: time.Millisecond, halfClosed: time.Millisecond})
			done, path := nativeTestStart(t, left, right, m, nil, nil, nil, direct)
			waitNativeCondition(t, func() bool {
				m.mu.Lock()
				defer m.mu.Unlock()
				return len(m.connections) == 1
			})
			time.Sleep(5 * time.Millisecond)
			m.sample()
			if err := waitTCPRelayTest(t, done); err != nil {
				t.Fatal(err)
			}
			for _, peer := range []*net.TCPConn{client, server} {
				if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("idle peer: %v", err)
				}
			}
			if got := stats.DefaultStore.Snapshot()[path]; got.ActiveConnections != 0 || got.UploadBytes != 0 || got.DownloadBytes != 0 {
				t.Fatal(got)
			}
		})
	}
}

func TestNativeTCPHalfClosedIdleTimeout(t *testing.T) {
	for _, direct := range []bool{true, false} {
		t.Run(map[bool]string{true: "splice", false: "ordinary"}[direct], func(t *testing.T) {
			left, client := relayTestTCPPair(t)
			right, server := relayTestTCPPair(t)
			m := nativeTestMonitor(t)
			m.setTimeouts(tcpIdleTimeouts{established: time.Hour, halfClosed: time.Millisecond})
			done, _ := nativeTestStart(t, left, right, m, nil, nil, nil, direct)
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			// The server receives the forwarded FIN but never closes its side.
			if _, err := server.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("forwarded FIN: %v", err)
			}
			waitNativeCondition(t, func() bool {
				m.sample()
				return len(done) == 1
			})
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := client.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("half-closed client: %v", err)
			}
		})
	}
}

func TestNativeTCPCounterFailureFallsBackBeforeConsumption(t *testing.T) {
	left, client := relayTestTCPPair(t)
	right, server := relayTestTCPPair(t)
	// A pending application write disqualifies the counter baseline.
	_ = right.SetWriteBuffer(4096)
	_ = server.SetReadBuffer(4096)
	prefix := bytes.Repeat([]byte("prefix"), 1<<17)
	prewrite := make(chan error, 1)
	go func() { _, err := right.Write(prefix); prewrite <- err }()
	waitNativeCondition(t, func() bool { _, err := tcpWriteCounter(right); return err != nil })
	traffic := stats.DefaultStore.OpenConnection(stats.Path{Dialer: t.Name(), NodeID: time.Now().String()}, false)
	defer traffic.Close()
	if pair, _ := nativeTCPPair(left, right); pair[0] != nil {
		t.Fatal("accepted invalid baseline")
	}
	payload := []byte("untouched source")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(left, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("probe consumed bytes: %q %v", got, err)
	}
	_ = server.Close()
	<-prewrite
}

func TestNativeTCPConcurrentSamplingAndClose(t *testing.T) {
	left, client := relayTestTCPPair(t)
	right, server := relayTestTCPPair(t)
	m := nativeTestMonitor(t)
	done, path := nativeTestStart(t, left, right, m, nil, nil, nil, true)
	stop, sampled := make(chan struct{}), make(chan struct{})
	var reads atomic.Int64
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stop:
				return
			default:
				m.sample()
				reads.Add(1)
			}
		}
	}()
	payload := bytes.Repeat([]byte("duplex"), 8192)
	copied := make(chan error, 1)
	go func() { _, err := client.Write(payload); copied <- errors.Join(err, client.CloseWrite()) }()
	got, err := io.ReadAll(server)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("forward: %d %v", len(got), err)
	}
	if err := <-copied; err != nil {
		t.Fatal(err)
	}
	_ = server.CloseWrite()
	if err := waitTCPRelayTest(t, done); err != nil {
		t.Fatal(err)
	}
	close(stop)
	<-sampled
	if got := stats.DefaultStore.Snapshot()[path].UploadBytes; got != uint64(len(payload)) {
		t.Fatalf("sampling/FIN/close overcount: %d", got)
	}
	if reads.Load() == 0 {
		t.Fatal("fixture never sampled")
	}
}

func BenchmarkTCPRelay(b *testing.B) {
	for _, direct := range []bool{false, true} {
		b.Run(map[bool]string{false: "buffered", true: "splice"}[direct], func(b *testing.B) {
			left, client := relayTestTCPPair(b)
			right, server := relayTestTCPPair(b)
			_ = client.SetDeadline(time.Time{})
			_ = server.SetDeadline(time.Time{})
			traffic := stats.DefaultStore.OpenConnection(stats.Path{Dialer: b.Name()}, false)
			defer traffic.Close()
			monitor := new(tcpRelayMonitor)
			defer monitor.close()
			finished := make(chan error, 1)
			go func() {
				relay := &tcpRelay{lConn: left, rConn: right, outboundOrigin: netproxy.OriginTarget, direct: direct, monitor: monitor}
				finished <- relay.copyTCP(traffic, time.Second)
			}()
			payload := bytes.Repeat([]byte("x"), 1<<20)
			written := make(chan error, 1)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			go func() {
				for range b.N {
					if _, err := client.Write(payload); err != nil {
						written <- err
						return
					}
				}
				written <- client.CloseWrite()
			}()
			if _, err := io.CopyN(io.Discard, server, int64(b.N)*int64(len(payload))); err != nil {
				b.Fatal(err)
			}
			_ = server.CloseWrite()
			if err := <-written; err != nil {
				b.Fatal(err)
			}
			if err := <-finished; err != nil {
				b.Fatal(err)
			}
		})
	}
}

func TestNativeTCPRejectsProtocolAdapters(t *testing.T) {
	left, _ := relayTestTCPPair(t)
	right, _ := relayTestTCPPair(t)
	// An arbitrary adapter can implement encryption or framing even if it
	// embeds a TCP socket. Only the explicit Runtime wrapper may be bypassed.
	adapter := struct{ net.Conn }{right}
	if pair, _ := nativeTCPPair(left, adapter); pair[0] != nil {
		t.Fatal("protocol adapter was bypassed")
	}
}

func TestNativeTCPRejectsMPTCP(t *testing.T) {
	var lc net.ListenConfig
	lc.SetMultipathTCP(true)
	listener, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var d net.Dialer
	d.SetMultipathTCP(true)
	client, err := d.DialContext(t.Context(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if enabled, err := client.(*net.TCPConn).MultipathTCP(); err != nil || !enabled {
		t.Skip("kernel did not negotiate MPTCP")
	}
	if _, err := tcpWriteCounter(client.(*net.TCPConn)); err == nil {
		t.Fatal("MPTCP accepted as native TCP")
	}
}
