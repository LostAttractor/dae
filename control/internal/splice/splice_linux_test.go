//go:build linux && dae_splice && dae_splice_tests

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"golang.org/x/sys/unix"
)

func writeFull(writer io.Writer, p []byte) error {
	return writeFullAndRecord(writer, p, nil)
}

func loadTestSpliceRuntime(t *testing.T) *Runtime {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	runtime, err := New(&ebpf.CollectionOptions{}, 7440*time.Second)
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			t.Logf("%+v", verifierErr)
		}
		t.Fatalf("%+v", err)
	}
	if runtime == nil {
		t.Fatal("splice runtime is unexpectedly unavailable")
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime
}

func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err = net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		client.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		client.Close()
		t.Fatal("accept timed out")
	}
	return client, server
}

func testSocketCookie(t *testing.T, conn *net.TCPConn) uint64 {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cookie uint64
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cookie, controlErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil {
		t.Fatal(err)
	}
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	return cookie
}

func readExactly(t *testing.T, conn *net.TCPConn, want []byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if n, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read %d of %d bytes: %v", n, len(want), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

func expectEOF(t *testing.T, conn *net.TCPConn, direction string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("%s FIN: n=%d err=%v", direction, n, err)
	}
}

func runSplice(t *testing.T, runtime *Runtime, accepted, remote *net.TCPConn, traffic *stats.Connection) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		handled, err := runtime.Relay(accepted, remote, traffic)
		if !handled && err == nil {
			err = errors.New("direct splice relay was not handled")
		}
		result <- err
	}()
	return result
}

func trafficCounterValue(t *testing.T, path stats.Path, direction string) uint64 {
	t.Helper()
	snapshot, err := stats.DefaultStore.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	pathStats, ok := snapshot[path]
	if !ok {
		t.Fatalf("traffic path is absent: %+v", path)
	}
	if direction == "upload" {
		return pathStats.UploadBytes
	}
	return pathStats.DownloadBytes
}

func waitRelay(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("direct splice relay did not finish")
	}
}

func waitRedirectArmed(t *testing.T, runtime *Runtime, cookies ...uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		armed := true
		for _, cookie := range cookies {
			endpoint, err := runtime.endpoint(cookie)
			if err != nil || endpoint.PeerCookie == 0 {
				armed = false
				break
			}
		}
		if armed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("splice redirect did not arm")
}

func waitPass(t *testing.T, runtime *Runtime, cookies ...uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		passed := true
		for _, cookie := range cookies {
			endpoint, err := runtime.endpoint(cookie)
			if err != nil || endpoint.PeerCookie != 0 {
				passed = false
				break
			}
		}
		if passed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("splice redirect did not switch to pass")
}

func TestSpliceAcceptedRemoteIntegration(t *testing.T) {
	runtime := loadTestSpliceRuntime(t)
	client, accepted := tcpPair(t)
	remote, server := tcpPair(t)
	defer client.Close()
	defer accepted.Close()
	defer remote.Close()
	defer server.Close()
	cookieA := testSocketCookie(t, accepted)
	cookieR := testSocketCookie(t, remote)
	statsPathID := t.TempDir()
	path := stats.Path{
		NodeID: statsPathID, Outbound: statsPathID, Subtag: "sub", Dialer: "direct", Network: common.NetworkTCP4,
	}
	traffic := stats.DefaultStore.OpenConnection(path)
	result := runSplice(t, runtime, accepted, remote, traffic)
	waitRedirectArmed(t, runtime, cookieA, cookieR)

	upload := []byte("upload")
	if err := writeFull(client, upload); err != nil {
		t.Fatal(err)
	}
	readExactly(t, server, upload)
	statsA, err := runtime.stats(cookieA)
	if err != nil || statsA.SkbRedirected == 0 {
		t.Fatalf("accepted-to-remote redirect is inactive: stats=%+v err=%v", statsA, err)
	}

	download := []byte("download")
	if err := writeFull(server, download); err != nil {
		t.Fatal(err)
	}
	readExactly(t, client, download)
	statsR, err := runtime.stats(cookieR)
	if err != nil || statsR.SkbRedirected == 0 {
		t.Fatalf("remote-to-accepted redirect is inactive: stats=%+v err=%v", statsR, err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	waitPass(t, runtime, cookieA, cookieR)
	afterFIN := []byte("upload-after-server-fin")
	if err := writeFull(client, afterFIN); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, client, "download")
	readExactly(t, server, afterFIN)
	statsA, err = runtime.stats(cookieA)
	if err != nil || statsA.SkbPass < uint64(len(afterFIN)) {
		t.Fatalf("accepted pass ingress is inactive: stats=%+v err=%v", statsA, err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, server, "upload")
	waitRelay(t, result)
	if got, want := trafficCounterValue(t, path, "upload"), uint64(len(upload)+len(afterFIN)); got != want {
		t.Fatalf("accounted upload = %d, want %d", got, want)
	}
	if got, want := trafficCounterValue(t, path, "download"), uint64(len(download)); got != want {
		t.Fatalf("accounted download = %d, want %d", got, want)
	}
}

func TestSpliceInitialHalfCloseDoesNotArmIntegration(t *testing.T) {
	runtime := loadTestSpliceRuntime(t)
	client, accepted := tcpPair(t)
	remote, server := tcpPair(t)
	defer client.Close()
	defer accepted.Close()
	defer remote.Close()
	defer server.Close()

	cookieA, err := runtime.registerSocket(accepted)
	if err != nil {
		t.Fatal(err)
	}
	cookieR, err := runtime.registerSocket(remote)
	if err != nil {
		runtime.cleanupMetadata(cookieA)
		t.Fatal(err)
	}
	defer runtime.cleanupMetadata(cookieA, cookieR)
	edges := [2]*spliceDirectEdge{
		{src: accepted, dst: remote, srcCookie: cookieA, dstCookie: cookieR},
		{src: remote, dst: accepted, srcCookie: cookieR, dstCookie: cookieA},
	}

	payload := []byte("upload-before-arm")
	if err := writeFull(client, payload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.pumpAndArm(edges); err != nil {
		t.Fatal(err)
	}
	readExactly(t, server, payload)
	expectEOF(t, server, "initial upload")
	if !edges[0].closed || !edges[1].userspace {
		t.Fatalf("initial half-close state: upload=%+v download=%+v", edges[0], edges[1])
	}
	for _, cookie := range []uint64{cookieA, cookieR} {
		endpoint, err := runtime.endpoint(cookie)
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.PeerCookie != 0 {
			t.Fatalf("endpoint %d armed after initial half-close: %+v", cookie, endpoint)
		}
	}
}

func TestSpliceClientFirstLargeHalfCloseIntegration(t *testing.T) {
	runtime := loadTestSpliceRuntime(t)
	client, accepted := tcpPair(t)
	remote, server := tcpPair(t)
	defer client.Close()
	defer accepted.Close()
	defer remote.Close()
	defer server.Close()
	result := runSplice(t, runtime, accepted, remote, nil)
	cookieA := testSocketCookie(t, accepted)
	cookieR := testSocketCookie(t, remote)
	waitRedirectArmed(t, runtime, cookieA, cookieR)

	upload := bytes.Repeat([]byte("client-to-server"), 64*1024)
	if err := writeFull(client, upload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readExactly(t, server, upload)
	expectEOF(t, server, "upload")

	download := bytes.Repeat([]byte("server-to-client"), 16*1024)
	if err := writeFull(server, download); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readExactly(t, client, download)
	expectEOF(t, client, "download")
	waitRelay(t, result)
}

func TestSpliceServerFirstLargeIntegration(t *testing.T) {
	runtime := loadTestSpliceRuntime(t)
	client, accepted := tcpPair(t)
	remote, server := tcpPair(t)
	defer client.Close()
	defer accepted.Close()
	defer remote.Close()
	defer server.Close()

	payload := bytes.Repeat([]byte("server-first-data"), 128*1024)
	writeResult := make(chan error, 1)
	go func() { writeResult <- writeFull(server, payload) }()
	time.Sleep(10 * time.Millisecond)
	result := runSplice(t, runtime, accepted, remote, nil)
	readExactly(t, client, payload)
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	waitRelay(t, result)
}

func TestSpliceMPTCPFallbackPreservesAcceptedDataIntegration(t *testing.T) {
	runtime := loadTestSpliceRuntime(t)
	client, accepted := tcpPair(t)
	defer client.Close()
	defer accepted.Close()

	var listenConfig net.ListenConfig
	listenConfig.SetMultipathTCP(true)
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("MPTCP listener unavailable: %v", err)
	}
	defer listener.Close()
	serverCh := make(chan *net.TCPConn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			serverCh <- conn.(*net.TCPConn)
		}
	}()
	var dialer net.Dialer
	dialer.SetMultipathTCP(true)
	remoteConn, err := dialer.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Skipf("MPTCP dial unavailable: %v", err)
	}
	remote := remoteConn.(*net.TCPConn)
	defer remote.Close()
	var server *net.TCPConn
	select {
	case server = <-serverCh:
	case <-time.After(time.Second):
		t.Fatal("MPTCP accept timed out")
	}
	defer server.Close()
	if mptcp, err := remote.MultipathTCP(); err != nil || !mptcp {
		t.Skipf("connection fell back to TCP: mptcp=%v err=%v", mptcp, err)
	}

	payload := []byte("accepted data before MPTCP fallback")
	if err := writeFull(client, payload); err != nil {
		t.Fatal(err)
	}
	handled, err := runtime.Relay(accepted, remote, nil)
	if err != nil || handled {
		t.Fatalf("MPTCP relay = handled:%v err:%v, want userspace fallback", handled, err)
	}
	readExactly(t, accepted, payload)
}

func TestSpliceRedirectTargetFaultFallsBackIntegration(t *testing.T) {
	runtime := loadTestSpliceRuntime(t)
	client, accepted := tcpPair(t)
	remote, server := tcpPair(t)
	defer client.Close()
	defer accepted.Close()
	defer remote.Close()
	defer server.Close()
	cookieA := testSocketCookie(t, accepted)
	cookieR := testSocketCookie(t, remote)
	result := runSplice(t, runtime, accepted, remote, nil)
	waitRedirectArmed(t, runtime, cookieA, cookieR)

	endpoint, err := runtime.endpoint(cookieA)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.PeerCookie = ^uint64(0)
	if err := runtime.updateEndpoint(cookieA, &endpoint); err != nil {
		t.Fatal(err)
	}

	payload := []byte("userspace fallback after redirect fault")
	if err := writeFull(client, payload); err != nil {
		t.Fatal(err)
	}
	readExactly(t, server, payload)
	stats, err := runtime.stats(cookieA)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Fault&spliceFaultTarget == 0 || stats.SkbPass < uint64(len(payload)) {
		t.Fatalf("fault stats = %+v, want fault=%d and skb_pass>=%d",
			stats, spliceFaultTarget, len(payload))
	}

	waitPass(t, runtime, cookieA, cookieR)
	upload := bytes.Repeat([]byte("client-after-fallback"), 512*1024)
	download := bytes.Repeat([]byte("server-after-fallback"), 512*1024)
	clientWrite := make(chan error, 1)
	clientRead := make(chan error, 1)
	go func() { clientWrite <- writeFull(client, upload) }()
	go func() {
		if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			clientRead <- err
			return
		}
		got := make([]byte, len(download))
		_, err := io.ReadFull(client, got)
		if err == nil && !bytes.Equal(got, download) {
			err = errors.New("download payload mismatch after fallback")
		}
		clientRead <- err
	}()
	if err := server.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeFull(server, download); err != nil {
		t.Fatal(err)
	}
	readExactly(t, server, upload)
	if err := <-clientWrite; err != nil {
		t.Fatal(err)
	}
	if err := <-clientRead; err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	waitRelay(t, result)
}
