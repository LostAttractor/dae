package shadowsocks

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/transport/simpleobfs"
	"golang.org/x/sys/unix"
)

// Behind simple-obfs the socket is tuned once the handshake response and the
// bytes read with it are consumed, so a stalled chunk is awaited whole.
func TestTCPReadTunesSocketBehindObfs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()

	payload := bytes.Repeat([]byte("x"), TCPChunkMaxLen)
	key, wire := responseStream(t, "aes-128-gcm", payload, 2)
	wire = append([]byte(obfsResponseHeader), wire...)
	// The response, salt and first chunk share a write; the second chunk stalls.
	stall := len(obfsResponseHeader) + 16 + 2 + 16 + len(payload) + 16 + 1448
	if _, err := server.Write(wire[:stall]); err != nil {
		t.Fatal(err)
	}
	conn := NewTCPConn(simpleobfs.NewHTTPObfs(client, "example.org", "80", "/"), ciphers.AeadCiphersConf["aes-128-gcm"], key, nil, nil)
	got := make([]byte, 2*len(payload))
	if _, err := io.ReadFull(conn, got[:len(payload)]); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, got[len(payload):])
		done <- err
	}()
	raw, err := client.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
		lowat := 0
		if err := raw.Control(func(fd uintptr) { lowat, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVLOWAT) }); err != nil {
			t.Fatal(err)
		}
		if lowat > 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stalled chunk awaited without a receive low-water mark")
		}
	}
	if _, err := server.Write(wire[stall:]); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || !bytes.Equal(got, bytes.Repeat(payload, 2)) {
		t.Fatalf("second chunk: %v", err)
	}
}
