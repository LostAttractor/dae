package ss2022test

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022"
)

// The client of package shadowsocks_2022 reaches its target through the
// fixture, both ways, beyond one chunk.
func TestServerRelaysClientStream(t *testing.T) {
	psk := bytes.Repeat([]byte{7}, KeySize)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type accepted struct {
		conn   *Conn
		target string
		err    error
	}
	done := make(chan accepted, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- accepted{err: err}
			return
		}
		conn, target, err := Accept(raw, psk)
		done <- accepted{conn, target, err}
	}()
	dialer, err := shadowsocks_2022.NewDialer(direct.NewDirectDialer(direct.Option{}), protocol.Header{
		ProxyAddress: listener.Addr().String(), Cipher: Method, Password: base64.StdEncoding.EncodeToString(psk),
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := dialer.DialContext(t.Context(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	upload := bytes.Repeat([]byte("u"), 3*maxChunk)
	go client.Write(upload)
	server := <-done
	if server.err != nil || server.target != "example.test:443" {
		t.Fatalf("accepted %q, %v", server.target, server.err)
	}
	defer server.conn.Close()
	got := make([]byte, len(upload))
	if _, err := io.ReadFull(server.conn, got); err != nil || !bytes.Equal(got, upload) {
		t.Fatalf("server read %d bytes, %v", len(got), err)
	}
	download := bytes.Repeat([]byte("d"), maxChunk+1)
	go server.conn.Write(download)
	got = make([]byte, len(download))
	if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, download) {
		t.Fatalf("client read %d bytes, %v", len(got), err)
	}
}
