package smux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	xtacismux "github.com/xtaci/smux"
)

type streamWriteFunc struct {
	net.Conn
	write func([]byte) (int, error)
}

func (c streamWriteFunc) Write(p []byte) (int, error) { return c.write(p) }

func TestConnWritesRequestOnlyOnce(t *testing.T) {
	var wire bytes.Buffer
	conn := &Conn{Conn: streamWriteFunc{write: wire.Write}, addr: "example.org:443"}
	for _, payload := range []string{"first", "second"} {
		if n, err := conn.Write([]byte(payload)); err != nil || n != len(payload) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	flags := make([]byte, 2)
	if _, err := io.ReadFull(&wire, flags); err != nil || !bytes.Equal(flags, []byte{0, 0}) {
		t.Fatalf("request flags = %x, %v", flags, err)
	}
	addr, err := socks5.ReadAddrInfo(&wire)
	if err != nil || addr.Hostname != "example.org" || addr.Port != 443 {
		t.Fatalf("request address = %v, %v", addr, err)
	}
	if wire.String() != "firstsecond" {
		t.Fatalf("payload = %q", wire.String())
	}
}

func TestConnEstablishedWritePreservesPartialFailure(t *testing.T) {
	want := errors.New("write interrupted")
	conn := &Conn{Conn: streamWriteFunc{write: func([]byte) (int, error) { return 3, want }}, onceWrite: true}
	if n, err := conn.Write([]byte("payload")); n != 3 || !errors.Is(err, want) {
		t.Fatalf("Write = %d, %v; want underlying partial result", n, err)
	}
}

// Memory isolates wrapper copies; smux includes both ends of an established
// stream and its scheduling. Initial connection setup is outside the timing.
func BenchmarkConnWrite(b *testing.B) {
	for _, transport := range []string{"memory", "smux"} {
		for _, size := range []int{256, 4096, 32768} {
			b.Run(fmt.Sprintf("%s/bytes=%d", transport, size), func(b *testing.B) {
				var carrier net.Conn = streamWriteFunc{write: func(p []byte) (int, error) { return len(p), nil }}
				if transport == "smux" {
					local, remote := net.Pipe()
					client, err := xtacismux.Client(local, nil)
					if err != nil {
						b.Fatal(err)
					}
					b.Cleanup(func() { client.Close() })
					server, err := xtacismux.Server(remote, nil)
					if err != nil {
						b.Fatal(err)
					}
					b.Cleanup(func() { server.Close() })
					stream, err := client.OpenStream()
					if err != nil {
						b.Fatal(err)
					}
					peer, err := server.AcceptStream()
					if err != nil {
						b.Fatal(err)
					}
					carrier = stream
					done := make(chan struct{})
					go func() {
						defer close(done)
						buf := make([]byte, size)
						for {
							if _, err := io.ReadFull(peer, buf); err != nil {
								return
							}
							if _, err := peer.Write(buf); err != nil {
								return
							}
						}
					}()
					b.Cleanup(func() { peer.Close(); <-done })
				}
				conn := &Conn{Conn: carrier, onceRead: true, onceWrite: true}
				payload := bytes.Repeat([]byte("x"), size)
				response := make([]byte, size)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					if n, err := conn.Write(payload); err != nil || n != size {
						b.Fatalf("Write = %d, %v", n, err)
					}
					if transport == "smux" {
						if _, err := io.ReadFull(conn, response); err != nil {
							b.Fatal(err)
						}
					}
				}
				if transport == "smux" && !bytes.Equal(response, payload) {
					b.Fatal("payload changed")
				}
			})
		}
	}
}
