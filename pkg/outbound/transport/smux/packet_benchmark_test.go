package smux

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	xtacismux "github.com/xtaci/smux"
)

type packetBenchmarkConn struct {
	net.Conn
	reader bytes.Reader
}

func (c *packetBenchmarkConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func packetBenchmarkFrame(b *testing.B, address string, size int) []byte {
	b.Helper()
	var frame bytes.Buffer
	if err := socks5.WriteAddr(address, &frame); err != nil {
		b.Fatal(err)
	}
	frame.Write(binary.BigEndian.AppendUint16(nil, uint16(size)))
	frame.Write(bytes.Repeat([]byte{'x'}, size))
	return frame.Bytes()
}

// Exercise the established UDP receive path, including SOCKS decoding and
// copying payload out of the stream. Socket and smux scheduling are excluded.
func BenchmarkUDPReadFrom(b *testing.B) {
	for _, address := range []struct{ name, value string }{
		{"ipv4", "192.0.2.1:53"},
		{"ipv6", "[2001:db8::1]:53"},
		{"domain", "example.test:53"},
	} {
		for _, size := range []int{64, 1200} {
			b.Run(fmt.Sprintf("%s/%d", address.name, size), func(b *testing.B) {
				frame := packetBenchmarkFrame(b, address.value, size)
				stream := new(packetBenchmarkConn)
				conn := &UDPConn{Conn: Conn{Conn: stream, onceRead: true}}
				payload := make([]byte, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					stream.reader.Reset(frame)
					n, addr, err := conn.ReadFrom(payload)
					if err != nil || n != size || addr == nil {
						b.Fatalf("ReadFrom = %d, %v, %v", n, addr, err)
					}
				}
			})
		}
	}
}

// Include a real smux session and both endpoints' allocations, using net.Pipe
// to avoid external network latency. One request/response is one operation.
func BenchmarkUDPSmuxRoundTrip(b *testing.B) {
	local, remote := net.Pipe()
	client, err := xtacismux.Client(local, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = client.Close() })
	server, err := xtacismux.Server(remote, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = server.Close() })
	stream, err := client.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	peer, err := server.AcceptStream()
	if err != nil {
		b.Fatal(err)
	}
	const size = 64
	frame := packetBenchmarkFrame(b, "192.0.2.1:53", size)
	done := make(chan error, 1)
	go func() {
		request := make([]byte, len(frame))
		for {
			if _, err := io.ReadFull(peer, request); err != nil {
				done <- err
				return
			}
			if _, err := peer.Write(request); err != nil {
				done <- err
				return
			}
		}
	}()
	b.Cleanup(func() {
		_ = peer.Close()
		<-done
	})
	conn := &UDPConn{Conn: Conn{Conn: stream, onceRead: true}}
	payload := make([]byte, size)
	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := stream.Write(frame); err != nil {
			b.Fatal(err)
		}
		n, addr, err := conn.ReadFrom(payload)
		if err != nil || n != size || addr == nil {
			b.Fatalf("ReadFrom = %d, %v, %v", n, addr, err)
		}
	}
}
