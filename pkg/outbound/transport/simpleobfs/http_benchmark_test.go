package simpleobfs

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
)

const httpObfsResponseHeader = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n"

type httpObfsMemoryConn struct {
	net.Conn
	reader bytes.Reader
}

func (c *httpObfsMemoryConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *httpObfsMemoryConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *httpObfsMemoryConn) Close() error                { return nil }

// Measure a complete connection lifetime with deterministic in-memory I/O.
// Loopback below includes the socket and goroutine overhead separately.
func BenchmarkHTTPObfs(b *testing.B) {
	for _, workload := range []struct {
		name string
		size int
	}{{"unread", 0}, {"short", 1024}, {"stream", 64 << 10}} {
		b.Run(workload.name, func(b *testing.B) {
			payload := bytes.Repeat([]byte("x"), workload.size)
			wire := append([]byte(httpObfsResponseHeader), payload...)
			buf := make([]byte, workload.size)
			b.ReportAllocs()
			b.SetBytes(int64(workload.size))
			for b.Loop() {
				raw := &httpObfsMemoryConn{}
				raw.reader.Reset(wire)
				conn := NewHTTPObfs(raw, "example.org", "80", "/")
				if workload.size != 0 {
					if _, err := conn.Write(payload); err != nil {
						b.Fatal(err)
					}
					if _, err := io.ReadFull(conn, buf); err != nil {
						b.Fatal(err)
					}
				}
				if err := conn.Close(); err != nil {
					b.Fatal(err)
				}
			}
			if !bytes.Equal(buf, payload) {
				b.Fatal("response payload changed")
			}
		})
	}
}

// Includes both ends of each short TCP connection, HTTP request generation,
// response parsing, payload delivery and close. Server allocations are included.
func BenchmarkHTTPObfsLoopback(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 1024)
	wire := append([]byte(httpObfsResponseHeader), payload...)
	var server sync.WaitGroup
	server.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			request, err := http.ReadRequest(bufio.NewReader(conn))
			if err == nil {
				_, err = io.Copy(io.Discard, request.Body)
				request.Body.Close()
			}
			if err == nil {
				_, err = conn.Write(wire)
			}
			conn.Close()
			if err != nil {
				b.Error(err)
				return
			}
		}
	})
	defer server.Wait()
	defer listener.Close()
	buf := make([]byte, len(payload))
	address := listener.Addr().String()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		raw, err := net.Dial("tcp", address)
		if err != nil {
			b.Fatal(err)
		}
		conn := NewHTTPObfs(raw, "example.org", "80", "/")
		if _, err := conn.Write(payload); err != nil {
			conn.Close()
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			b.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			b.Fatal(err)
		}
	}
	if !bytes.Equal(buf, payload) {
		b.Fatal("response payload changed")
	}
}
