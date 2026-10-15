package simpleobfs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestResponseFragmentsSurviveDeadline(t *testing.T) {
	hello := make([]byte, 96)
	copy(hello, []byte{0x16, 3, 1, 0, 91, 2})
	tlsFlight := append(hello, 0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 4)
	tlsFlight = append(tlsFlight, []byte("data")...)
	tlsFlight = append(tlsFlight, 0x17, 3, 3, 0, 4)
	tlsFlight = append(tlsFlight, []byte("more")...)
	for _, tc := range []struct {
		name string
		wrap func(net.Conn) net.Conn
		wire []byte
	}{
		{"http", func(c net.Conn) net.Conn { return NewHTTPObfs(c, "example.org", "80", "/") }, []byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\ndatamore")},
		{"tls", func(c net.Conn) net.Conn { return NewTLSObfs(c, "example.org") }, tlsFlight},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			conn := tc.wrap(client)
			defer conn.Close()
			first := make(chan struct{})
			go func() { peer.Write(tc.wire[:3]); close(first) }()
			conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			buf := make([]byte, 8)
			_, err := conn.Read(buf)
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("deadline: %v", err)
			}
			<-first
			conn.SetReadDeadline(time.Now().Add(time.Second))
			go func() {
				for _, b := range tc.wire[3:] {
					if _, err := peer.Write([]byte{b}); err != nil {
						return
					}
				}
			}()
			if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "datamore" {
				t.Fatalf("fragmented response: %q %v", buf, err)
			}
		})
	}
}

func TestClientRequestWireAndShortWrite(t *testing.T) {
	for _, tlsMode := range []bool{false, true} {
		client, peer := net.Pipe()
		client.SetDeadline(time.Now().Add(time.Second))
		var conn net.Conn = NewHTTPObfs(client, "example.org", "8080", "/path?q=1")
		if tlsMode {
			conn = NewTLSObfs(client, "example.org")
		}
		result := make(chan error, 1)
		go func() {
			if !tlsMode {
				request, err := http.ReadRequest(bufio.NewReader(peer))
				if err != nil {
					result <- err
					return
				}
				body, err := io.ReadAll(request.Body)
				if request.Host != "example.org:8080" || request.RequestURI != "/path?q=1" || string(body) != "target" {
					err = errors.New("incorrect HTTP wire")
				}
				result <- err
				return
			}
			var header [5]byte
			if _, err := io.ReadFull(peer, header[:]); err != nil {
				result <- err
				return
			}
			body := make([]byte, binary.BigEndian.Uint16(header[3:]))
			_, err := io.ReadFull(peer, body)
			// Fixed hello fields end at byte 138 (including record header).
			if err == nil && (body[0] != 1 || !bytes.Equal(body[133:137], []byte{0, 0x23, 0, 6}) || string(body[137:143]) != "target") {
				err = errors.New("target is not in the TLS session ticket")
			}
			result <- err
		}()
		if n, err := conn.Write([]byte("target")); err != nil || n != 6 {
			t.Fatalf("write %d %v", n, err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		conn.Close()
		peer.Close()
		raw := &shortWriter{}
		conn = NewHTTPObfs(raw, "example.org", "80", "/")
		if tlsMode {
			conn = NewTLSObfs(raw, "example.org")
		}
		for range 2 {
			if _, err := conn.Write([]byte("target")); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short wire error: %v", err)
			}
		}
		if raw.calls != 1 {
			t.Fatal("replayed a partial request")
		}
	}
}

type shortWriter struct {
	net.Conn
	calls int
}

func (c *shortWriter) Write(p []byte) (int, error) { c.calls++; return len(p) - 1, nil }
