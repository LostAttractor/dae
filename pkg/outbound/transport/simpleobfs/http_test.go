package simpleobfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPObfsResponseAndReaderReuse(t *testing.T) {
	for _, test := range []struct {
		name, header, wantErr string
	}{
		{"upgrade", httpObfsResponseHeader, ""},
		{"long header", "HTTP/1.1 101 Switching Protocols\r\nX-Long: " + strings.Repeat("x", 8<<10) + "\r\n\r\n", ""},
		{"wrong status", "HTTP/1.1 403 Forbidden\r\n\r\n", "HTTP status 403"},
		{"malformed", "not HTTP\r\n\r\n", "invalid HTTP response"},
		{"too large", "HTTP/1.1 101 Switching Protocols\r\nX-Long: " + strings.Repeat("x", 64<<10) + "\r\n\r\n", "header too large"},
		{"incomplete", "HTTP/1.1 101 Switching Protocols\r\n", "unexpected EOF"},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Distinct payloads expose stale prefetched data on subsequent uses.
			for i := range 8 {
				payload := bytes.Repeat([]byte{byte('a' + i)}, 8192)
				wire := []byte(test.header)
				if test.wantErr == "" {
					wire = append(wire, payload...)
				}
				raw := &httpObfsMemoryConn{}
				raw.reader.Reset(wire)
				conn := NewHTTPObfs(raw, "example.org", "80", "/")
				got, err := io.ReadAll(conn)
				if test.wantErr == "" {
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("payload length = %d, error = %v", len(got), err)
					}
				} else {
					if err == nil || !strings.Contains(err.Error(), test.wantErr) || len(got) != 0 {
						t.Fatalf("read = %q, %v; want %q", got, err, test.wantErr)
					}
					if _, again := conn.Read(make([]byte, 1)); again != err {
						t.Fatalf("lost persistent header error: %v, then %v", err, again)
					}
				}
				if err := conn.Close(); err != nil {
					t.Fatal(err)
				}
				// Concurrent callers must return a reader to the pool at most once.
				var closers sync.WaitGroup
				for range 4 {
					closers.Go(func() {
						if err := conn.Close(); err != nil {
							t.Error(err)
						}
					})
				}
				closers.Wait()
			}
		})
	}
}

type httpObfsReadStep struct {
	data string
	err  error
}

type httpObfsScriptedConn struct {
	httpObfsMemoryConn
	steps []httpObfsReadStep
}

func (c *httpObfsScriptedConn) Read(p []byte) (int, error) {
	if len(c.steps) == 0 {
		return 0, io.EOF
	}
	step := &c.steps[0]
	n := copy(p, step.data)
	step.data = step.data[n:]
	if step.data != "" {
		return n, nil
	}
	err := step.err
	c.steps = c.steps[1:]
	return n, err
}

func TestHTTPObfsBufferedDataBeforeError(t *testing.T) {
	for _, readErr := range []error{io.EOF, os.ErrDeadlineExceeded} {
		t.Run(readErr.Error(), func(t *testing.T) {
			raw := &httpObfsScriptedConn{steps: []httpObfsReadStep{
				{httpObfsResponseHeader + "data", readErr}, {"more", nil},
			}}
			conn := NewHTTPObfs(raw, "example.org", "80", "/")
			defer conn.Close()
			buf := make([]byte, 2)
			for _, want := range []string{"da", "ta"} {
				if n, err := conn.Read(buf); err != nil || n != len(buf) || string(buf) != want {
					t.Fatalf("buffered Read = %q, %d, %v; want %q", buf, n, err, want)
				}
			}
			if n, err := conn.Read(buf); n != 0 || !errors.Is(err, readErr) {
				t.Fatalf("pending error = %d, %v; want %v", n, err, readErr)
			}
			if readErr == os.ErrDeadlineExceeded {
				got, err := io.ReadAll(conn)
				if err != nil || string(got) != "more" {
					t.Fatalf("read after timeout = %q, %v", got, err)
				}
			}
		})
	}
}

type httpObfsReadSignalConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *httpObfsReadSignalConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(p)
}

func TestHTTPObfsCloseInterruptsRead(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	raw := &httpObfsReadSignalConn{Conn: client, started: make(chan struct{})}
	conn := NewHTTPObfs(raw, "example.org", "80", "/")
	readDone := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readDone <- err
	}()
	<-raw.started
	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked behind Read")
	}
	if err := <-readDone; err == nil {
		t.Fatal("blocked Read succeeded after Close")
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close = %v", err)
	}
}

func TestHTTPObfsCloseBeforeRead(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	conn := NewHTTPObfs(client, "example.org", "80", "/")
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close = %v", err)
	}
}
