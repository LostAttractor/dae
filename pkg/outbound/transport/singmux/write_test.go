package singmux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
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

func TestConnFirstWriteFailure(t *testing.T) {
	var request bytes.Buffer
	if err := WriteStreamRequest(&request, &StreamRequest{Destination: "example.org:443"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	headerLen := request.Len()
	for _, written := range []int{0, 1, headerLen - 1, headerLen, headerLen + 2, headerLen + len(payload)} {
		for _, writeErr := range []error{nil, errors.New("write interrupted")} {
			t.Run(fmt.Sprintf("written=%d/error=%v", written, writeErr), func(t *testing.T) {
				var wire bytes.Buffer
				calls := 0
				conn := &Conn{Conn: streamWriteFunc{write: func(p []byte) (int, error) {
					calls++
					if calls == 1 {
						wire.Write(p[:written])
						return written, writeErr
					}
					return wire.Write(p)
				}}, addr: "example.org:443"}
				wantErr := writeErr
				if wantErr == nil && written < headerLen+len(payload) {
					wantErr = io.ErrShortWrite
				}
				if n, err := conn.Write(payload); n != max(0, written-headerLen) || !errors.Is(err, wantErr) {
					t.Fatalf("first Write = %d, %v; want %d, %v", n, err, max(0, written-headerLen), wantErr)
				}
				if written > 0 && written < headerLen {
					if n, err := conn.Write(payload); n != 0 || !errors.Is(err, wantErr) || calls != 1 {
						t.Fatalf("write after incomplete request = %d, %v; carrier writes %d", n, err, calls)
					}
					return
				}
				if n, err := conn.Write(payload); n != len(payload) || err != nil {
					t.Fatalf("next Write = %d, %v", n, err)
				}
				want := bytes.Clone(request.Bytes())
				want = append(want, payload[:max(0, written-headerLen)]...)
				want = append(want, payload...)
				if !bytes.Equal(wire.Bytes(), want) {
					t.Fatalf("wire = %x, want %x", wire.Bytes(), want)
				}
			})
		}
	}
}

func TestConnConcurrentWritesSendOneRequest(t *testing.T) {
	const writers, size = 32, 128
	var wire bytes.Buffer
	conn := &Conn{Conn: streamWriteFunc{write: wire.Write}, addr: "example.org:443"}
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			if n, err := conn.Write(bytes.Repeat([]byte{byte(i)}, size)); n != size || err != nil {
				t.Errorf("Write = %d, %v", n, err)
			}
		})
	}
	wg.Wait()
	var request bytes.Buffer
	if err := WriteStreamRequest(&request, &StreamRequest{Destination: conn.addr}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Next(request.Len()), request.Bytes()) {
		t.Fatal("invalid stream request")
	}
	seen := make(map[byte]bool)
	for wire.Len() > 0 {
		payload := wire.Next(size)
		if len(payload) != size || !bytes.Equal(payload, bytes.Repeat(payload[:1], size)) || seen[payload[0]] {
			t.Fatalf("interleaved or duplicate payload: %x", payload)
		}
		seen[payload[0]] = true
	}
	if len(seen) != writers {
		t.Fatalf("received %d writes, want %d", len(seen), writers)
	}
}

func TestConnEstablishedWritePreservesPartialFailure(t *testing.T) {
	for _, writeErr := range []error{nil, errors.New("write interrupted")} {
		conn := &Conn{Conn: streamWriteFunc{write: func([]byte) (int, error) { return 3, writeErr }}, onceWrite: true}
		want := writeErr
		if want == nil {
			want = io.ErrShortWrite
		}
		if n, err := conn.Write([]byte("payload")); n != 3 || !errors.Is(err, want) {
			t.Fatalf("Write = %d, %v; want underlying partial result", n, err)
		}
	}
}

type closeWriteFunc struct {
	streamWriteFunc
	closeWrite func() error
}

func (c closeWriteFunc) CloseWrite() error { return c.closeWrite() }

func TestConnConcurrentWriteAndCloseWrite(t *testing.T) {
	var wire bytes.Buffer
	closed := false
	conn := &Conn{Conn: closeWriteFunc{
		write: func(p []byte) (int, error) {
			if closed {
				return 0, net.ErrClosed
			}
			return wire.Write(p)
		},
		closeWrite: func() error { closed = true; return nil },
	}, addr: "example.org:443"}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			n, err := conn.Write([]byte("payload"))
			if err == nil && n != 7 || err != nil && (!errors.Is(err, net.ErrClosed) || n != 0) {
				t.Errorf("Write = %d, %v", n, err)
			}
		})
	}
	wg.Go(func() {
		if err := conn.CloseWrite(); err != nil {
			t.Error(err)
		}
	})
	wg.Wait()
	var request bytes.Buffer
	if err := WriteStreamRequest(&request, &StreamRequest{Destination: conn.addr}); err != nil {
		t.Fatal(err)
	}
	if !closed || !bytes.Equal(wire.Next(request.Len()), request.Bytes()) {
		t.Fatal("CloseWrite did not send one complete request")
	}
	if !bytes.Equal(wire.Bytes(), bytes.Repeat([]byte("payload"), wire.Len()/7)) {
		t.Fatalf("invalid payload after CloseWrite: %q", wire.Bytes())
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
					stream, peer := smuxStreamPair(b)
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
