package mux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type frameConn struct {
	net.Conn
	reader  io.Reader
	writes  bytes.Buffer
	shortAt int
	calls   int
}

func (c *frameConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *frameConn) Write(p []byte) (int, error) {
	c.calls++
	if c.calls == c.shortAt {
		return c.writes.Write(p[:len(p)-1])
	}
	return c.writes.Write(p)
}

type byteReader struct{ io.Reader }

func (r byteReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(len(p), 1)]) }

func TestReadFragmentedHeader(t *testing.T) {
	wire := append([]byte{0, 4, 0, 0, SessionStatusKeep, OptionData, 0, 5}, []byte("hello")...)
	carrier := &frameConn{reader: byteReader{bytes.NewReader(wire)}}
	conn := NewConn(carrier, MuxOption{Host: "127.0.0.1"})
	payload := make([]byte, 5)
	if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "hello" {
		t.Fatalf("Read = %q, %v", payload, err)
	}
}

func TestReadDrainsControlFramePayloads(t *testing.T) {
	var wire []byte
	frame := func(status, option byte, data string) {
		wire = append(wire, 0, 4, 0, 0, status, option)
		if option&OptionData != 0 {
			wire = append(wire, 0, byte(len(data)))
			wire = append(wire, data...)
		}
	}
	frame(SessionStatusKeepAlive, OptionData, "ping")
	frame(SessionStatusNew, OptionData, "meta")
	frame(SessionStatusKeep, OptionData, "")
	frame(SessionStatusKeep, OptionData|OptionError, "hello")
	frame(SessionStatusKeepAlive, OptionNone, "")
	frame(SessionStatusKeep, OptionData, " world")
	conn := NewConn(&frameConn{reader: bytes.NewReader(wire)}, MuxOption{Host: "127.0.0.1"})
	payload, err := io.ReadAll(conn)
	if string(payload) != "hello world" || err != nil {
		t.Fatalf("Read = %q, %v", payload, err)
	}
}

func TestRemoteEndDoesNotWaitForCarrierClose(t *testing.T) {
	for _, option := range []byte{OptionNone, OptionError, OptionData} {
		t.Run(fmt.Sprint(option), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				_, _ = server.Write([]byte{0, 4, 0, 0, SessionStatusEnd, option})
			}()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			conn := NewConn(client, MuxOption{})
			for range 2 {
				n, err := conn.Read(make([]byte, 1))
				if n != 0 || err == nil || option != OptionError && !errors.Is(err, io.EOF) {
					t.Fatalf("Read after End = %d, %v", n, err)
				}
				if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
					t.Fatal("End waited for the carrier")
				}
			}
		})
	}
}

func TestWriteReturnsPayloadCountAndDetectsShortFrames(t *testing.T) {
	for _, shortAt := range []int{0, 1, 2} {
		carrier := &frameConn{shortAt: shortAt}
		conn := NewConn(carrier, MuxOption{Host: "127.0.0.1"})
		n, err := conn.Write([]byte("hello"))
		if shortAt == 0 {
			if n != 5 || err != nil {
				t.Fatalf("Write = %d, %v", n, err)
			}
		} else {
			want := 0
			if shortAt == 2 {
				want = 4
			}
			if n != want || !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short frame %d: Write = %d, %v; want %d, ErrShortWrite", shortAt, n, err, want)
			}
			if n, err := conn.Write([]byte("retry")); n != 0 || !errors.Is(err, io.ErrShortWrite) || carrier.calls != shortAt {
				t.Fatalf("write after incomplete frame = %d, %v; carrier writes %d", n, err, carrier.calls)
			}
		}
	}
}

func TestConcurrentWritesPreserveFrames(t *testing.T) {
	const writers, size = 32, 128
	incoming := bytes.Repeat([]byte{0, 4, 9, 9, SessionStatusKeep, OptionData, 0, 1, 'r'}, writers)
	carrier := &frameConn{reader: bytes.NewReader(incoming)}
	conn := NewConn(carrier, MuxOption{ID: [2]byte{1, 2}, Host: "127.0.0.1"})
	var wg sync.WaitGroup
	wg.Go(func() {
		for range writers {
			if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
				t.Error(err)
				return
			}
		}
	})
	for i := range writers {
		wg.Go(func() {
			if n, err := conn.Write(bytes.Repeat([]byte{byte(i)}, size)); n != size || err != nil {
				t.Errorf("Write = %d, %v", n, err)
			}
		})
	}
	wg.Wait()
	wire := carrier.writes.Bytes()
	metadataLen := int(binary.BigEndian.Uint16(wire[:2]))
	wire = wire[2+metadataLen:]
	seen := make(map[byte]bool)
	for len(wire) > 0 {
		if len(wire) < 8+size || !bytes.Equal(wire[:8], []byte{0, 4, 1, 2, SessionStatusKeep, OptionData, 0, size}) {
			t.Fatalf("invalid frame: %x", wire)
		}
		payload := wire[8 : 8+size]
		if !bytes.Equal(payload, bytes.Repeat(payload[:1], size)) || seen[payload[0]] {
			t.Fatalf("interleaved or duplicate payload: %x", payload)
		}
		seen[payload[0]] = true
		wire = wire[8+size:]
	}
	if len(seen) != writers {
		t.Fatalf("received %d frames, want %d", len(seen), writers)
	}
}

func TestShadowsocksHandshakeOverMux(t *testing.T) {
	carrier := new(frameConn)
	conn := NewConn(carrier, MuxOption{Host: "127.0.0.1"})
	address, err := socks5.AddressFromString("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conf := ciphers.AeadCiphersConf["aes-128-gcm"]
	client := shadowsocks.NewTCPConn(conn, conf, make([]byte, conf.KeyLen), shadowsocks.RandomSaltGenerator(conf.SaltLen), address)
	if n, err := client.Write(nil); n != 0 || err != nil {
		t.Fatalf("initial handshake = %d, %v", n, err)
	}
	if n, err := client.Write([]byte("hello")); n != 5 || err != nil {
		t.Fatalf("application write = %d, %v", n, err)
	}
}

type closeTrackingConn struct {
	readStarted chan struct{}
	closed      chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
	writes      int
}

func (c *closeTrackingConn) Read([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *closeTrackingConn) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}

func (c *closeTrackingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *closeTrackingConn) LocalAddr() net.Addr              { return nil }
func (c *closeTrackingConn) RemoteAddr() net.Addr             { return nil }
func (c *closeTrackingConn) SetDeadline(time.Time) error      { return nil }
func (c *closeTrackingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeTrackingConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnCloseUnblocksReadWithoutWriting(t *testing.T) {
	underlay := &closeTrackingConn{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	conn := NewConn(underlay, MuxOption{})
	readDone := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readDone <- err
	}()
	<-underlay.readStarted

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after Close")
	}
	if underlay.writes != 0 {
		t.Fatalf("underlay writes = %d, want 0", underlay.writes)
	}
}
