package mux

import (
	"bytes"
	"errors"
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

func TestWriteReturnsPayloadCountAndDetectsShortFrames(t *testing.T) {
	for _, shortAt := range []int{0, 1, 2} {
		carrier := &frameConn{shortAt: shortAt}
		conn := NewConn(carrier, MuxOption{Host: "127.0.0.1"})
		n, err := conn.Write([]byte("hello"))
		if shortAt == 0 {
			if n != 5 || err != nil {
				t.Fatalf("Write = %d, %v", n, err)
			}
		} else if n != 0 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short frame %d: Write = %d, %v", shortAt, n, err)
		}
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
