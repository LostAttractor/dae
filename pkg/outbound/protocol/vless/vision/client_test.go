package vision

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	outtls "github.com/daeuniverse/dae/pkg/outbound/transport/tls"
	utls "github.com/refraction-networking/utls"
)

type rawCounter struct {
	net.Conn
	halves atomic.Int32
	lease  *netproxy.Lease
}

func (c *rawCounter) CloseWrite() error                { c.halves.Add(1); return c.Conn.(*net.TCPConn).CloseWrite() }
func (c *rawCounter) DependencyLease() *netproxy.Lease { return c.lease }

type tlsParent struct{ raw *rawCounter }

func (p *tlsParent) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := new(net.Dialer).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	p.raw = &rawCounter{Conn: c, lease: netproxy.NewLease(netproxy.NewResourceRef())}
	return p.raw, nil
}
func (*tlsParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}
func tlsPair(t *testing.T, kind string) (*Conn, *gotls.Conn, *rawCounter) {
	t.Helper()
	seed := httptest.NewTLSServer(nil)
	cert := seed.TLS.Certificates[0]
	seed.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverReady := make(chan *gotls.Conn, 1)
	serverError := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverError <- err
			return
		}
		server := gotls.Server(raw, &gotls.Config{Certificates: []gotls.Certificate{cert}, MinVersion: gotls.VersionTLS13})
		err = server.Handshake()
		if err != nil {
			raw.Close()
			serverError <- err
			return
		}
		serverReady <- server
	}()
	parent := new(tlsParent)
	implementation := kind
	if kind == "reality-accessor" {
		implementation = "utls"
	}
	layer, err := (&outtls.TLSConfig{Host: listener.Addr().String(), AllowInsecure: true}).Build(&dialer.ExtraOption{TlsImplementation: implementation, UtlsImitate: "chrome"}, dialer.NewUpstream(parent))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	carrier, err := layer.Data.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var server *gotls.Conn
	select {
	case server = <-serverReady:
	case err = <-serverError:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if kind == "reality-accessor" {
		u := carrier.(interface{ TLSConn() net.Conn }).TLSConn().(*utls.UConn)
		carrier = &outtls.RealityUConn{UConn: u}
	}
	c, err := NewConn(carrier, bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	if kind != "reality-accessor" && c.DependencyLease() != parent.raw.lease {
		t.Fatal("Vision lost parent stream lease")
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	t.Cleanup(func() { _ = c.Close(); _ = server.NetConn().Close() })
	return c, server, parent.raw
}
func record(uuid []byte, command byte, payload []byte) []byte {
	data := append([]byte(nil), uuid...)
	data = append(data, command, byte(len(payload)>>8), byte(len(payload)), 0, 0)
	return append(data, payload...)
}
func readRecord(r io.Reader, first bool) (byte, []byte, error) {
	size := 5
	if first {
		size += 16
	}
	header := make([]byte, size)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	header = header[size-5:]
	content := int(binary.BigEndian.Uint16(header[1:3]))
	padding := int(binary.BigEndian.Uint16(header[3:5]))
	data := make([]byte, content+padding)
	_, err := io.ReadFull(r, data)
	return header[0], data[:content], err
}
func TestTLSCarriersDrainToRawAndCloseWriteUsesActiveDirection(t *testing.T) {
	for _, kind := range []string{"tls", "utls", "reality-accessor"} {
		t.Run(kind, func(t *testing.T) {
			t.Run("read-direct", func(t *testing.T) {
				c, server, _ := tlsPair(t, kind)
				done := make(chan error, 1)
				go func() {
					_, err := server.Write(record(c.uuid[:], commandPaddingDirect, []byte("head")))
					if err == nil {
						_, err = server.NetConn().Write([]byte("tail"))
					}
					if err == nil {
						err = server.NetConn().(*net.TCPConn).CloseWrite()
					}
					done <- err
				}()
				got, err := io.ReadAll(c)
				if err != nil || string(got) != "headtail" {
					t.Fatalf("direct read=%q,%v", got, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
			t.Run("write-direct", func(t *testing.T) {
				c, server, raw := tlsPair(t, kind)
				hello := make([]byte, 81)
				copy(hello, []byte{22, 3, 3, 0, 76, 2})
				hello[43] = 0
				binary.BigEndian.PutUint16(hello[44:], 0x1301)
				copy(hello[60:], tls13SupportedVersions)
				done := make(chan error, 1)
				go func() { _, err := server.Write(record(c.uuid[:], commandPaddingContinue, hello)); done <- err }()
				got := make([]byte, len(hello))
				if _, err := io.ReadFull(c, got); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				app := []byte{23, 3, 3, 0, 3, 'a', 'b', 'c'}
				for i, want := range []byte{commandPaddingContinue, commandPaddingDirect} {
					if _, err := c.Write(app); err != nil {
						t.Fatal(err)
					}
					command, payload, err := readRecord(server, i == 0)
					if err != nil || command != want || !bytes.Equal(payload, app) {
						t.Fatalf("frame %d=%d,%x,%v", i, command, payload, err)
					}
				}
				if _, err := c.Write([]byte("raw")); err != nil {
					t.Fatal(err)
				}
				if err := c.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				direct, err := io.ReadAll(server.NetConn())
				if err != nil || string(direct) != "raw" || raw.halves.Load() != 1 {
					t.Fatalf("direct halfclose=%q,%v,calls=%d", direct, err, raw.halves.Load())
				}
			})
		})
	}
}
func TestXUDPPassesThroughVisionAndKeepsPacketBoundaries(t *testing.T) {
	c, server, _ := tlsPair(t, "tls")
	pc := NewPacketConn(c, netproxy.NewAddr("udp", "127.0.0.1:53"))
	target := netproxy.NewAddr("udp", "[2001:db8::1]:53")
	if n, err := pc.WriteTo([]byte("request"), target); err != nil || n != 7 {
		t.Fatalf("WriteTo=%d,%v", n, err)
	}
	_, data, err := readRecord(server, true)
	if err != nil {
		t.Fatal(err)
	}
	size := int(binary.BigEndian.Uint16(data))
	if data[4] != 1 || data[5] != 1 {
		t.Fatalf("not a new XUDP request: %x", data)
	}
	addr, err := readPacketAddress(data[6 : 2+size])
	if err != nil || addr.String() != target.String() {
		t.Fatalf("XUDP address=%v,%v", addr, err)
	}
	// Server Keep frames may omit the destination and use the fixed association.
	reply := []byte{0, 4, 0, 0, 2, 1, 0, 3, 'a', 'b', 'c', 0, 4, 0, 0, 2, 1, 0, 2, 'd', 'e'}
	done := make(chan error, 1)
	go func() { _, err := server.Write(record(c.uuid[:], commandPaddingEnd, reply)); done <- err }()
	p := make([]byte, 1)
	n, _, err := pc.ReadFrom(p)
	if n != 1 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("truncation=%d,%v", n, err)
	}
	p = make([]byte, 20)
	n, _, err = pc.ReadFrom(p)
	if err != nil || string(p[:n]) != "de" {
		t.Fatalf("next datagram=%q,%v", p[:n], err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
