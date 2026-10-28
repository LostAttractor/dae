package juicity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/quic-go"
)

func TestClientMetadataWireFormat(t *testing.T) {
	for _, tc := range []struct{ addr, wire string }{
		{"1.2.3.4:443", "010102030401bb"},
		{"[2001:db8::1]:53", "0420010db80000000000000000000000010035"},
		{"example.com:80", "030b6578616d706c652e636f6d0050"},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			metadata, err := protocol.ParseMetadata(tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			m := Metadata{Metadata: metadata, Network: "tcp"}
			buf := new(bytes.Buffer)
			if err = m.appendTo(buf); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(buf.Bytes()); got != tc.wire {
				t.Fatalf("wire=%s", got)
			}
			got, err := readMetadata(buf)
			if err != nil || got.Hostname != m.Hostname || got.Port != m.Port || got.Type != m.Type {
				t.Fatalf("decoded=%+v err=%v", got, err)
			}
		})
	}
}

func TestStreamUDPReadReportsTruncation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	listener, err := quic.ListenAddr("127.0.0.1:0", recoveryTLS(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"juicity-test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(0, "")
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(0, "")
	for _, tc := range []struct {
		size       int
		incomplete bool
	}{
		{size: 0}, {size: 1}, {size: 4}, {size: 8}, {size: 1, incomplete: true},
	} {
		t.Run(fmt.Sprintf("buffer=%d/incomplete=%v", tc.size, tc.incomplete), func(t *testing.T) {
			remote, err := server.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			metadata, _ := protocol.ParseMetadata("127.0.0.1:53")
			m := Metadata{Metadata: metadata, Network: "udp"}
			for _, payload := range []string{"data", "next"} {
				if err := m.appendTo(&wire); err != nil {
					t.Fatal(err)
				}
				wire.Write(binary.BigEndian.AppendUint16(nil, uint16(len(payload))))
				if tc.incomplete {
					wire.WriteString(payload[:2])
					break
				}
				wire.WriteString(payload)
			}
			if _, err := remote.Write(wire.Bytes()); err != nil {
				t.Fatal(err)
			}
			_ = remote.Close()
			stream, err := client.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.SetReadDeadline(time.Now().Add(time.Second))
			conn := &PacketConn{Conn: &Conn{Stream: stream, lease: netproxy.NewLease(netproxy.NewResourceRef())}}
			defer conn.Close()
			buf := make([]byte, tc.size)
			n, addr, err := conn.ReadFrom(buf)
			var wantErr error
			if tc.size < 4 {
				wantErr = io.ErrShortBuffer
			}
			if tc.incomplete {
				wantErr = io.EOF
			}
			if n != min(tc.size, 4) || string(buf[:n]) != "data"[:n] || addr == nil || addr.String() != "127.0.0.1:53" || !errors.Is(err, wantErr) {
				t.Fatalf("ReadFrom = %q, %v, %v; want %v", buf[:n], addr, err, wantErr)
			}
			if tc.incomplete {
				return
			}
			if !conn.lease.Valid() {
				t.Fatal("truncation invalidated the stream")
			}
			buf = make([]byte, 8)
			if n, _, err := conn.ReadFrom(buf); err != nil || string(buf[:n]) != "next" {
				t.Fatalf("next datagram = %q, %v", buf[:n], err)
			}
		})
	}
}

func TestUnderlayUDPShortReadAndInitialSaltRetry(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := &shadowsocks.Key{CipherConf: CipherConf, MasterKey: bytes.Repeat([]byte{7}, CipherConf.KeyLen)}
	salt := bytes.Repeat([]byte{9}, CipherConf.SaltLen)
	salt[0], salt[1] = 0, 0
	client := &TransportPacketConn{PacketConn: raw, proxyAddr: server.LocalAddr().(*net.UDPAddr), target: netproxy.NewAddr("udp", "127.0.0.1:0"), key: key, firstIv: append([]byte(nil), salt...)}
	defer client.Close()
	client.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err = client.Write([]byte("request")); err == nil {
		t.Fatal("past deadline accepted write")
	}
	if !bytes.Equal(client.firstIv, salt) {
		t.Fatal("failed first write consumed authentication salt")
	}
	client.SetWriteDeadline(time.Time{})
	if n, err := client.Write([]byte("request")); err != nil || n != 7 {
		t.Fatalf("Write=%d %v", n, err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	wire := make([]byte, 256)
	n, addr, err := server.ReadFrom(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[:CipherConf.SaltLen], salt) {
		t.Fatal("first salt changed")
	}
	plaintext := make([]byte, 256)
	if n, err := DecryptUDP(plaintext, key, wire[:n], ciphers.JuicityReusedInfo); err != nil || string(plaintext[:n]) != "request" {
		t.Fatalf("request decrypt=%q %v", plaintext[:n], err)
	}
	response, err := EncryptUDPFromPool(key, []byte("long response"), salt, ciphers.JuicityReusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.PutBuffer(response)
	if _, err = server.WriteTo(response, addr); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	tiny := make([]byte, 4)
	if n, _, err := client.ReadFrom(tiny); err != nil || n != 4 || string(tiny) != "long" {
		t.Fatalf("short ReadFrom=%q n=%d err=%v", tiny, n, err)
	}
}

// droppingSocket never waits: it drops while drop is set, as a socket with a
// full send buffer does.
type droppingSocket struct {
	net.PacketConn
	drop bool
	sent int
}

func (s *droppingSocket) TryWriteTo(b []byte, _ net.Addr) (int, error) {
	if s.drop {
		return 0, netproxy.ErrPacketDropped
	}
	s.sent++
	return len(b), nil
}

// The underlay encrypts and sends without waiting, and the authentication
// salt goes with the first datagram the socket takes, not one it drops.
func TestUnderlayUDPKeepsInitialSaltAcrossDrops(t *testing.T) {
	socket := &droppingSocket{drop: true}
	key := &shadowsocks.Key{CipherConf: CipherConf, MasterKey: bytes.Repeat([]byte{7}, CipherConf.KeyLen)}
	salt := bytes.Repeat([]byte{9}, CipherConf.SaltLen)
	client := &TransportPacketConn{PacketConn: socket, proxyAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, key: key, firstIv: salt}
	if writer, ok := netproxy.PacketConnAs[netproxy.NonBlockingWriter](client); !ok || writer != netproxy.NonBlockingWriter(client) {
		t.Fatalf("lookup found %T, want the underlay itself", writer)
	}
	if _, err := client.TryWriteTo([]byte("request"), nil); err != netproxy.ErrPacketDropped || client.firstIv == nil {
		t.Fatalf("dropped TryWriteTo = %v, salt kept %v", err, client.firstIv != nil)
	}
	if n, err := client.Write([]byte("request")); n != 7 || err != nil || client.firstIv == nil {
		t.Fatalf("dropped Write = %d, %v, salt kept %v", n, err, client.firstIv != nil)
	}
	socket.drop = false
	if _, err := client.TryWriteTo([]byte("request"), nil); err != nil || socket.sent != 1 || client.firstIv != nil {
		t.Fatalf("TryWriteTo = %v with %d sent, salt kept %v", err, socket.sent, client.firstIv != nil)
	}
}

func TestUnderlayUDPChecksCarrierBeforeEncryption(t *testing.T) {
	// No key: attempting encryption before rejecting this carrier would panic.
	client := &TransportPacketConn{PacketConn: new(net.UDPConn)}
	if client.CanTryWrite() {
		t.Fatal("waiting carrier reported nonblocking capability")
	}
	if _, err := client.TryWriteTo([]byte("request"), nil); err != errors.ErrUnsupported {
		t.Fatalf("TryWriteTo = %v", err)
	}
}
