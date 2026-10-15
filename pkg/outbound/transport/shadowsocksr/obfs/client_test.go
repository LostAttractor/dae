package obfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/transport/shadowsocksr/proto"
)

// Independent peer records: hello random MAC, optional ticket, CCS, and a
// finished MAC over the entire flight, as defined by obfs_tls.py.
func peerTLSFlight(key, clientID, payload []byte) []byte {
	mac := func(data []byte) []byte {
		h := hmac.New(sha1.New, append(bytes.Clone(key), clientID...))
		h.Write(data)
		return h.Sum(nil)[:10]
	}
	hello := make([]byte, 76)
	copy(hello, []byte{0x16, 3, 3, 0, 71, 2, 0, 0, 67, 3, 3})
	copy(hello[11:33], bytes.Repeat([]byte{0x56}, 22))
	copy(hello[33:43], mac(hello[11:33]))
	flight := append(hello, 0x16, 3, 3, 0, 4, 4, 0, 0, 0)
	flight = append(flight, 0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 32)
	flight = append(flight, bytes.Repeat([]byte{0x78}, 22)...)
	flight = append(flight, mac(flight)...)
	flight = append(flight, 0x17, 3, 3, byte(len(payload)>>8), byte(len(payload)))
	return append(flight, payload...)
}

func TestTicketHandshakeFragmentsAndAuthentication(t *testing.T) {
	for _, fast := range []bool{false, true} {
		for _, fragmented := range []bool{false, true} {
			codec := newTLS12TicketAuth(fast).(*tls12TicketAuth)
			codec.SetServerInfo(&ServerInfo{Host: "example.org", Key: []byte("shared key")})
			first, err := codec.Encode([]byte("target"))
			if err != nil {
				t.Fatal(err)
			}
			helloSize := 5 + int(binary.BigEndian.Uint16(first[3:5]))
			if fast && len(first) <= helloSize {
				t.Fatal("fastauth did not send the target in its first flight")
			}
			if !fast && len(first) != helloSize {
				t.Fatal("ordinary auth sent data before the peer handshake")
			}
			flight := peerTLSFlight(codec.Key, first[44:76], []byte("reply"))
			var got bytes.Buffer
			backs := 0
			for len(flight) > 0 {
				n := len(flight)
				if fragmented {
					n = 1
				}
				plain, sendBack, err := codec.Decode(flight[:n])
				if err != nil {
					t.Fatal(err)
				}
				got.Write(plain)
				if sendBack {
					backs++
				}
				flight = flight[n:]
			}
			wantBacks := 1
			if fast {
				wantBacks = 0
			}
			if got.String() != "reply" || backs != wantBacks {
				t.Fatalf("fast=%v fragmented=%v: payload=%q, replies=%d", fast, fragmented, got.String(), backs)
			}
		}
	}
	for _, offset := range []int{33, 127} {
		codec := newTLS12TicketAuth(false).(*tls12TicketAuth)
		codec.Key = []byte("key")
		flight := peerTLSFlight(codec.Key, codec.data.localClientID[:], []byte("secret"))
		flight[offset] ^= 1
		plain, _, err := codec.Decode(flight)
		if !errors.Is(err, proto.ErrTLS12TicketAuthHMACError) || len(plain) != 0 {
			t.Fatalf("tampered flight released data: %x, %v", plain, err)
		}
	}
}

func TestHTTPHeaderSurvivesReadDeadline(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	conn := &Conn{Conn: client, codec: newHttpSimple()}
	defer conn.Close()
	firstWritten := make(chan struct{})
	go func() { _, _ = peer.Write([]byte("HTTP/1.1 200 OK\r\nX-Header: va")); close(firstWritten) }()
	conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("expected read deadline: %v", err)
	}
	<-firstWritten
	conn.SetReadDeadline(time.Time{})
	go func() { _, _ = peer.Write([]byte("lue\r\n\r\nreply")) }()
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "reply" {
		t.Fatalf("buffer lost after deadline: %q, %v", buf[:n], err)
	}
}

func TestTicketHandshakeFlushesTargetAndPreservesReply(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	codec := newTLS12TicketAuth(false).(*tls12TicketAuth)
	conn := &Conn{Conn: client, codec: codec}
	defer conn.Close()
	cipher, err := ciphers.NewStreamCipher("aes-128-cfb", "password")
	if err != nil {
		t.Fatal(err)
	}
	conn.SetCipher(cipher)
	conn.SetDeadline(time.Now().Add(time.Second))
	server := make(chan error, 1)
	go func() {
		var header [5]byte
		if _, err := io.ReadFull(peer, header[:]); err != nil {
			server <- err
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err := io.ReadFull(peer, body); err != nil {
			server <- err
			return
		}
		if _, err := peer.Write(peerTLSFlight(cipher.Key(), body[39:71], []byte("reply"))); err != nil {
			server <- err
			return
		}
		finished := make([]byte, 43)
		if _, err := io.ReadFull(peer, finished); err != nil {
			server <- err
			return
		}
		if _, err := io.ReadFull(peer, header[:]); err != nil {
			server <- err
			return
		}
		body = make([]byte, binary.BigEndian.Uint16(header[3:]))
		_, err := io.ReadFull(peer, body)
		if err == nil && string(body) != "target" {
			err = errors.New("target was not flushed")
		}
		server <- err
	}()
	if _, err := conn.Write([]byte("target")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("pending handshake accepted FIN: %v", err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-server; err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "reply" {
		t.Fatalf("coalesced response: %q %v", buf, err)
	}
}
