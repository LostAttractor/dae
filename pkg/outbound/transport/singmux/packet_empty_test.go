package singmux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
)

func TestUDPWritePreservesEmptyDatagrams(t *testing.T) {
	for _, implementation := range []string{"generic", "smux"} {
		t.Run(implementation, func(t *testing.T) {
			local, remote := net.Pipe()
			session := newTestSmuxSession(local)
			defer session.Close()
			server := smuxtest.Server(remote)
			defer server.Close()
			queued := testSmuxPacketConn(t, session)
			var conn net.PacketConn = queued
			if implementation == "generic" {
				queued.onceWrite = false
				conn = &queued.UDPConn
			}
			payloads := [][]byte{nil, []byte("next"), nil}
			address := netproxy.NewAddr("udp", "192.0.2.1:53")
			for _, payload := range payloads {
				if n, err := conn.WriteTo(payload, address); n != len(payload) || err != nil {
					t.Fatalf("WriteTo = %d, %v", n, err)
				}
			}
			peer, err := server.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadFull(peer, make([]byte, 2)); err != nil {
				t.Fatal(err)
			}
			if _, err := socks5.ReadAddr(peer); err != nil {
				t.Fatal(err)
			}
			for _, want := range payloads {
				from, err := socks5.ReadAddr(peer)
				if err != nil || from.String() != address.String() {
					t.Fatalf("datagram address = %v, %v", from, err)
				}
				var length uint16
				if err := binary.Read(peer, binary.BigEndian, &length); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, length)
				if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, want) {
					t.Fatalf("datagram = %q, %v; want %q", got, err, want)
				}
			}
		})
	}
}

func TestUDPRejectsOversizedDatagramBeforeRequest(t *testing.T) {
	calls := 0
	conn := &UDPConn{Conn: Conn{Conn: streamWriteFunc{write: func(p []byte) (int, error) {
		calls++
		return len(p), nil
	}}, addr: "example.org:53", udp: true, packetAddr: true}}
	if n, err := conn.WriteTo(make([]byte, 65536), netproxy.NewAddr("udp", "192.0.2.1:53")); n != 0 || !errors.Is(err, syscall.EMSGSIZE) || calls != 0 {
		t.Fatalf("oversized datagram = %d, %v; %d carrier writes", n, err, calls)
	}
}
