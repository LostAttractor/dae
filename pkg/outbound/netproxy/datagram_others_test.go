//go:build !linux

package netproxy

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestUDPSocketUnsupportedAndWriteFallback(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	socket := NewUDPSocket(client)
	if socket != nil || socket.Send(nil, netip.AddrPort{}) != errors.ErrUnsupported {
		t.Fatal("non-Linux socket did not report unsupported")
	}
	conn := TrackConn(client, func() {})
	if CanTryWrite(conn) {
		t.Fatal("unsupported socket reported nonblocking capability")
	}
	if _, err := TryWrite(conn, []byte("not sent")); err != errors.ErrUnsupported {
		t.Fatalf("TryWrite = %v", err)
	}
	if n, err := WriteDatagram(conn, []byte("fallback")); n != 8 || err != nil {
		t.Fatalf("WriteDatagram = %d, %v", n, err)
	}
	var buf [16]byte
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := server.ReadFrom(buf[:]); err != nil || string(buf[:n]) != "fallback" {
		t.Fatalf("received %q, %v", buf[:n], err)
	}
}
