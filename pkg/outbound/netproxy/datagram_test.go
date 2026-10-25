package netproxy

import (
	"errors"
	"net"
	"testing"
)

type queuedPacketConn struct {
	net.PacketConn
	to []net.Addr
}

func (c *queuedPacketConn) TryWriteTo(b []byte, addr net.Addr) (int, error) {
	c.to = append(c.to, addr)
	return len(b), nil
}

// Dispatch through ownership wrappers preserves the packet layer.
func TestTryWritePacketDispatchAndFallback(t *testing.T) {
	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	buf := make([]byte, 16)
	queue := new(queuedPacketConn)
	bound := &BindPacketConn{PacketConn: queue, Address: to}
	if !CanTryWrite(TrackConn(bound, func() {})) {
		t.Fatal("queued carrier reported no capability")
	}
	if _, err := TryWrite(bound, []byte("datagram")); err != nil || len(queue.to) != 1 || queue.to[0] != to {
		t.Fatalf("TryWrite = %v, queued to %v", err, queue.to)
	}

	pipe, peer := net.Pipe()
	defer pipe.Close()
	defer peer.Close()
	if CanTryWrite(TrackConn(pipe, func() {})) {
		t.Fatal("waiting carrier reported nonblocking capability")
	}
	if _, err := TryWrite(pipe, []byte("datagram")); err != errors.ErrUnsupported {
		t.Fatalf("TryWrite on a pipe = %v", err)
	}
	go func() { _, _ = peer.Read(buf) }()
	if n, err := WriteDatagram(pipe, []byte("datagram")); n != 8 || err != nil {
		t.Fatalf("WriteDatagram on a pipe = %d, %v", n, err)
	}
}
