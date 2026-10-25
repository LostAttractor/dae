package proto

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_stream"
)

type PacketConn struct {
	*shadowsocks_stream.UdpConn
	codec   IProtocol
	codecMu sync.Mutex
}

func (c *PacketConn) DependencyLease() *netproxy.Lease { return c.UdpConn.DependencyLease() }

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	n, err := c.UdpConn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	c.codecMu.Lock()
	decoded, err := c.codec.DecodePkt(buf[:n])
	c.codecMu.Unlock()
	if err != nil {
		return 0, nil, err
	}
	address := socks.SplitAddr(decoded)
	if address == nil {
		return 0, nil, errors.New("SSR packet has no target address")
	}
	payload := decoded[len(address):]
	n = copy(p, payload)
	if n < len(payload) {
		err = io.ErrShortBuffer
	}
	return n, netproxy.NewAddr("udp", address.String()), err
}

func (c *PacketConn) WriteTo(p []byte, target net.Addr) (int, error) {
	return c.writeTo(p, target, c.UdpConn.Write)
}

// TryWriteTo sends the encoded datagram without waiting; see
// netproxy.NonBlockingWriter.
func (c *PacketConn) TryWriteTo(p []byte, target net.Addr) (int, error) {
	if !c.CanTryWrite() {
		return 0, errors.ErrUnsupported
	}
	return c.writeTo(p, target, c.UdpConn.TryWrite)
}

func (c *PacketConn) writeTo(p []byte, target net.Addr, write func([]byte) (int, error)) (int, error) {
	if target == nil {
		return 0, errors.New("SSR packet has no target address")
	}
	address, err := socks.ParseAddr(target.String())
	if err != nil {
		return 0, err
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	buf.Write(address)
	buf.Write(p)
	c.codecMu.Lock()
	err = c.codec.EncodePkt(buf)
	c.codecMu.Unlock()
	if err != nil {
		return 0, err
	}
	if buf.Len() > 65507 {
		return 0, errors.New("SSR packet exceeds maximum size")
	}
	n, err := write(buf.Bytes())
	if n == buf.Len() {
		return len(p), err
	}
	if err == nil {
		err = io.ErrShortWrite
	}
	return 0, err
}
