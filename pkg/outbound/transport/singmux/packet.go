package singmux

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type UDPConn struct {
	Conn
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	addr, err = socks5.ReadAddr(&c.Conn)
	if err != nil {
		return 0, nil, err
	}
	var length uint16
	err = binary.Read(&c.Conn, binary.BigEndian, &length)
	if err != nil {
		return 0, nil, err
	}
	n, err = io.ReadFull(&c.Conn, b[:min(len(b), int(length))])
	if err != nil {
		return n, addr, err
	}
	if n < int(length) {
		if _, err = io.CopyN(io.Discard, &c.Conn, int64(int(length)-n)); err != nil {
			return n, addr, err
		}
		return n, addr, io.ErrShortBuffer
	}
	return n, addr, nil
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if len(b) > 0 {
		err = socks5.WriteNetAddr(addr, buf)
		if err != nil {
			return 0, err
		}
		binary.Write(buf, binary.BigEndian, uint16(len(b)))
		buf.Write(b)
	}
	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}

// smuxPacketConn writes datagrams to an smux stream without waiting: each is
// queued as its own frames or dropped once the stream or session holds too
// many queued datagrams; see netproxy.NonBlockingWriter. Reads stay with
// UDPConn.
type smuxPacketConn struct {
	UDPConn
	leased *leasedStream
	stream *smuxStream

	request   []byte // sent with the first datagram, which is never dropped
	mu        sync.Mutex
	requested atomic.Bool
}

func newSmuxPacketConn(leased *leasedStream, stream *smuxStream, layer netproxy.FailureLayer, addr string) (*smuxPacketConn, error) {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if err := WriteStreamRequest(buf, &StreamRequest{Destination: addr, UDP: true, PacketAddr: true}); err != nil {
		_ = leased.Close()
		return nil, err
	}
	stream.session.mu.Lock()
	stream.datagram = true
	stream.session.mu.Unlock()
	return &smuxPacketConn{
		UDPConn: UDPConn{Conn: Conn{Conn: leased, layer: layer, addr: addr, udp: true, packetAddr: true, onceWrite: true}},
		leased:  leased, stream: stream, request: bytes.Clone(buf.Bytes()),
	}, nil
}

// WriteTo reports a dropped datagram as written: to callers that do not
// count drops, as quic-go or DNS, ErrPacketDropped would be a failure.
func (c *smuxPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.TryWriteTo(b, addr)
	if err == netproxy.ErrPacketDropped {
		return len(b), nil
	}
	return n, err
}

func (c *smuxPacketConn) TryWriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if !c.requested.Load() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.requested.Load() {
			return c.writeTo(b, addr, c.request)
		}
	}
	return c.writeTo(b, addr, nil)
}

// writeTo queues one datagram behind request, if any, which forces it.
func (c *smuxPacketConn) writeTo(b []byte, addr net.Addr, request []byte) (int, error) {
	var header [socks.MaxAddrLen + 2]byte
	prefix, err := socks5.AppendNetAddr(header[:0], addr)
	if err != nil {
		return 0, err
	}
	prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(b)))
	size := smuxHeaderSize + len(request) + len(prefix) + len(b)
	var data []byte
	if size <= smuxFullFrame {
		data = newFrame(size, 0)
	} else {
		data = pool.GetBuffer(size) // writeDatagram splits it into frames
	}
	n := smuxHeaderSize + copy(data[smuxHeaderSize:], request)
	copy(data[n+copy(data[n:], prefix):], b)
	err = c.stream.writeDatagram(data, request != nil)
	if request != nil && err == nil {
		c.requested.Store(true)
	}
	switch {
	case err == nil:
		return len(b), nil
	case err == netproxy.ErrPacketDropped:
		return 0, err
	default:
		return 0, c.leased.failure(err, netproxy.OpWrite)
	}
}
