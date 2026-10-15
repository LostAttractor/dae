package vless

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

type packetConn struct {
	net.Conn
	target          net.Addr
	reader          *bufio.Reader
	readMu, writeMu sync.Mutex
	size            int
	haveSize        bool
}

func newPacketConn(conn net.Conn, target net.Addr) *packetConn {
	return &packetConn{Conn: conn, target: target, reader: bufio.NewReaderSize(conn, 65535)}
}
func (c *packetConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil || addr.String() != c.target.String() {
		return 0, fmt.Errorf("VLESS UDP stream is bound to %s", c.target)
	}
	if len(p) > 65535 {
		return 0, fmt.Errorf("VLESS datagram too large: %d", len(p))
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	buf.WriteByte(byte(len(p) >> 8))
	buf.WriteByte(byte(len(p)))
	buf.Write(p)
	n, err := c.Conn.Write(buf.Bytes())
	if err == nil && n != buf.Len() {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if !c.haveSize {
		header, err := c.reader.Peek(2)
		if err != nil {
			return 0, nil, err
		}
		c.size = int(binary.BigEndian.Uint16(header))
		_, _ = c.reader.Discard(2)
		c.haveSize = true
	}
	data, err := c.reader.Peek(c.size)
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, data)
	_, _ = c.reader.Discard(c.size)
	c.haveSize = false
	if n < c.size {
		return n, c.target, io.ErrShortBuffer
	}
	return n, c.target, nil
}
