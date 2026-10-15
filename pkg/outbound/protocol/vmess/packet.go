package vmess

import (
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

type PacketConn struct {
	*Conn
	target     net.Addr
	packetAddr bool
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.packetAddr && len(p) == 0 {
		return 0, fmt.Errorf("empty VMess UDP payload is reserved for the end marker")
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if c.packetAddr {
		var header [19]byte
		address, err := appendPacketAddress(header[:0], addr)
		if err != nil {
			return 0, err
		}
		buf.Write(address)
	} else if addr == nil || addr.String() != c.target.String() {
		return 0, fmt.Errorf("VMess UDP stream is bound to %s", c.target)
	}
	buf.Write(p)
	if buf.Len() > MaxChunkSize-2-c.writeCipher.Overhead()-int(c.writeSize.MaxPaddingLen()) {
		return 0, fmt.Errorf("VMess datagram too large: %d", len(p))
	}
	if err := c.writeChunk(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	data, err := c.readChunk()
	if err != nil {
		return 0, nil, err
	}
	addr := c.target
	if c.packetAddr {
		addr, data, err = extractPacketAddress(data)
		if err != nil {
			return 0, nil, err
		}
	}
	n := copy(p, data)
	if n < len(data) {
		return n, addr, io.ErrShortBuffer
	}
	return n, addr, nil
}
