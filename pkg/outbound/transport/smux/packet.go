package smux

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/pool"
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
