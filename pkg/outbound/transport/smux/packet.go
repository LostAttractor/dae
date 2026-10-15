package smux

import (
	"encoding/binary"
	"fmt"
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
	n, err = c.Conn.Read(b)
	if n != int(length) {
		return 0, nil, fmt.Errorf("read length mismatch: %d != %d", n, length)
	}
	return n, addr, err
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if len(b) > 0 {
		err = socks5.WriteAddr(addr.String(), buf)
		if err != nil {
			return 0, err
		}
		binary.Write(buf, binary.BigEndian, uint16(len(b)))
		buf.Write(b)
	}
	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}
