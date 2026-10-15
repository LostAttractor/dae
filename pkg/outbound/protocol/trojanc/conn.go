// https://trojan-gfw.github.io/trojan/protocol
package trojanc

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

const (
	commandConnect = 1
	commandUDP     = 3
)

type Conn struct {
	net.Conn
	addr        *socks5.AddressInfo
	command     byte
	pass        [56]byte
	writeMutex  sync.Mutex
	wroteHeader bool
	writeErr    error
}

func newConn(conn net.Conn, addr *socks5.AddressInfo, command byte, password string) net.Conn {
	hash := sha256.Sum224([]byte(password))
	c := &Conn{Conn: conn, addr: addr, command: command}
	hex.Encode(c.pass[:], hash[:])
	if writer, ok := conn.(netproxy.CloseWriter); ok {
		return &netproxy.CloseWriteConn{Conn: c, CloseWriter: writer}
	}
	return c
}

func (c *Conn) Write(b []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.wroteHeader {
		return c.Conn.Write(b)
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	buf.Write(c.pass[:])
	buf.WriteString("\r\n")
	buf.WriteByte(c.command)
	if err := socks5.WriteAddrInfo(c.addr, buf); err != nil {
		c.writeErr = err
		return 0, err
	}
	buf.WriteString("\r\n")
	headerLen := buf.Len()
	buf.Write(b)
	n, err := c.Conn.Write(buf.Bytes())
	if n != buf.Len() {
		if err == nil {
			err = io.ErrShortWrite
		}
		c.writeErr = err
		return 0, err
	}
	c.wroteHeader = true
	c.addr = nil
	return n - headerLen, err
}
