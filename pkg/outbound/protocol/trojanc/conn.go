// https://trojan-gfw.github.io/trojan/protocol
package trojanc

import (
	"crypto/sha256"
	"encoding/hex"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

const (
	commandConnect = 1
	commandUDP     = 3
)

// Conn sends the request header with the first Write in one carrier write.
// A CONNECT Read or a CloseWrite before any Write sends the header alone, so
// server-first protocols and read-first callers still reach the target.
type Conn struct {
	net.Conn
	addr    *socks5.AddressInfo
	command byte
	pass    [56]byte
	first   protocol.FirstWrite
}

// closeWriteConn exposes CloseWrite only over carriers that can half-close.
type closeWriteConn struct {
	*Conn
	carrier netproxy.CloseWriter
}

func newConn(conn net.Conn, addr *socks5.AddressInfo, command byte, password string) net.Conn {
	hash := sha256.Sum224([]byte(password))
	c := &Conn{Conn: conn, addr: addr, command: command}
	hex.Encode(c.pass[:], hash[:])
	if writer, ok := conn.(netproxy.CloseWriter); ok {
		return &closeWriteConn{Conn: c, carrier: writer}
	}
	return c
}

func (c *closeWriteConn) CloseWrite() error {
	c.first.Lock()
	err := c.first.FlushLocked(c.flush)
	c.first.Unlock()
	if err != nil {
		return err
	}
	return c.carrier.CloseWrite()
}

func (c *Conn) Read(b []byte) (int, error) {
	// UDP replies follow a datagram, and packet readers start before the first
	// WriteTo, so a UDP Read must neither send the header nor see write errors.
	if len(b) > 0 && c.command == commandConnect {
		if err := c.first.Flush(c.flush); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

func (c *Conn) flush() error {
	_, err := c.writeLocked(nil)
	return err
}

func (c *Conn) Write(b []byte) (int, error) {
	c.first.Lock()
	defer c.first.Unlock()
	return c.writeLocked(b)
}

func (c *Conn) writeLocked(b []byte) (int, error) {
	if !c.first.Pending() {
		return c.first.Write(c.Conn, nil, b)
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	buf.Write(c.pass[:])
	buf.WriteString("\r\n")
	buf.WriteByte(c.command)
	if err := socks5.WriteAddrInfo(c.addr, buf); err != nil {
		return 0, c.first.Done(err)
	}
	buf.WriteString("\r\n")
	c.addr = nil
	return c.first.Write(c.Conn, buf.Bytes(), b)
}
