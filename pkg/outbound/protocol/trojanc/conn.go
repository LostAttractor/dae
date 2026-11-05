// https://trojan-gfw.github.io/trojan/protocol
package trojanc

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
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
	addr        *socks5.AddressInfo
	command     byte
	pass        [56]byte
	writeMutex  sync.Mutex
	wroteHeader atomic.Bool
	writeErr    error
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
	if err := c.flushHeader(); err != nil {
		return err
	}
	return c.carrier.CloseWrite()
}

func (c *Conn) Read(b []byte) (int, error) {
	// UDP replies follow a datagram, and packet readers start before the first
	// WriteTo, so a UDP Read must neither send the header nor see write errors.
	if len(b) > 0 && c.command == commandConnect {
		if err := c.flushHeader(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

func (c *Conn) flushHeader() error {
	if c.wroteHeader.Load() {
		return nil
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.wroteHeader.Load() {
		return nil
	}
	_, err := c.writeLocked(nil)
	return err
}

func (c *Conn) Write(b []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	return c.writeLocked(b)
}

func (c *Conn) writeLocked(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.wroteHeader.Load() {
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
	c.wroteHeader.Store(true)
	c.addr = nil
	return n - headerLen, err
}
