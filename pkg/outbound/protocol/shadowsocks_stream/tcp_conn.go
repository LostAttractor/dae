package shadowsocks_stream

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

type TcpConn struct {
	net.Conn
	cipher                *ciphers.StreamCipher
	readMu, writeMu       sync.Mutex
	readIV                []byte
	readIVUsed            int
	readReady, writeReady bool
	readErr, writeErr     error
}

func NewTCPConn(conn net.Conn, cipher *ciphers.StreamCipher) *TcpConn {
	return &TcpConn{Conn: conn, cipher: cipher, readIV: make([]byte, cipher.InfoIVLen())}
}
func (c *TcpConn) Cipher() *ciphers.StreamCipher    { return c.cipher }
func (c *TcpConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }

func (c *TcpConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	if !c.readReady {
		n, err := io.ReadFull(c.Conn, c.readIV[c.readIVUsed:])
		c.readIVUsed += n
		if err != nil {
			return 0, err
		}
		if err := c.cipher.InitDecrypt(c.readIV); err != nil {
			c.readErr = err
			return 0, err
		}
		c.readReady = true
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.cipher.Decrypt(p[:n], p[:n])
	}
	return n, err
}

func (c *TcpConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	iv, err := c.cipher.InitEncrypt()
	if err != nil {
		c.writeErr = err
		return 0, err
	}
	if !c.writeReady {
		if inner, ok := c.Conn.(interface{ SetCipher(*ciphers.StreamCipher) }); ok {
			inner.SetCipher(c.cipher)
		}
		if inner, ok := c.Conn.(interface{ SetAddrLen(int) }); ok {
			inner.SetAddrLen(len(p))
		}
	}
	written := 0
	for written < len(p) {
		size := min(len(p)-written, 32<<10)
		ivSize := 0
		if !c.writeReady {
			ivSize = len(iv)
		}
		buf := pool.GetBuffer(ivSize + size)
		copy(buf, iv)
		c.cipher.Encrypt(buf[ivSize:], p[written:written+size])
		n, err := c.Conn.Write(buf)
		pool.PutBuffer(buf)
		if err == nil && n != ivSize+size {
			err = io.ErrShortWrite
		}
		c.writeReady = true
		if err != nil {
			c.writeErr = err
			return written + max(0, min(size, n-ivSize)), err
		}
		written += size
	}
	return written, nil
}

func (c *TcpConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	c.writeErr = net.ErrClosed
	if writer, ok := c.Conn.(netproxy.CloseWriter); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}
