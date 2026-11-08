package shadowsocks_stream

import (
	"cmp"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

// TcpConn encrypts one Shadowsocks stream. A conn returned by
// Dialer.DialContext holds the target address header until the first Write,
// which sends IV, header and payload in one carrier write; a Read or CloseWrite
// before any Write sends the header alone first.
type TcpConn struct {
	net.Conn
	cipher            *ciphers.StreamCipher
	readMu            sync.Mutex
	first             protocol.FirstWrite // the IV and any header go with the first write
	readIV            []byte
	readIVUsed        int
	readReady         bool
	readErr, writeErr error
	header            []byte // nil unless DialContext deferred a header
}

func NewTCPConn(conn net.Conn, cipher *ciphers.StreamCipher) *TcpConn {
	return &TcpConn{Conn: conn, cipher: cipher, readIV: make([]byte, cipher.InfoIVLen())}
}
func (c *TcpConn) Cipher() *ciphers.StreamCipher    { return c.cipher }
func (c *TcpConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }

func (c *TcpConn) Read(p []byte) (int, error) {
	if len(p) > 0 && c.header != nil {
		if err := c.first.Flush(c.flush); err != nil {
			return 0, err
		}
	}
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
	c.first.Lock()
	defer c.first.Unlock()
	return c.write(p)
}

// flush lets server-first peers reply before the caller writes.
func (c *TcpConn) flush() error {
	_, err := c.write(nil)
	return err
}

func (c *TcpConn) write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	var header []byte
	if c.first.Pending() {
		header = c.header
	}
	if len(p) == 0 && header == nil {
		return 0, nil
	}
	iv, err := c.cipher.InitEncrypt()
	if err != nil {
		c.writeErr = err
		if c.first.Pending() {
			c.first.Done(err)
		}
		return 0, err
	}
	if c.first.Pending() {
		if inner, ok := c.Conn.(interface{ SetCipher(*ciphers.StreamCipher) }); ok {
			inner.SetCipher(c.cipher)
		}
		if inner, ok := c.Conn.(interface{ SetAddrLen(int) }); ok {
			// SSR obfuscation sizes its first request around the address.
			inner.SetAddrLen(cmp.Or(len(header), len(p)))
		}
	}
	written := 0
	for len(header) > 0 || written < len(p) {
		size := min(len(p)-written, 32<<10)
		ivSize := 0
		if c.first.Pending() {
			ivSize = len(iv)
		}
		headEnd := ivSize + len(header)
		buf := pool.GetBuffer(headEnd + size)
		copy(buf, iv)
		// Cap the header slice: Salsa20 uses spare dst capacity as scratch.
		c.cipher.Encrypt(buf[ivSize:headEnd:headEnd], header)
		c.cipher.Encrypt(buf[headEnd:], p[written:written+size])
		n, err := c.Conn.Write(buf)
		pool.PutBuffer(buf)
		if err == nil && n != len(buf) {
			err = io.ErrShortWrite
		}
		if c.first.Pending() {
			header = nil
			c.first.Done(err)
		}
		if err != nil {
			c.writeErr = err
			return written + max(0, min(size, n-headEnd)), err
		}
		written += size
	}
	return written, nil
}

func (c *TcpConn) CloseWrite() error {
	c.first.Lock()
	defer c.first.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	// The peer needs the target before EOF, and a later Read must not find a
	// closed write side with the header still pending.
	if _, err := c.write(nil); err != nil {
		return err
	}
	c.writeErr = net.ErrClosed
	if writer, ok := c.Conn.(netproxy.CloseWriter); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}
