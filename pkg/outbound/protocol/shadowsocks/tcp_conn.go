package shadowsocks

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/internal/aeadframe"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

const (
	TCPChunkMaxLen = (1 << 14) - 1
)

// TCPConn represents a Shadowsocks TCP connection. Its request header (the
// salt, then the target address unless addr is nil) goes with the first
// write; a Read or CloseWrite before any write sends it alone.
type TCPConn struct {
	net.Conn
	addr       *socks5.AddressInfo
	cipherConf *ciphers.CipherConf
	masterKey  []byte
	sg         SaltGenerator

	cipherWrite cipher.AEAD
	onceRead    bool
	first       protocol.FirstWrite // the write lock
	nonceWrite  []byte
	writeErr    error // Sticky after an incomplete ciphertext write or a failed header.

	readMutex sync.Mutex

	reader aeadframe.Reader
}

type Key struct {
	CipherConf *ciphers.CipherConf
	MasterKey  []byte
}

// A nil addr omits the destination header for an enclosing client protocol.
func NewTCPConn(conn net.Conn, conf *ciphers.CipherConf, masterKey []byte, sg SaltGenerator, addr *socks5.AddressInfo) net.Conn {
	tcpConn := &TCPConn{
		Conn:       conn,
		addr:       addr,
		cipherConf: conf,
		masterKey:  masterKey,
		sg:         sg,
		nonceWrite: make([]byte, conf.NonceLen),
		reader:     aeadframe.Reader{Conn: conn},
	}
	return tcpConn
}

// Read sends a pending destination header first so the server can answer a
// client that reads before writing. Without a destination, the enclosing
// protocol owns the request and decides when to send it.
func (c *TCPConn) Read(b []byte) (int, error) {
	if len(b) > 0 && c.addr != nil {
		if err := c.first.Flush(c.flush); err != nil {
			return 0, err
		}
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if !c.onceRead && len(b) > 0 {
		salt, err := c.reader.Peek(c.cipherConf.SaltLen)
		if err != nil {
			return 0, err
		}
		aead, err := CreateCipher(c.masterKey, salt, c.cipherConf)
		if err != nil {
			return 0, c.reader.Fail(fmt.Errorf("fail to initiate cipher: %w", err))
		}
		c.reader.Discard(len(salt))
		c.reader.Start(aead, make([]byte, c.cipherConf.NonceLen), -1)
		c.onceRead = true
	}
	return c.reader.Read(b)
}

func (c *TCPConn) Close() error {
	err := c.Conn.Close() // Interrupt Read before acquiring its mutex.
	c.readMutex.Lock()
	c.reader.Close()
	c.readMutex.Unlock()
	return err
}

// CloseWrite follows the last complete encrypted frame and leaves Read usable.
func (c *TCPConn) CloseWrite() error {
	c.first.Lock()
	defer c.first.Unlock()
	if err := c.first.FlushLocked(c.flush); err != nil {
		return err
	}
	if c.writeErr != nil {
		return c.writeErr
	}
	writer, ok := c.Conn.(netproxy.CloseWriter)
	if !ok {
		c.writeErr = errors.ErrUnsupported
		return c.writeErr
	}
	err := writer.CloseWrite()
	c.writeErr = err
	if err == nil {
		c.writeErr = net.ErrClosed
	}
	return err
}

func (c *TCPConn) Write(b []byte) (int, error) { return c.WriteBuffers([][]byte{b}) }

// WriteBuffers seals the concatenation of v in chunks cut by aeadframe.Seal
// and writes them at once. An incomplete write is sticky, as in Write.
func (c *TCPConn) WriteBuffers(v [][]byte) (int, error) {
	c.first.Lock()
	defer c.first.Unlock()
	return c.writeLocked(v)
}

// flush sends the header alone. The caller holds first.
func (c *TCPConn) flush() error {
	_, err := c.writeLocked(nil)
	return err
}

func (c *TCPConn) writeLocked(v [][]byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	total := 0
	for _, b := range v {
		total += len(b)
	}
	first := c.first.Pending()
	var salt []byte
	payload := v
	if first {
		// The salt precedes the first chunk, which carries the address.
		salt = c.sg.Get()
		defer pool.PutBuffer(salt)
		var err error
		if c.cipherWrite, err = CreateCipher(c.masterKey, salt, c.cipherConf); err != nil {
			err = fmt.Errorf("fail to initiate cipher: %w", err)
		} else if c.addr != nil {
			address := pool.GetBytesBuffer()
			defer pool.PutBytesBuffer(address)
			if err = socks5.WriteAddrInfo(c.addr, address); err == nil {
				payload = append([][]byte{address.Bytes()}, v...)
			}
		}
		if err != nil {
			c.writeErr = c.first.Done(err)
			return 0, err
		}
	}
	buf := pool.GetBuffer(len(salt) + aeadframe.SealedSize(c.cipherWrite, payload, TCPChunkMaxLen))
	defer pool.PutBuffer(buf)
	out := aeadframe.Seal(append(buf[:0], salt...), c.cipherWrite, c.nonceWrite, payload, TCPChunkMaxLen)
	written, err := c.Conn.Write(out)
	if written != len(out) && err == nil {
		err = io.ErrShortWrite
	}
	if first {
		c.first.Done(err)
	}
	// After the header, a complete frame keeps later writes aligned.
	if err != nil && (first || written != len(out)) {
		c.writeErr = err
	}
	if written != len(out) {
		return 0, err
	}
	return total, err
}
