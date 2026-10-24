package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/internal/aeadframe"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

const (
	TCPChunkMaxLen = (1 << 14) - 1
)

// TCPConn represents a Shadowsocks TCP connection
type TCPConn struct {
	net.Conn
	addr       *socks5.AddressInfo
	cipherConf *ciphers.CipherConf
	masterKey  []byte
	sg         SaltGenerator

	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool
	nonceWrite  []byte
	writeErr    error // Sticky after an incomplete ciphertext write.

	readMutex  sync.Mutex
	writeMutex sync.Mutex

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

func (c *TCPConn) Read(b []byte) (int, error) {
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
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
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

func (c *TCPConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	buf := pool.GetBytesBuffer()
	payload := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	defer pool.PutBytesBuffer(payload)
	if !c.onceWrite {
		defer func() {
			if err != nil && !c.onceWrite {
				c.writeErr = err
			}
		}()
		// Generate salt and setup encryption
		salt := c.sg.Get()
		defer pool.PutBuffer(salt)
		c.cipherWrite, err = CreateCipher(c.masterKey, salt, c.cipherConf)
		if err != nil {
			return 0, fmt.Errorf("fail to initiate cipher: %w", err)
		}
		// Add salt for first write
		buf.Write(salt)

		if c.addr != nil {
			if err = socks5.WriteAddrInfo(c.addr, payload); err != nil {
				return 0, err
			}
		}

		c.onceWrite = true
	}
	payload.Write(b)
	c.seal(buf, payload.Bytes())
	written, err := c.Conn.Write(buf.Bytes())
	if written == buf.Len() {
		return len(b), err
	}
	if err == nil {
		err = io.ErrShortWrite
	}
	c.writeErr = err
	return 0, err
}

func (c *TCPConn) seal(buf *bytes.Buffer, payload []byte) {
	chunks := (len(payload) + TCPChunkMaxLen - 1) / TCPChunkMaxLen
	buf.Grow(len(payload) + chunks*(2+2*c.cipherWrite.Overhead()))
	var chunkLengthBuf [2]byte
	for i := 0; i < len(payload); i += TCPChunkMaxLen {
		// write chunk
		var chunkLength = common.Min(TCPChunkMaxLen, len(payload)-i)
		binary.BigEndian.PutUint16(chunkLengthBuf[:], uint16(chunkLength))
		buf.Write(c.cipherWrite.Seal(buf.AvailableBuffer(), c.nonceWrite, chunkLengthBuf[:], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(buf.AvailableBuffer(), c.nonceWrite, payload[i:i+chunkLength], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
	}
}
