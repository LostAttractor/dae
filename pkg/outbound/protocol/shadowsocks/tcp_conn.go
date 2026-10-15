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
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
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

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool
	nonceRead   []byte
	nonceWrite  []byte
	writeErr    error // Sticky after an incomplete ciphertext write.
	readErr     error

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	readBuf    []byte
	readOffset int
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
		nonceRead:  make([]byte, conf.NonceLen),
		nonceWrite: make([]byte, conf.NonceLen),
	}
	return tcpConn
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(b) == 0 {
		return 0, nil
	}

	if c.readBuf != nil {
		n = copy(b, c.readBuf[c.readOffset:])
		c.readOffset += n
		if c.readOffset == len(c.readBuf) {
			pool.PutBuffer(c.readBuf)
			c.readBuf = nil
			c.readOffset = 0
		}
		return n, nil
	}

	if !c.onceRead {
		var salt = pool.GetBuffer(c.cipherConf.SaltLen)
		defer pool.PutBuffer(salt)

		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			if n > 0 {
				c.readErr = err
			}
			return 0, err
		}
		c.cipherRead, err = CreateCipher(c.masterKey, salt, c.cipherConf)
		if err != nil {
			c.readErr = fmt.Errorf("fail to initiate cipher: %w", err)
			return 0, c.readErr
		}

		c.onceRead = true
	}

	// Chunk
	payload, err := c.readChunk()
	if err != nil {
		return 0, err
	}
	n = copy(b, payload)
	if len(payload) > n {
		c.readBuf = payload
		c.readOffset = n
	} else {
		pool.PutBuffer(payload)
	}
	return n, nil
}

func (c *TCPConn) readChunk() ([]byte, error) {
	payloadLength := pool.GetBuffer(2 + c.cipherConf.TagLen)
	defer pool.PutBuffer(payloadLength)
	if n, err := io.ReadFull(c.Conn, payloadLength); err != nil {
		if n > 0 {
			c.readErr = err
		}
		return nil, err
	}
	_, err := c.cipherRead.Open(payloadLength[:0], c.nonceRead, payloadLength, nil)
	if err != nil {
		c.readErr = responseFailure(protocol.ErrFailAuth, netproxy.ScopeStream)
		return nil, c.readErr
	}
	common.BytesIncLittleEndian(c.nonceRead)
	l := binary.BigEndian.Uint16(payloadLength)
	payload := pool.GetBuffer(int(l) + c.cipherConf.TagLen)
	if _, err = io.ReadFull(c.Conn, payload); err != nil {
		pool.PutBuffer(payload)
		c.readErr = err
		return nil, err
	}
	plaintext, err := c.cipherRead.Open(payload[:0], c.nonceRead, payload, nil)
	if err != nil {
		pool.PutBuffer(payload)
		c.readErr = responseFailure(protocol.ErrFailAuth, netproxy.ScopeStream)
		return nil, c.readErr
	}
	common.BytesIncLittleEndian(c.nonceRead)
	return plaintext, nil
}

func (c *TCPConn) Close() error {
	err := c.Conn.Close()
	c.readMutex.Lock()
	c.readErr = net.ErrClosed
	if c.readBuf != nil {
		pool.PutBuffer(c.readBuf)
		c.readBuf = nil
		c.readOffset = 0
	}
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
