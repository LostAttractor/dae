package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/internal/aeadframe"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"lukechampine.com/blake3"
)

const (
	TCPChunkMaxLen         = (1 << 16) - 1
	HeaderTypeClientStream = 0
	HeaderTypeServerStream = 1
	MaxPaddingLength       = 900
)

type TCPConn struct {
	net.Conn
	addr                  *socks5.AddressInfo
	cipherConf            *ciphers.CipherConf2022
	pskList               [][]byte
	uPSK                  []byte
	requestSalt           []byte // Immutable after construction; shared by reader and writer.
	cipherWrite           cipher.AEAD
	onceRead, onceWrite   bool
	nonceWrite            []byte
	writeErr              error
	readMutex, writeMutex sync.Mutex
	reader                aeadframe.Reader
	closeOnce             sync.Once
	closeErr              error
}

func NewTCPConn(conn net.Conn, conf *ciphers.CipherConf2022, pskList [][]byte, uPSK []byte, sg shadowsocks.SaltGenerator, addr *socks5.AddressInfo) net.Conn {
	salt := sg.Get()
	c := &TCPConn{Conn: conn, addr: addr, cipherConf: conf, pskList: pskList, uPSK: uPSK, requestSalt: append([]byte(nil), salt...), nonceWrite: make([]byte, conf.NonceLen), reader: aeadframe.Reader{Conn: conn}}
	pool.PutBuffer(salt)
	return c
}

func (c *TCPConn) Read(b []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if !c.onceRead && len(b) > 0 {
		if err := c.readResponseHeader(); err != nil {
			return 0, err
		}
	}
	return c.reader.Read(b)
}

// readResponseHeader authenticates the salt and fixed response header, which
// announces the first payload chunk's length.
func (c *TCPConn) readResponseHeader() error {
	saltLen := c.cipherConf.SaltLen
	size := saltLen + 11 + saltLen + c.cipherConf.TagLen
	header, err := c.reader.Peek(size)
	if err != nil {
		return err
	}
	aead, err := CreateCipher(c.uPSK, header[:saltLen], c.cipherConf)
	if err != nil {
		return c.reader.Fail(err)
	}
	nonce := make([]byte, c.cipherConf.NonceLen)
	ciphertext := header[saltLen:]
	response, err := aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return c.reader.Fail(responseFailure(protocol.ErrFailAuth, netproxy.ScopeStream))
	}
	if response[0] != HeaderTypeServerStream {
		return c.reader.Fail(responseFailure(fmt.Errorf("unexpected response header type: %d", response[0]), netproxy.ScopeStream))
	}
	if !validTimestamp(binary.BigEndian.Uint64(response[1:9]), time.Now()) {
		return c.reader.Fail(responseFailure(protocol.ErrReplayAttack, netproxy.ScopeStream))
	}
	if subtle.ConstantTimeCompare(response[9:9+saltLen], c.requestSalt) != 1 {
		return c.reader.Fail(responseFailure(protocol.ErrReplayAttack, netproxy.ScopeStream))
	}
	common.BytesIncLittleEndian(nonce)
	c.reader.Discard(size)
	c.reader.Start(aead, nonce, int(binary.BigEndian.Uint16(response[9+saltLen:])))
	c.onceRead = true
	return nil
}

func validTimestamp(seconds uint64, now time.Time) bool {
	current := now.Unix()
	tolerance := int64(ciphers.TimestampTolerance / time.Second)
	return seconds <= uint64(current+tolerance) && seconds >= uint64(current-tolerance)
}

func (c *TCPConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close() // Interrupt Read before acquiring its mutex.
		c.readMutex.Lock()
		c.reader.Close()
		c.readMutex.Unlock()
	})
	return c.closeErr
}

func (c *TCPConn) writeIdentityHeader(buf *bytes.Buffer) error {
	var header [aes.BlockSize]byte
	for i := 0; i < len(c.pskList)-1; i++ {
		key := GenerateSubKey(c.pskList[i], c.requestSalt, Shadowsocks2022IdentityHeaderInfo)
		block, err := c.cipherConf.NewBlockCipher(key)
		pool.PutBuffer(key)
		if err != nil {
			return err
		}
		hash := blake3.Sum512(c.pskList[i+1])
		block.Encrypt(header[:], hash[:aes.BlockSize])
		buf.Write(header[:])
	}
	return nil
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
	inputLength := len(b)
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if !c.onceWrite {
		// Any initialization failure is terminal; retrying with the same salt
		// after encrypting a header must never restart its nonce sequence.
		defer func() {
			if err != nil && !c.onceWrite {
				c.writeErr = err
			}
		}()
		variable := pool.GetBytesBuffer()
		defer pool.PutBytesBuffer(variable)
		if err = socks5.WriteAddrInfo(c.addr, variable); err != nil {
			return 0, err
		}
		paddingLength := 0
		if len(b) == 0 {
			paddingLength = 1 + mathrand.IntN(MaxPaddingLength)
		}
		variable.Write(binary.BigEndian.AppendUint16(nil, uint16(paddingLength)))
		if paddingLength > 0 {
			padding := pool.GetBuffer(paddingLength)
			rand.Read(padding)
			variable.Write(padding)
			pool.PutBuffer(padding)
		}
		initialLength := min(len(b), TCPChunkMaxLen-variable.Len())
		variable.Write(b[:initialLength])
		b = b[initialLength:]
		var fixed [11]byte
		fixed[0] = HeaderTypeClientStream
		binary.BigEndian.PutUint64(fixed[1:], uint64(time.Now().Unix()))
		binary.BigEndian.PutUint16(fixed[9:], uint16(variable.Len()))
		buf.Write(c.requestSalt)
		if err = c.writeIdentityHeader(buf); err != nil {
			return 0, err
		}
		c.cipherWrite, err = CreateCipher(c.uPSK, c.requestSalt, c.cipherConf)
		if err != nil {
			return 0, err
		}
		buf.Grow(len(fixed) + variable.Len() + 2*c.cipherConf.TagLen)
		buf.Write(c.cipherWrite.Seal(buf.AvailableBuffer(), c.nonceWrite, fixed[:], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(buf.AvailableBuffer(), c.nonceWrite, variable.Bytes(), nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		c.onceWrite = true
	}
	c.seal(buf, b)
	written, err := c.Conn.Write(buf.Bytes())
	if written == buf.Len() {
		return inputLength, err
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
	var length [2]byte
	for len(payload) > 0 {
		n := min(len(payload), TCPChunkMaxLen)
		binary.BigEndian.PutUint16(length[:], uint16(n))
		buf.Write(c.cipherWrite.Seal(buf.AvailableBuffer(), c.nonceWrite, length[:], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(buf.AvailableBuffer(), c.nonceWrite, payload[:n], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		payload = payload[n:]
	}
}
