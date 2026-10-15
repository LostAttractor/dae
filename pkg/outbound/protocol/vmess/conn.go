package vmess

import (
	"bufio"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

const MaxChunkSize = 1 << 14

// Conn owns one VMess request stream. Shared transports remain owned by their dialer.
type Conn struct {
	net.Conn
	readMu, writeMu         sync.Mutex
	reader                  *bufio.Reader
	writeCipher, readCipher cipher.AEAD
	writeSize, readSize     *ShakeSizeParser
	writeIV, readIV         [16]byte
	responseKey             [16]byte
	responseAuth            byte
	responseLength          int
	responseReady           bool
	writeCount, readCount   uint32
	wantChunk, padding      int
	pending                 []byte
	readErr, writeErr       error
}

func newConn(parent net.Conn, request request, key []byte) (*Conn, error) {
	instruction := ReqInstructionDataFromPool(request)
	defer pool.PutBuffer(instruction)
	c := &Conn{Conn: parent, reader: bufio.NewReaderSize(parent, MaxChunkSize), responseAuth: instruction[33]}
	copy(c.writeIV[:], instruction[1:17])
	readIV := sha256.Sum256(c.writeIV[:])
	copy(c.readIV[:], readIV[:16])
	readKey := sha256.Sum256(instruction[17:33])
	copy(c.responseKey[:], readKey[:16])
	newCipher, ok := NewCipherMapper[request.cipher]
	if !ok {
		return nil, fmt.Errorf("unsupported VMess cipher: %s", request.cipher)
	}
	var err error
	c.writeCipher, err = newCipher(instruction[17:33])
	if err != nil {
		return nil, err
	}
	c.readCipher, err = newCipher(c.responseKey[:])
	if err != nil {
		return nil, err
	}
	c.writeSize = NewShakeSizeParser(c.writeIV[:])
	c.readSize = NewShakeSizeParser(c.readIV[:])
	header, err := EncryptReqHeaderFromPool(instruction, key)
	if err != nil {
		return nil, err
	}
	defer pool.PutBuffer(header)
	n, err := parent.Write(header)
	if err == nil && n != len(header) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}
func (c *Conn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }

func chunkNonce(iv [16]byte, count uint32, size int) []byte {
	binary.BigEndian.PutUint16(iv[:2], uint16(count))
	return iv[:size]
}
func protocolError(message string) error {
	return netproxy.WrapFailure(fmt.Errorf("vmess: %s", message), netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol, Phase: netproxy.OpRead})
}

func (c *Conn) writeChunk(p []byte) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.writeCount > 65535 {
		c.writeErr = netproxy.WrapFailure(fmt.Errorf("VMess request nonce exhausted"), netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Origin: netproxy.OriginLocalProtocol, Reason: netproxy.ReasonProtocol, Phase: netproxy.OpWrite})
		return c.writeErr
	}
	padding := int(c.writeSize.NextPaddingLen())
	size := len(p) + c.writeCipher.Overhead() + padding
	data := pool.GetBuffer(2 + size)
	defer pool.PutBuffer(data)
	c.writeSize.Encode(uint16(size), data)
	c.writeCipher.Seal(data[2:2], chunkNonce(c.writeIV, c.writeCount, c.writeCipher.NonceSize()), p, nil)
	c.writeCount++
	fastrand.Read(data[len(data)-padding:])
	n, err := c.Conn.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.writeErr = err
	}
	return err
}
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	written := 0
	size := MaxChunkSize - 2 - c.writeCipher.Overhead() - int(c.writeSize.MaxPaddingLen())
	for written < len(p) {
		n := min(size, len(p)-written)
		if err := c.writeChunk(p[written : written+n]); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}
func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	if err := c.writeChunk(nil); err != nil {
		return err
	}
	c.writeErr = net.ErrClosed
	// The authenticated empty frame terminates this direction without closing
	// the parent carrier or requiring a transport-specific half-close.
	return nil
}

func (c *Conn) readResponse() error {
	if c.responseReady {
		return nil
	}
	if c.responseLength == 0 {
		data, err := c.reader.Peek(18)
		if err != nil {
			return err
		}
		aead, err := NewAesGcm(KDF(c.responseKey[:], []byte(KDFSaltConstAEADRespHeaderLenKey))[:16])
		if err != nil {
			return err
		}
		var size [2]byte
		plain, err := aead.Open(size[:0], KDF(c.readIV[:], []byte(KDFSaltConstAEADRespHeaderLenIV))[:12], data, nil)
		if err != nil {
			c.readErr = protocolError("invalid response length authentication")
			return c.readErr
		}
		c.responseLength = int(binary.BigEndian.Uint16(plain))
		if c.responseLength < 4 || c.responseLength > 1024 {
			c.readErr = protocolError("invalid response header length")
			return c.readErr
		}
		_, _ = c.reader.Discard(18)
	}
	data, err := c.reader.Peek(c.responseLength + 16)
	if err != nil {
		return err
	}
	aead, err := NewAesGcm(KDF(c.responseKey[:], []byte(KDFSaltConstAEADRespHeaderPayloadKey))[:16])
	if err != nil {
		return err
	}
	plain, err := aead.Open(data[:0], KDF(c.readIV[:], []byte(KDFSaltConstAEADRespHeaderPayloadIV))[:12], data, nil)
	if err != nil {
		c.readErr = protocolError("invalid response authentication")
		return c.readErr
	}
	if plain[0] != c.responseAuth || plain[2] != 0 {
		c.readErr = protocolError("invalid response auth or unsupported command")
		return c.readErr
	}
	_, _ = c.reader.Discard(c.responseLength + 16)
	c.responseReady = true
	return nil
}
func (c *Conn) readChunk() ([]byte, error) {
	if c.readErr != nil {
		return nil, c.readErr
	}
	if err := c.readResponse(); err != nil {
		return nil, err
	}
	if c.wantChunk == 0 {
		data, err := c.reader.Peek(2)
		if err != nil {
			return nil, err
		}
		c.padding = int(c.readSize.NextPaddingLen())
		size, _ := c.readSize.Decode(data)
		c.wantChunk = int(size)
		if c.wantChunk < c.padding+c.readCipher.Overhead() || c.wantChunk > MaxChunkSize-2 {
			c.readErr = protocolError("invalid chunk length")
			return nil, c.readErr
		}
		_, _ = c.reader.Discard(2)
	}
	data, err := c.reader.Peek(c.wantChunk)
	if err != nil {
		return nil, err
	}
	if c.readCount > 65535 {
		c.readErr = protocolError("response nonce exhausted")
		return nil, c.readErr
	}
	plain, err := c.readCipher.Open(data[:0], chunkNonce(c.readIV, c.readCount, c.readCipher.NonceSize()), data[:c.wantChunk-c.padding], nil)
	if err != nil {
		c.readErr = protocolError("invalid chunk authentication")
		return nil, c.readErr
	}
	c.readCount++
	_, _ = c.reader.Discard(c.wantChunk)
	c.wantChunk = 0
	if len(plain) == 0 {
		c.readErr = io.EOF
		return nil, io.EOF
	}
	return plain, nil
}
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var err error
		c.pending, err = c.readChunk()
		if err != nil {
			return 0, err
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
