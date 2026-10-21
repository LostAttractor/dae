package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
	"lukechampine.com/blake3"
)

type UdpConn struct {
	net.Conn
	sessionID                              [8]byte
	packetID                               uint64
	exhausted                              bool
	cipherConf                             *ciphers.CipherConf2022
	blockCipherEncrypt, blockCipherDecrypt cipher.Block
	pskList                                [][]byte
	uPSK                                   []byte
	cipherWrite                            cipher.AEAD
	writeMutex, readMutex                  sync.Mutex
	serverSessions                         [2]serverSession
}

// Two server sessions permit server restarts without unbounded history. Each
// session is retained for at least 60 seconds after its last valid packet.
type serverSession struct {
	id          [8]byte
	cipher      cipher.AEAD
	lastSeen    time.Time
	latest      uint64
	seen        [16]uint64 // 1024 packet IDs, indexed circularly.
	initialized bool
}

func (s *serverSession) accept(packetID uint64) bool {
	if s.initialized && packetID <= s.latest && s.latest-packetID >= 1024 {
		return false
	}
	if !s.initialized || packetID > s.latest {
		if !s.initialized || packetID-s.latest >= 1024 {
			clear(s.seen[:])
		} else {
			for step := uint64(1); step <= packetID-s.latest; step++ {
				index := (s.latest + step) % 1024
				s.seen[index/64] &^= uint64(1) << (index % 64)
			}
		}
		s.latest = packetID
		s.initialized = true
	}
	index := packetID % 1024
	mask := uint64(1) << (index % 64)
	if s.seen[index/64]&mask != 0 {
		return false
	}
	s.seen[index/64] |= mask
	return true
}

func NewUdpConn(conn net.Conn, conf *ciphers.CipherConf2022, encrypt, decrypt cipher.Block, pskList [][]byte, uPSK []byte) *UdpConn {
	c := &UdpConn{Conn: conn, cipherConf: conf, blockCipherEncrypt: encrypt, blockCipherDecrypt: decrypt, pskList: pskList, uPSK: uPSK}
	fastrand.Read(c.sessionID[:])
	return c
}

func (c *UdpConn) writeIdentityHeader(buf *bytes.Buffer, separate []byte) error {
	var header [aes.BlockSize]byte
	for i := 0; i < len(c.pskList)-1; i++ {
		hash := blake3.Sum512(c.pskList[i+1])
		subtle.XORBytes(header[:], hash[:aes.BlockSize], separate)
		block, err := c.cipherConf.NewBlockCipher(c.pskList[i])
		if err != nil {
			return err
		}
		block.Encrypt(header[:], header[:])
		buf.Write(header[:])
	}
	return nil
}

func (c *UdpConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("nil packet destination")
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.exhausted {
		return 0, fmt.Errorf("Shadowsocks 2022 packet ID exhausted")
	}
	message := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(message)
	message.WriteByte(HeaderTypeClientStream)
	message.Write(binary.BigEndian.AppendUint64(nil, uint64(time.Now().Unix())))
	message.Write([]byte{0, 0}) // no UDP padding
	if err := socks5.WriteNetAddr(addr, message); err != nil {
		return 0, err
	}
	message.Write(payload)
	if 16*len(c.pskList)+message.Len()+c.cipherConf.TagLen > 65507 {
		return 0, netproxy.WrapFailure(io.ErrShortBuffer, netproxy.Failure{Scope: netproxy.ScopeOperation, Origin: netproxy.OriginCaller, Reason: netproxy.ReasonCapacity})
	}
	var separate [16]byte
	copy(separate[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(separate[8:], c.packetID)
	// Even a failed send consumes its packet ID: AEAD nonces are never reused.
	if c.packetID == math.MaxUint64 {
		c.exhausted = true
	} else {
		c.packetID++
	}
	var encrypted [16]byte
	c.blockCipherEncrypt.Encrypt(encrypted[:], separate[:])
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	buf.Write(encrypted[:])
	if err := c.writeIdentityHeader(buf, separate[:]); err != nil {
		return 0, err
	}
	if c.cipherWrite == nil {
		// The session ID is fixed; only the packet ID in the nonce changes.
		aead, err := CreateCipher(c.uPSK, c.sessionID[:], c.cipherConf)
		if err != nil {
			return 0, err
		}
		c.cipherWrite = aead
	}
	buf.Grow(message.Len() + c.cipherWrite.Overhead())
	buf.Write(c.cipherWrite.Seal(buf.AvailableBuffer(), separate[4:], message.Bytes(), nil))
	n, err := c.Conn.Write(buf.Bytes())
	if n == buf.Len() {
		return len(payload), err
	}
	if err == nil {
		err = io.ErrShortWrite
	}
	return 0, err
}

func (c *UdpConn) acceptServerPacket(id [8]byte, packetID uint64, now time.Time, aead cipher.AEAD) bool {
	selected := -1
	for i := range c.serverSessions {
		s := &c.serverSessions[i]
		if !s.lastSeen.IsZero() && s.id == id {
			selected = i
			break
		}
	}
	if selected < 0 {
		for i := range c.serverSessions {
			s := &c.serverSessions[i]
			if s.lastSeen.IsZero() || now.Sub(s.lastSeen) >= time.Minute {
				c.serverSessions[i] = serverSession{id: id}
				selected = i
				break
			}
		}
	}
	if selected < 0 {
		return false
	}
	s := &c.serverSessions[selected]
	if !s.accept(packetID) {
		return false
	}
	s.lastSeen = now
	s.cipher = aead
	return true
}

func (c *UdpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < 16+c.cipherConf.TagLen {
		return 0, nil, responseFailure(io.ErrUnexpectedEOF, netproxy.ScopeOperation)
	}
	c.blockCipherDecrypt.Decrypt(buf[:16], buf[:16])
	var serverID [8]byte
	copy(serverID[:], buf[:8])
	var aead cipher.AEAD
	for i := range c.serverSessions {
		s := &c.serverSessions[i]
		if s.id == serverID && s.cipher != nil {
			aead = s.cipher
			break
		}
	}
	if aead == nil {
		aead, err = CreateCipher(c.uPSK, serverID[:], c.cipherConf)
		if err != nil {
			return 0, nil, err
		}
	}
	payload, err := aead.Open(buf[16:16], buf[4:16], buf[16:n], nil)
	if err != nil {
		return 0, nil, responseFailure(protocol.ErrFailAuth, netproxy.ScopeOperation)
	}
	// Type, time, and the originating client session must all authenticate
	// before a packet can move the replay window.
	if len(payload) < 19 {
		return 0, nil, responseFailure(io.ErrUnexpectedEOF, netproxy.ScopeOperation)
	}
	if payload[0] != HeaderTypeServerStream {
		return 0, nil, responseFailure(fmt.Errorf("unexpected response packet type: %d", payload[0]), netproxy.ScopeOperation)
	}
	now := time.Now()
	if !validTimestamp(binary.BigEndian.Uint64(payload[1:9]), now) || subtle.ConstantTimeCompare(payload[9:17], c.sessionID[:]) != 1 {
		return 0, nil, responseFailure(protocol.ErrReplayAttack, netproxy.ScopeOperation)
	}
	padding := int(binary.BigEndian.Uint16(payload[17:19]))
	if padding > len(payload)-19 {
		return 0, nil, responseFailure(io.ErrUnexpectedEOF, netproxy.ScopeOperation)
	}
	reader := bytes.NewReader(payload[19+padding:])
	addr, err := socks5.ReadAddr(reader)
	if err != nil {
		return 0, nil, responseFailure(err, netproxy.ScopeOperation)
	}
	// Publish the cipher with the replay state only after all checks succeed.
	if !c.acceptServerPacket(serverID, binary.BigEndian.Uint64(buf[8:16]), now, aead) {
		return 0, nil, responseFailure(protocol.ErrReplayAttack, netproxy.ScopeOperation)
	}
	n = copy(b, payload[len(payload)-reader.Len():])
	if n < reader.Len() {
		return n, addr, io.ErrShortBuffer
	}
	return n, addr, nil
}
