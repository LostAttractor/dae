package shadowsocks

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type UdpConn struct {
	net.Conn

	cipherConf *ciphers.CipherConf
	masterKey  []byte
	sg         SaltGenerator
}

func NewUdpConn(conn net.Conn, conf *ciphers.CipherConf, masterKey []byte, sg SaltGenerator) *UdpConn {
	return &UdpConn{
		Conn:       conn,
		cipherConf: conf,
		masterKey:  masterKey,
		sg:         sg,
	}
}

func (c *UdpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("nil packet destination")
	}
	buf := pool.GetBytesBuffer()
	payload := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	defer pool.PutBytesBuffer(payload)

	// Combine address and data
	err := socks5.WriteNetAddr(addr, payload)
	if err != nil {
		return 0, err
	}
	payload.Write(b)

	// Encrypt and send
	salt := c.sg.Get()
	defer pool.PutBuffer(salt)
	buf.Write(salt)
	cipher, err := CreateCipher(c.masterKey, salt, c.cipherConf)
	if err != nil {
		return 0, err
	}
	buf.Grow(payload.Len() + cipher.Overhead())
	buf.Write(cipher.Seal(buf.AvailableBuffer(), ciphers.ZeroNonce[:c.cipherConf.NonceLen], payload.Bytes(), nil))

	written, err := c.Conn.Write(buf.Bytes())
	if written == buf.Len() {
		return len(b), err
	}
	if err == nil {
		err = io.ErrShortWrite
	}
	return 0, err
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < c.cipherConf.SaltLen {
		return 0, nil, fmt.Errorf("short length to decrypt")
	}
	salt := buf[:c.cipherConf.SaltLen]

	payload := buf[c.cipherConf.SaltLen:n]
	ciph, err := CreateCipher(c.masterKey, salt, c.cipherConf)
	if err != nil {
		return 0, nil, err
	}
	payload, err = ciph.Open(payload[:0], ciphers.ZeroNonce[:c.cipherConf.NonceLen], payload, nil)
	if err != nil {
		return 0, nil, err
	}

	reader := bytes.NewReader(payload)

	// Parse address from decrypted data
	addr, err = socks5.ReadAddr(reader)
	if err != nil {
		return 0, nil, err
	}

	return copy(b, payload[len(payload)-reader.Len():]), addr, nil
}
