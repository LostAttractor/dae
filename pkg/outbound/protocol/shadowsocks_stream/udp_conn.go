package shadowsocks_stream

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

// UdpConn encrypts one datagram per Read/Write; its parent is connected to the proxy.
type UdpConn struct {
	net.Conn
	cipher *ciphers.StreamCipher
}

func NewUDPConn(conn net.Conn, cipher *ciphers.StreamCipher) *UdpConn {
	return &UdpConn{Conn: conn, cipher: cipher}
}
func (c *UdpConn) Cipher() *ciphers.StreamCipher    { return c.cipher }
func (c *UdpConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
func (c *UdpConn) Write(p []byte) (int, error) {
	ivLen := c.cipher.InfoIVLen()
	if len(p)+ivLen > 65535 {
		return 0, fmt.Errorf("shadowsocks datagram too large: %d", len(p))
	}
	buf := pool.GetBuffer(ivLen + len(p))
	defer pool.PutBuffer(buf)
	enc, err := c.cipher.NewEncryptor(buf[:ivLen])
	if err != nil {
		return 0, err
	}
	enc.XORKeyStream(buf[ivLen:], p)
	n, err := c.Conn.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *UdpConn) Read(p []byte) (int, error) {
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	ivLen := c.cipher.InfoIVLen()
	if n < ivLen {
		return 0, fmt.Errorf("shadowsocks datagram has a truncated IV")
	}
	dec, err := c.cipher.NewDecryptor(buf[:ivLen])
	if err != nil {
		return 0, err
	}
	payload := buf[ivLen:n]
	dec.XORKeyStream(payload, payload)
	n = copy(p, payload)
	if n < len(payload) {
		return n, io.ErrShortBuffer
	}
	return n, nil
}

type packetConn struct{ *UdpConn }

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, socks5.ErrInvalidAddress
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if err := socks5.WriteNetAddr(addr, buf); err != nil {
		return 0, err
	}
	buf.Write(p)
	if _, err := c.UdpConn.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	n, err := c.UdpConn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	reader := bytes.NewReader(buf[:n])
	addr, err := socks5.ReadAddrInfo(reader)
	if err != nil {
		return 0, nil, err
	}
	host := addr.Hostname
	if addr.IP.IsValid() {
		host = addr.IP.String()
	}
	from := netproxy.NewAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(addr.Port))))
	size := reader.Len()
	n, _ = reader.Read(p)
	if n < size {
		return n, from, io.ErrShortBuffer
	}
	return n, from, nil
}
