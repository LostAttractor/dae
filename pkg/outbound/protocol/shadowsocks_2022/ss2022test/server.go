// Package ss2022test is a minimal Shadowsocks 2022 TCP server for tests:
// 2022-blake3-aes-128-gcm with one PSK, written from the specification
// rather than from the client. It checks neither timestamps nor replays.
package ss2022test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

const (
	Method   = "2022-blake3-aes-128-gcm"
	KeySize  = 16
	tagSize  = 16
	maxChunk = 0xffff
)

var errProtocol = errors.New("ss2022test: invalid request")

// Conn is the server end of one Shadowsocks 2022 TCP connection.
type Conn struct {
	net.Conn
	psk, requestSalt []byte

	readMu    sync.Mutex
	read      cipher.AEAD
	readNonce [12]byte
	plain     []byte // opened, not yet returned

	writeMu    sync.Mutex
	write      cipher.AEAD
	writeNonce [12]byte
}

// Accept reads conn's request header and returns the connection with the
// target address the client asked for.
func Accept(conn net.Conn, psk []byte) (*Conn, string, error) {
	c := &Conn{Conn: conn, psk: psk, requestSalt: make([]byte, KeySize)}
	if _, err := io.ReadFull(conn, c.requestSalt); err != nil {
		return nil, "", err
	}
	var err error
	if c.read, err = sessionCipher(psk, c.requestSalt); err != nil {
		return nil, "", err
	}
	fixed, err := c.open(11)
	if err != nil {
		return nil, "", err
	}
	if fixed[0] != 0 {
		return nil, "", errProtocol
	}
	variable, err := c.open(int(binary.BigEndian.Uint16(fixed[9:])))
	if err != nil {
		return nil, "", err
	}
	target, n, err := parseAddress(variable)
	if err != nil || len(variable) < n+2 {
		return nil, "", errProtocol
	}
	padding := int(binary.BigEndian.Uint16(variable[n:]))
	if len(variable) < n+2+padding {
		return nil, "", errProtocol
	}
	c.plain = variable[n+2+padding:]
	return c, target, nil
}

// parseAddress reads a SOCKS address: IPv4, domain or IPv6, then the port.
func parseAddress(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, errProtocol
	}
	var host string
	n := 1
	switch b[0] {
	case 1:
		n += 4
		if len(b) >= n {
			host = net.IP(b[1:n]).String()
		}
	case 3:
		if len(b) < 2 {
			return "", 0, errProtocol
		}
		n += 1 + int(b[1])
		if len(b) >= n {
			host = string(b[2:n])
		}
	case 4:
		n += 16
		if len(b) >= n {
			host = net.IP(b[1:n]).String()
		}
	default:
		return "", 0, errProtocol
	}
	if len(b) < n+2 {
		return "", 0, errProtocol
	}
	port := binary.BigEndian.Uint16(b[n:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), n + 2, nil
}

func sessionCipher(psk, salt []byte) (cipher.AEAD, error) {
	key := make([]byte, KeySize)
	blake3.DeriveKey(key, "shadowsocks 2022 session subkey", append(append([]byte(nil), psk...), salt...))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func increment(nonce *[12]byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// open reads and authenticates one sealed field of n plaintext bytes.
func (c *Conn) open(n int) ([]byte, error) {
	buf := make([]byte, n+tagSize)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return nil, err
	}
	plain, err := c.read.Open(buf[:0], c.readNonce[:], buf, nil)
	if err != nil {
		return nil, fmt.Errorf("ss2022test: %w", err)
	}
	increment(&c.readNonce)
	return plain, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.plain) == 0 {
		length, err := c.open(2)
		if err != nil {
			return 0, err
		}
		if c.plain, err = c.open(int(binary.BigEndian.Uint16(length))); err != nil {
			return 0, err
		}
	}
	n := copy(b, c.plain)
	c.plain = c.plain[n:]
	return n, nil
}

func (c *Conn) seal(dst, plain []byte) []byte {
	dst = c.write.Seal(dst, c.writeNonce[:], plain, nil)
	increment(&c.writeNonce)
	return dst
}

// Write sends b in chunks; the first carries the response header, which
// announces the length of the first chunk.
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var out []byte
	rest := b
	if c.write == nil {
		salt := make([]byte, KeySize)
		rand.Read(salt)
		var err error
		if c.write, err = sessionCipher(c.psk, salt); err != nil {
			return 0, err
		}
		first := rest[:min(len(rest), maxChunk)]
		header := []byte{1}
		header = binary.BigEndian.AppendUint64(header, uint64(time.Now().Unix()))
		header = append(header, c.requestSalt...)
		header = binary.BigEndian.AppendUint16(header, uint16(len(first)))
		out = c.seal(append(out, salt...), header)
		out = c.seal(out, first)
		rest = rest[len(first):]
	}
	for len(rest) > 0 {
		chunk := rest[:min(len(rest), maxChunk)]
		out = c.seal(out, binary.BigEndian.AppendUint16(nil, uint16(len(chunk))))
		out = c.seal(out, chunk)
		rest = rest[len(chunk):]
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}
