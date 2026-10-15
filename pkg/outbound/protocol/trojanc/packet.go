package trojanc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type PacketConn struct {
	net.Conn
	readMutex  sync.Mutex
	readBuf    *bytes.Buffer
	readErr    error
	writeMutex sync.Mutex
	writeErr   error
	closeOnce  sync.Once
	closeErr   error
}

// readTo retains partial fields across deadlines. The two-byte payload length
// bounds the retained frame; no read consumes bytes from the following packet.
func (c *PacketConn) readTo(size int) error {
	for c.readBuf.Len() < size {
		err := c.readErr
		if err == nil {
			remaining := size - c.readBuf.Len()
			c.readBuf.Grow(remaining)
			b := c.readBuf.AvailableBuffer()[:remaining]
			n, readErr := c.Conn.Read(b)
			c.readBuf.Write(b[:n])
			err = readErr
			if err != nil {
				// A timeout may be joined with an independently fatal carrier error.
				retryable := true
				for _, failure := range netproxy.Failures(err) {
					if failure.Reason != netproxy.ReasonDeadline || failure.Scope == netproxy.ScopeSharedResource {
						retryable = false
					}
				}
				if !retryable {
					c.readErr = err
				}
			}
			if c.readBuf.Len() >= size {
				return nil
			}
			if n == 0 && err == nil {
				return io.ErrNoProgress
			}
		}
		if err == io.EOF && c.readBuf.Len() > 0 {
			_, _, err = c.invalidFrame(io.ErrUnexpectedEOF)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *PacketConn) invalidFrame(err error) (int, net.Addr, error) {
	c.readErr = netproxy.WrapFailure(err, netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Origin: netproxy.OriginPeer, Phase: netproxy.OpRead, Reason: netproxy.ReasonProtocol})
	return 0, nil, c.readErr
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.readBuf == nil {
		if c.readErr != nil {
			return 0, nil, c.readErr
		}
		c.readBuf = pool.GetBytesBuffer()
	}
	if err := c.readTo(1); err != nil {
		return 0, nil, err
	}
	addressLen := 0
	switch c.readBuf.Bytes()[0] {
	case byte(socks5.AddressTypeIPv4):
		addressLen = 7
	case byte(socks5.AddressTypeIPv6):
		addressLen = 19
	case byte(socks5.AddressTypeDomain):
		if err := c.readTo(2); err != nil {
			return 0, nil, err
		}
		if c.readBuf.Bytes()[1] == 0 {
			return c.invalidFrame(socks5.ErrInvalidAddress)
		}
		addressLen = 4 + int(c.readBuf.Bytes()[1])
	default:
		return c.invalidFrame(socks5.ErrInvalidAddress)
	}
	if err := c.readTo(addressLen + 4); err != nil {
		return 0, nil, err
	}
	header := c.readBuf.Bytes()
	if header[addressLen+2] != '\r' || header[addressLen+3] != '\n' {
		return c.invalidFrame(fmt.Errorf("invalid trojan UDP delimiter"))
	}
	payloadLen := int(binary.BigEndian.Uint16(header[addressLen:]))
	if err := c.readTo(addressLen + 4 + payloadLen); err != nil {
		return 0, nil, err
	}
	frame := c.readBuf.Bytes()
	addr, err := socks5.ReadAddr(bytes.NewReader(frame[:addressLen]))
	if err != nil {
		return c.invalidFrame(err)
	}
	n := copy(b, frame[addressLen+4:])
	c.readBuf.Reset()
	if n < payloadLen {
		return n, addr, io.ErrShortBuffer
	}
	return n, addr, nil
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > 65535 {
		return 0, fmt.Errorf("trojan UDP payload exceeds 65535 bytes")
	}
	if addr == nil {
		return 0, socks5.ErrInvalidAddress
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if err := socks5.WriteAddr(addr.String(), buf); err != nil {
		return 0, err
	}
	buf.WriteByte(byte(len(b) >> 8))
	buf.WriteByte(byte(len(b)))
	buf.WriteString("\r\n")
	buf.Write(b)
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	n, err := c.Conn.Write(buf.Bytes())
	if n != buf.Len() {
		if err == nil {
			err = io.ErrShortWrite
		}
		c.writeErr = err
		return 0, err
	}
	return len(b), err
}

func (c *PacketConn) Close() error {
	c.closeOnce.Do(func() {
		// Close the carrier before taking the reader lock so blocked reads exit.
		c.closeErr = c.Conn.Close()
		c.readMutex.Lock()
		defer c.readMutex.Unlock()
		if c.readBuf != nil {
			pool.PutBytesBuffer(c.readBuf)
			c.readBuf = nil
		}
		c.readErr = net.ErrClosed
	})
	return c.closeErr
}
