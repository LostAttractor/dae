package vision

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type PacketConn struct {
	*Conn
	target                           net.Addr
	reader                           *bufio.Reader
	readPacketMu, writePacketMu      sync.Mutex
	sent                             bool
	stage, metadataSize, payloadSize int
	source                           net.Addr
	readPacketErr                    error
}

func NewPacketConn(conn *Conn, target net.Addr) *PacketConn {
	return &PacketConn{Conn: conn, target: target, reader: bufio.NewReaderSize(conn, 65535)}
}
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("missing XUDP destination")
	}
	if len(p) > 65535 {
		return 0, fmt.Errorf("XUDP datagram too large: %d", len(p))
	}
	target, err := socks5.AddressFromString(addr.String())
	if err != nil {
		return 0, err
	}
	if len(target.Hostname) > 255 {
		return 0, fmt.Errorf("XUDP hostname exceeds 255 bytes")
	}
	c.writePacketMu.Lock()
	defer c.writePacketMu.Unlock()
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	buf.Write([]byte{0, 0, 0, 0})
	command := byte(1)
	if c.sent {
		command = 2
	}
	buf.WriteByte(command)
	buf.WriteByte(1)
	buf.WriteByte(2)
	buf.WriteByte(byte(target.Port >> 8))
	buf.WriteByte(byte(target.Port))
	switch target.Type {
	case socks5.AddressTypeIPv4:
		buf.WriteByte(1)
		buf.Write(target.IP.AsSlice())
	case socks5.AddressTypeIPv6:
		buf.WriteByte(3)
		buf.Write(target.IP.AsSlice())
	case socks5.AddressTypeDomain:
		buf.WriteByte(2)
		buf.WriteByte(byte(len(target.Hostname)))
		buf.WriteString(target.Hostname)
	}
	binary.BigEndian.PutUint16(buf.Bytes(), uint16(buf.Len()-2))
	buf.WriteByte(byte(len(p) >> 8))
	buf.WriteByte(byte(len(p)))
	buf.Write(p)
	n, err := c.Conn.Write(buf.Bytes())
	if err == nil && n != buf.Len() {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	c.sent = true
	return len(p), nil
}
func readPacketAddress(p []byte) (net.Addr, error) {
	if len(p) < 4 || p[0] != 2 {
		return nil, visionError("invalid XUDP network/address")
	}
	port := binary.BigEndian.Uint16(p[1:3])
	typ := p[3]
	p = p[4:]
	host := ""
	switch typ {
	case 1, 3:
		size := 4
		if typ == 3 {
			size = 16
		}
		if len(p) < size {
			return nil, visionError("truncated XUDP IP")
		}
		ip, _ := netip.AddrFromSlice(p[:size])
		host = ip.String()
	case 2:
		if len(p) < 1 || len(p) < 1+int(p[0]) {
			return nil, visionError("truncated XUDP domain")
		}
		host = string(p[1 : 1+int(p[0])])
	default:
		return nil, visionError("invalid XUDP address type")
	}
	return netproxy.NewAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port)))), nil
}
func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readPacketMu.Lock()
	defer c.readPacketMu.Unlock()
	if c.readPacketErr != nil {
		return 0, nil, c.readPacketErr
	}
	for {
		if c.stage == 0 {
			header, err := c.reader.Peek(2)
			if err != nil {
				return 0, nil, err
			}
			c.metadataSize = int(binary.BigEndian.Uint16(header))
			if c.metadataSize < 4 || c.metadataSize > 512 {
				c.readPacketErr = visionError("invalid XUDP metadata length")
				return 0, nil, c.readPacketErr
			}
			_, _ = c.reader.Discard(2)
			c.stage = 1
		}
		if c.stage == 1 {
			metadata, err := c.reader.Peek(c.metadataSize)
			if err != nil {
				return 0, nil, err
			}
			command, option := metadata[2], metadata[3]
			c.source = c.target
			if command == 3 {
				c.readPacketErr = io.EOF
				return 0, nil, io.EOF
			}
			if command != 2 && command != 4 {
				c.readPacketErr = visionError("unexpected XUDP command")
				return 0, nil, c.readPacketErr
			}
			if command == 2 && len(metadata) > 4 {
				c.source, err = readPacketAddress(metadata[4:])
				if err != nil {
					c.readPacketErr = err
					return 0, nil, err
				}
			}
			_, _ = c.reader.Discard(c.metadataSize)
			if option&1 == 0 {
				c.stage = 0
				continue
			}
			c.stage = 2
			if command == 4 {
				c.source = nil
			}
		}
		if c.stage == 2 {
			header, err := c.reader.Peek(2)
			if err != nil {
				return 0, nil, err
			}
			c.payloadSize = int(binary.BigEndian.Uint16(header))
			_, _ = c.reader.Discard(2)
			c.stage = 3
		}
		payload, err := c.reader.Peek(c.payloadSize)
		if err != nil {
			return 0, nil, err
		}
		n := copy(p, payload)
		_, _ = c.reader.Discard(c.payloadSize)
		c.stage = 0
		if c.source == nil {
			continue
		}
		if n < c.payloadSize {
			return n, c.source, io.ErrShortBuffer
		}
		return n, c.source, nil
	}
}
