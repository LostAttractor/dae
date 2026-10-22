// Thanks to Dreamacro/clash.

package mux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type SessionStatus = byte

const (
	SessionStatusNew       SessionStatus = 0x01
	SessionStatusKeep      SessionStatus = 0x02
	SessionStatusEnd       SessionStatus = 0x03
	SessionStatusKeepAlive SessionStatus = 0x04
)

const (
	OptionNone  = byte(0x00)
	OptionData  = byte(0x01)
	OptionError = byte(0x02)
)

type MuxOption struct {
	ID   [2]byte
	Port uint16
	Host string
	Type string
}

// Conn is an mux-compatible client for v2ray-plugin, not a complete implementation
type Conn struct {
	net.Conn
	buf     bytes.Buffer
	id      [2]byte
	length  [2]byte
	status  [2]byte
	otb     []byte
	remain  int
	readErr error
}

func (m *Conn) Read(b []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	for m.remain == 0 {
		_, err := io.ReadFull(m.Conn, m.length[:])
		if err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint16(m.length[:])
		if length < 4 || length > 512 {
			return 0, errors.New("invalid metalen")
		}

		_, err = io.ReadFull(m.Conn, m.id[:])
		if err != nil {
			return 0, err
		}

		_, err = io.ReadFull(m.Conn, m.status[:])
		if err != nil {
			return 0, err
		}

		// Skip metadata extensions; frames usually have none.
		if length > 4 {
			if _, err := io.CopyN(io.Discard, m.Conn, int64(length)-4); err != nil {
				return 0, err
			}
		}
		opcode, opts := m.status[0], m.status[1]
		if opcode == SessionStatusEnd {
			m.readErr = io.EOF
			if opts&OptionError != 0 {
				m.readErr = errors.New("mux: remote session failed")
			}
			return 0, m.readErr
		}
		// Any frame with the data option carries a length-prefixed payload,
		// which must be consumed to keep the stream framed.
		if opts&OptionData == 0 {
			continue
		}
		_, err = io.ReadFull(m.Conn, m.length[:])
		if err != nil {
			return 0, err
		}
		dataLen := int64(binary.BigEndian.Uint16(m.length[:]))
		if opcode != SessionStatusKeep {
			if _, err := io.CopyN(io.Discard, m.Conn, dataLen); err != nil {
				return 0, err
			}
			continue
		}
		m.remain = int(dataLen)
	}
	n, err := m.Conn.Read(b[:min(len(b), m.remain)])
	m.remain -= n
	return n, err
}

func (m *Conn) Write(b []byte) (int, error) {
	if m.otb != nil {
		// create a sub connection
		n, err := m.Conn.Write(m.otb)
		if err == nil && n != len(m.otb) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return 0, err
		}
		m.otb = nil
	}
	m.buf.Reset()
	binary.Write(&m.buf, binary.BigEndian, uint16(4))
	m.buf.Write(m.id[:])
	m.buf.WriteByte(SessionStatusKeep)
	m.buf.WriteByte(OptionData)
	binary.Write(&m.buf, binary.BigEndian, uint16(len(b)))
	m.buf.Write(b)

	n, err := m.Conn.Write(m.buf.Bytes())
	if n != m.buf.Len() {
		if err == nil {
			err = io.ErrShortWrite
		}
		return 0, err
	}
	return len(b), err
}

func (m *Conn) Close() error {
	// Each mux connection owns its underlay, so Close must interrupt its I/O.
	return m.Conn.Close()
}

func NewConn(conn net.Conn, option MuxOption) *Conn {
	buf := &bytes.Buffer{}

	// fill empty length
	buf.Write([]byte{0x0, 0x0})
	buf.Write(option.ID[:])
	buf.WriteByte(SessionStatusNew)
	buf.WriteByte(OptionNone)

	// tcp
	netType := byte(0x1)
	if option.Type == "udp" {
		netType = byte(0x2)
	}
	buf.WriteByte(netType)

	// port
	binary.Write(buf, binary.BigEndian, option.Port)

	// address
	ip := net.ParseIP(option.Host)
	if ip == nil {
		buf.WriteByte(0x2)
		buf.WriteString(option.Host)
	} else if ipv4 := ip.To4(); ipv4 != nil {
		buf.WriteByte(0x1)
		buf.Write(ipv4)
	} else {
		buf.WriteByte(0x3)
		buf.Write(ip.To16())
	}

	metadata := buf.Bytes()
	binary.BigEndian.PutUint16(metadata[:2], uint16(len(metadata)-2))

	return &Conn{
		Conn: conn,
		id:   option.ID,
		otb:  metadata,
	}
}
