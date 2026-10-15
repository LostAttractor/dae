// Modified from https://github.com/Dreamacro/clash/blob/master/component/simple-obfs/tls.go
// Wire format: shadowsocks/simple-obfs, src/obfs_tls.c.
package simpleobfs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

const chunkSize = 16 << 10

type TLSObfs struct {
	net.Conn
	reader                      *bufio.Reader
	server                      string
	remaining                   int
	firstRequest, firstResponse bool
	rMu, wMu                    sync.Mutex
	readErr, writeErr           error
}

func (c *TLSObfs) Read(p []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	for c.remaining == 0 {
		size := 5
		if c.firstResponse {
			size = 107
		}
		header, err := c.reader.Peek(size)
		if err != nil {
			if !isTimeout(err) {
				if err == io.EOF && c.reader.Buffered() != 0 {
					err = io.ErrUnexpectedEOF
				}
				c.readErr = err
			}
			return 0, err
		}
		if c.firstResponse {
			if !bytes.Equal(header[:5], []byte{0x16, 3, 1, 0, 91}) || header[5] != 2 || !bytes.Equal(header[96:105], []byte{0x14, 3, 3, 0, 1, 1, 0x16, 3, 3}) {
				c.readErr = wireError("invalid TLS response preface")
				return 0, c.readErr
			}
		} else if !bytes.Equal(header[:3], []byte{0x17, 3, 3}) {
			c.readErr = wireError("invalid TLS data record")
			return 0, c.readErr
		}
		c.remaining = int(binary.BigEndian.Uint16(header[size-2:]))
		if !c.firstResponse && c.remaining > chunkSize {
			c.readErr = wireError("TLS record too large")
			return 0, c.readErr
		}
		c.reader.Discard(size)
		c.firstResponse = false
	}
	n, err := c.reader.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	if err != nil && !isTimeout(err) {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		c.readErr = err
	}
	return n, err
}

func (c *TLSObfs) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(c.server) > 255 {
		return 0, wireError("TLS server name too long")
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	written := 0
	for len(p) > 0 {
		n := min(len(p), chunkSize)
		buf.Reset()
		if c.firstRequest {
			makeClientHelloMsg(buf, p[:n], c.server)
		} else {
			buf.Write([]byte{0x17, 3, 3, byte(n >> 8), byte(n)})
			buf.Write(p[:n])
		}
		if err := writeWire(c.Conn, buf.Bytes()); err != nil {
			c.writeErr = err
			return written, err
		}
		c.firstRequest = false
		written += n
		p = p[n:]
	}
	return written, nil
}

func NewTLSObfs(conn net.Conn, server string) net.Conn {
	return &TLSObfs{Conn: conn, reader: bufio.NewReader(conn), server: server, firstRequest: true, firstResponse: true}
}

func makeClientHelloMsg(buf *bytes.Buffer, data []byte, server string) {
	random := make([]byte, 28)
	sessionID := make([]byte, 32)
	fastrand.Read(random)
	fastrand.Read(sessionID)

	// handshake, TLS 1.0 version, length
	buf.WriteByte(22)
	buf.Write([]byte{0x03, 0x01})
	length := uint16(212 + len(data) + len(server))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length & 0xff))

	// clientHello, length, TLS 1.2 version
	buf.WriteByte(1)
	buf.WriteByte(0)
	binary.Write(buf, binary.BigEndian, uint16(208+len(data)+len(server)))
	buf.Write([]byte{0x03, 0x03})

	// random with timestamp, sid len, sid
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	buf.Write(random)
	buf.WriteByte(32)
	buf.Write(sessionID)

	// cipher suites
	buf.Write([]byte{0x00, 0x38})
	buf.Write([]byte{
		0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
		0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
		0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
		0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
	})

	// compression
	buf.Write([]byte{0x01, 0x00})

	// extension length
	binary.Write(buf, binary.BigEndian, uint16(79+len(data)+len(server)))

	// session ticket
	buf.Write([]byte{0x00, 0x23})
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)

	// server name
	buf.Write([]byte{0x00, 0x00})
	binary.Write(buf, binary.BigEndian, uint16(len(server)+5))
	binary.Write(buf, binary.BigEndian, uint16(len(server)+3))
	buf.WriteByte(0)
	binary.Write(buf, binary.BigEndian, uint16(len(server)))
	buf.Write([]byte(server))

	// ec_point
	buf.Write([]byte{0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02})

	// groups
	buf.Write([]byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18})

	// signature
	buf.Write([]byte{
		0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
		0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
		0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
	})

	// encrypt then mac
	buf.Write([]byte{0x00, 0x16, 0x00, 0x00})

	// extended master secret
	buf.Write([]byte{0x00, 0x17, 0x00, 0x00})

}
