package vision

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

const (
	commandPaddingContinue byte = iota
	commandPaddingEnd
	commandPaddingDirect
)
const maxContent = 32*1024 - 21

type Conn struct {
	net.Conn
	overlay                   net.Conn
	uuid                      [16]byte
	input                     *bytes.Reader
	rawInput                  *bytes.Buffer
	readMu, writeMu, filterMu sync.Mutex
	writeStarted, readStarted bool
	writePadding, readPadding bool
	writeDirect, readDirect   bool
	readHeader                [21]byte
	headerUsed                int
	content, padding          int
	command                   byte
	readErr, writeErr         error
	packetsToFilter           int
	isTLS, enableXTLS         bool
	remainingServerHello      uint16
	cipher                    uint16
}

func (c *Conn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.overlay) }
func visionError(message string) error {
	return netproxy.WrapFailure(fmt.Errorf("Vision: %s", message), netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol, Phase: netproxy.OpRead})
}
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	for {
		if c.readDirect {
			if c.input != nil && c.input.Len() > 0 {
				return c.input.Read(p)
			}
			if c.rawInput != nil && c.rawInput.Len() > 0 {
				return c.rawInput.Read(p)
			}
			return c.Conn.Read(p)
		}
		if !c.readPadding {
			return c.overlay.Read(p)
		}
		if c.content > 0 {
			n, err := c.overlay.Read(p[:min(len(p), c.content)])
			c.content -= n
			c.filterTLS(p[:n])
			return n, err
		}
		if c.padding > 0 {
			n, err := io.CopyN(io.Discard, c.overlay, int64(c.padding))
			c.padding -= int(n)
			if err != nil {
				return 0, err
			}
		}
		if c.command == commandPaddingEnd {
			c.readPadding = false
			continue
		}
		if c.command == commandPaddingDirect {
			c.readDirect = true
			continue
		}
		size := 5
		if !c.readStarted {
			size += 16
		}
		n, err := io.ReadFull(c.overlay, c.readHeader[c.headerUsed:size])
		c.headerUsed += n
		if err != nil {
			return 0, err
		}
		header := c.readHeader[:size]
		if !c.readStarted {
			if subtle.ConstantTimeCompare(c.uuid[:], header[:16]) != 1 {
				c.readErr = visionError("response UUID mismatch")
				return 0, c.readErr
			}
			header = header[16:]
			c.readStarted = true
		}
		c.command = header[0]
		if c.command > commandPaddingDirect {
			c.readErr = visionError("invalid padding command")
			return 0, c.readErr
		}
		c.content = int(binary.BigEndian.Uint16(header[1:3]))
		c.padding = int(binary.BigEndian.Uint16(header[3:5]))
		c.headerUsed = 0
	}
}
func (c *Conn) write(p []byte) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	writer := c.overlay
	if c.writeDirect {
		writer = c.Conn
	}
	n, err := writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.writeErr = err
	}
	return err
}
func (c *Conn) writeRecord(p []byte, command byte, isTLS bool) error {
	padding := fastrand.Intn(256)
	if len(p) < 900 && isTLS {
		padding = fastrand.Intn(500) + 900 - len(p)
	}
	prefix := 5
	if !c.writeStarted {
		prefix += 16
	}
	data := pool.GetBuffer(prefix + len(p) + padding)
	defer pool.PutBuffer(data)
	offset := 0
	if !c.writeStarted {
		copy(data, c.uuid[:])
		offset = 16
	}
	data[offset] = command
	binary.BigEndian.PutUint16(data[offset+1:], uint16(len(p)))
	binary.BigEndian.PutUint16(data[offset+3:], uint16(padding))
	copy(data[prefix:], p)
	fastrand.Read(data[prefix+len(p):])
	if err := c.write(data); err != nil {
		return err
	}
	c.writeStarted = true
	if command != commandPaddingContinue {
		c.writePadding = false
	}
	if command == commandPaddingDirect {
		c.writeDirect = true
	}
	return nil
}
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	written := 0
	for written < len(p) {
		if !c.writePadding {
			if err := c.write(p[written:]); err != nil {
				return written, err
			}
			return len(p), nil
		}
		payload := p[written : written+min(maxContent, len(p)-written)]
		isTLS, enabled, left := c.filterTLS(payload)
		command := commandPaddingContinue
		if c.writeStarted {
			if !isTLS {
				command = commandPaddingEnd
			} else if bytes.HasPrefix(payload, []byte{23, 3, 3}) || left <= 0 {
				command = commandPaddingEnd
				if enabled {
					command = commandPaddingDirect
				}
			}
		}
		if err := c.writeRecord(payload, command, isTLS); err != nil {
			return written, err
		}
		written += len(payload)
	}
	return written, nil
}
func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.writePadding {
		if err := c.writeRecord(nil, commandPaddingEnd, false); err != nil {
			return err
		}
	}
	c.writeErr = net.ErrClosed
	writer := c.overlay
	if c.writeDirect {
		writer = c.Conn
	}
	if half, ok := writer.(netproxy.CloseWriter); ok {
		return half.CloseWrite()
	}
	return errors.ErrUnsupported
}
