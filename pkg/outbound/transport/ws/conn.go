package ws

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/gorilla/websocket"
)

// Only the client side is implemented: outgoing frames are masked and peer
// frames must be unmasked. Reads cross frame boundaries without buffering a
// complete message. Close closes the carrier; WebSocket has no write half-close.
type conn struct {
	net.Conn
	reader                      *bufio.Reader
	lease                       *netproxy.Lease
	readMu                      sync.Mutex
	writeGate                   chan struct{}
	done                        chan struct{}
	closeOnce                   sync.Once
	closeErr                    error
	deadlineMu                  sync.Mutex
	readDeadline, writeDeadline time.Time
	readTimeout, writeTimeout   protocol.Deadline
	controlWrite                bool
	remaining                   uint64
	fragmented                  bool
	readErr, writeErr           error
}

func newConn(raw net.Conn, reader *bufio.Reader, lease *netproxy.Lease) *conn {
	c := &conn{Conn: raw, reader: reader, lease: lease, writeGate: make(chan struct{}, 1), done: make(chan struct{}), readTimeout: protocol.MakeDeadline(), writeTimeout: protocol.MakeDeadline()}
	c.writeGate <- struct{}{}
	return c
}
func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.closeErr = c.Conn.Close()
		c.deadlineMu.Lock()
		c.readTimeout.Set(time.Time{})
		c.writeTimeout.Set(time.Time{})
		c.deadlineMu.Unlock()
	})
	return c.closeErr
}
func (c *conn) acquireWrite(control bool) error {
	var readTimeout <-chan struct{}
	if control {
		readTimeout = c.readTimeout.Wait()
	}
	writeTimeout := c.writeTimeout.Wait()
	select {
	case <-c.done:
		return net.ErrClosed
	case <-readTimeout:
		return os.ErrDeadlineExceeded
	case <-writeTimeout:
		return os.ErrDeadlineExceeded
	default:
	}
	select {
	case <-c.done:
		return net.ErrClosed
	case <-readTimeout:
		return os.ErrDeadlineExceeded
	case <-writeTimeout:
		return os.ErrDeadlineExceeded
	case <-c.writeGate:
		return nil
	}
}

// Control replies belong to the active Read as well as the write side. A peer
// that stops reading Pong cannot make Read ignore its deadline. Setters and the
// final restoration always use the latest user deadlines under deadlineMu.
func (c *conn) writeControl(opcode byte, data []byte) (err error) {
	if err = c.acquireWrite(true); err != nil {
		return err
	}
	defer func() { c.writeGate <- struct{}{} }()
	c.deadlineMu.Lock()
	c.controlWrite = true
	err = c.Conn.SetWriteDeadline(c.effectiveWriteDeadline())
	c.deadlineMu.Unlock()
	if err == nil {
		err = c.writeFrame(opcode, true, data)
	}
	c.deadlineMu.Lock()
	c.controlWrite = false
	restore := c.Conn.SetWriteDeadline(c.writeDeadline)
	c.deadlineMu.Unlock()
	return errors.Join(err, restore)
}
func (c *conn) effectiveWriteDeadline() time.Time {
	deadline := c.writeDeadline
	if c.controlWrite && !c.readDeadline.IsZero() && (deadline.IsZero() || c.readDeadline.Before(deadline)) {
		deadline = c.readDeadline
	}
	return deadline
}
func (c *conn) setDeadline(t time.Time, read, write bool) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	var err error
	if read {
		c.readDeadline = t
		c.readTimeout.Set(t)
		err = c.Conn.SetReadDeadline(t)
	}
	if write {
		c.writeDeadline = t
		c.writeTimeout.Set(t)
	}
	if write || c.controlWrite {
		err = errors.Join(err, c.Conn.SetWriteDeadline(c.effectiveWriteDeadline()))
	}
	return err
}
func (c *conn) SetDeadline(t time.Time) error      { return c.setDeadline(t, true, true) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.setDeadline(t, true, false) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }
func (c *conn) DependencyLease() *netproxy.Lease   { return c.lease }
func (c *conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	for c.remaining == 0 {
		if err := c.readHeader(); err != nil {
			if !isTimeout(err) {
				c.readErr = err
			}
			return 0, err
		}
	}
	n, err := c.reader.Read(p[:min(uint64(len(p)), c.remaining)])
	c.remaining -= uint64(n)
	if err == io.EOF {
		err = frameReadError(err)
	}
	if err != nil && !isTimeout(err) {
		c.readErr = err
	}
	return n, err
}
func (c *conn) readHeader() error {

	// Peek keeps an incomplete header/control body in the reader across a
	// deadline. No byte is committed until the complete bounded header exists.
	header, err := c.reader.Peek(2)
	if err != nil {
		return frameReadError(err)
	}
	first, second := header[0], header[1]
	final, opcode := first&0x80 != 0, first&0x0f
	if first&0x70 != 0 || second&0x80 != 0 {
		return badFrame("websocket: unexpected reserved bits or masked server frame")
	}
	length := uint64(second & 0x7f)
	headerLength := 2
	if length == 126 {
		headerLength = 4
	} else if length == 127 {
		headerLength = 10
	}
	header, err = c.reader.Peek(headerLength)
	if err != nil {
		return frameReadError(err)
	}
	switch length {
	case 126:
		length = uint64(binary.BigEndian.Uint16(header[2:4]))
		if length < 126 {
			return badFrame("websocket: non-minimal frame length")
		}
	case 127:
		length = binary.BigEndian.Uint64(header[2:10])
		if length < 65536 || length>>63 != 0 {
			return badFrame("websocket: invalid frame length")
		}
	}

	switch opcode {
	case 0:
		if !c.fragmented {
			return badFrame("websocket: continuation without a message")
		}
		_, _ = c.reader.Discard(headerLength)
		c.fragmented = !final
		c.remaining = length
	case websocket.BinaryMessage, websocket.TextMessage:
		if c.fragmented {
			return badFrame("websocket: data frame interrupted fragmented message")
		}
		_, _ = c.reader.Discard(headerLength)
		c.fragmented = !final
		c.remaining = length
	case websocket.PingMessage, websocket.PongMessage, websocket.CloseMessage:
		if !final || length > 125 {
			return badFrame("websocket: invalid control frame")
		}

		wire, err := c.reader.Peek(headerLength + int(length))
		if err != nil {
			return frameReadError(err)
		}
		var payload [125]byte
		copy(payload[:], wire[headerLength:])
		control := payload[:length]

		if opcode == websocket.PingMessage {
			if err := c.writeControl(websocket.PongMessage, control); err != nil {
				return err
			}
			_, _ = c.reader.Discard(headerLength + int(length))
			return nil
		}
		if opcode == websocket.CloseMessage {
			if length == 1 {
				return badFrame("websocket: invalid close payload")
			}
			code, text := websocket.CloseNoStatusReceived, ""
			if length >= 2 {
				code = int(binary.BigEndian.Uint16(control[:2]))
				text = string(control[2:length])
				if !validCloseCode(code) || !utf8.ValidString(text) {
					return badFrame("websocket: invalid close status or text")
				}
			}
			peerError := netproxy.WrapFailure(&websocket.CloseError{Code: code, Text: text}, netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeStream, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonClosed, Code: strconv.Itoa(code)})
			if err := c.writeControl(websocket.CloseMessage, control); err != nil {
				return errors.Join(peerError, err)
			}
			_, _ = c.reader.Discard(headerLength + int(length))
			if code == websocket.CloseNormalClosure {
				return io.EOF
			}
			return peerError
		}
		_, _ = c.reader.Discard(headerLength + int(length))
	default:
		return badFrame(fmt.Sprintf("websocket: unknown opcode %d", opcode))
	}
	return nil
}
func validCloseCode(code int) bool {
	return code >= 3000 && code <= 4999 || code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006
}
func (c *conn) Write(p []byte) (int, error) {
	if err := c.acquireWrite(false); err != nil {
		return 0, err
	}
	defer func() { c.writeGate <- struct{}{} }()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	written := 0
	opcode := byte(websocket.BinaryMessage)
	for len(p) > 0 {
		count := min(len(p), 16<<10)
		if err := c.writeFrame(opcode, count == len(p), p[:count]); err != nil {
			return written, err
		}
		written += count
		p = p[count:]
		opcode = 0
	}
	return written, nil
}
func (c *conn) writeFrame(opcode byte, final bool, p []byte) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if final {
		opcode |= 0x80
	}
	_ = buf.WriteByte(opcode)
	if len(p) < 126 {
		_ = buf.WriteByte(0x80 | byte(len(p)))
	} else {
		_ = buf.WriteByte(0xfe)
		_ = buf.WriteByte(byte(len(p) >> 8))
		_ = buf.WriteByte(byte(len(p)))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	_, _ = buf.Write(mask[:])
	offset := buf.Len()
	_, _ = buf.Write(p)
	for i := range p {
		buf.Bytes()[offset+i] ^= mask[i%4]
	}
	n, err := c.Conn.Write(buf.Bytes())
	if err == nil && n != buf.Len() {
		err = io.ErrShortWrite
	}
	c.writeErr = err
	if err == nil && opcode&0x0f == websocket.CloseMessage {
		c.writeErr = websocket.ErrCloseSent
	}
	return err
}
func headerToken(value, token string) bool {
	for item := range strings.SplitSeq(value, ",") {
		if strings.EqualFold(strings.TrimSpace(item), token) {
			return true
		}
	}
	return false
}

func frameReadError(err error) error {
	if err == io.EOF {
		return netproxy.WrapFailure(fmt.Errorf("websocket: unexpected EOF before close frame: %w", err), netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeStream, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol})
	}
	return err
}
func isTimeout(err error) bool {
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}

func badFrame(detail string) error {
	return netproxy.WrapFailure(errors.New(detail), netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeStream, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol})
}
