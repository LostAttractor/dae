// Package smuxtest is a minimal smux v1 server for tests: it accepts client
// streams and buffers their data without limit. It rejects the frames a
// sing-box server rejects (a wrong version, an unknown command) and, stricter
// than that server, control frames with payload and even stream IDs, which
// only a broken client sends.
package smuxtest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	Version = 1
	CmdSYN  = 0
	CmdFIN  = 1
	CmdPSH  = 2
	CmdNOP  = 3

	headerSize = 8
	maxFrame   = 32 << 10
)

var ErrProtocol = errors.New("smuxtest: invalid frame")

// Session is the server end of one smux session.
type Session struct {
	conn    net.Conn
	writeMu sync.Mutex
	header  [headerSize]byte // guarded by writeMu
	accept  chan *Stream
	done    chan struct{}

	mu      sync.Mutex
	streams map[uint32]*Stream
	err     error
}

// Server serves an smux session on conn, which carries no sing-mux header.
func Server(conn net.Conn) *Session {
	s := &Session{conn: conn, accept: make(chan *Stream, 1024), done: make(chan struct{}), streams: make(map[uint32]*Stream)}
	go s.recv()
	return s
}

// Accept returns the next stream the client opened.
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.done:
		return nil, s.Err()
	}
}

// Done is closed once the session ended, by Close or a failed read.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err reports why the session ended.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) Close() error {
	err := s.conn.Close()
	s.end(io.ErrClosedPipe)
	return err
}

// WriteFrame writes one raw frame.
func (s *Session) WriteFrame(version, cmd byte, sid uint32, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.header = [headerSize]byte{version, cmd}
	binary.LittleEndian.PutUint16(s.header[2:], uint16(len(payload)))
	binary.LittleEndian.PutUint32(s.header[4:], sid)
	if _, err := s.conn.Write(s.header[:]); err != nil || len(payload) == 0 {
		return err
	}
	_, err := s.conn.Write(payload)
	return err
}

func (s *Session) end(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	s.err = err
	close(s.done)
	for _, st := range s.streams {
		st.push(nil, err)
	}
}

func (s *Session) recv() {
	var header [headerSize]byte
	scratch := make([]byte, 1<<16)
	for {
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			s.end(err)
			return
		}
		length, sid := int(binary.LittleEndian.Uint16(header[2:])), binary.LittleEndian.Uint32(header[4:])
		if header[0] != Version || header[1] > CmdNOP || header[1] != CmdPSH && length != 0 || header[1] != CmdNOP && sid%2 == 0 {
			s.conn.Close()
			s.end(ErrProtocol)
			return
		}
		payload := scratch[:length]
		if _, err := io.ReadFull(s.conn, payload); err != nil {
			s.end(err)
			return
		}
		s.mu.Lock()
		st := s.streams[sid]
		opened := header[1] == CmdSYN && st == nil
		if opened {
			st = &Stream{session: s, id: sid, readable: make(chan struct{}, 1)}
			s.streams[sid] = st
		}
		s.mu.Unlock()
		switch {
		case opened:
			s.accept <- st
		case st == nil:
		case header[1] == CmdPSH:
			st.push(payload, nil)
		case header[1] == CmdFIN:
			st.push(nil, io.EOF)
		}
	}
}

// Stream is a server stream. Its writes are synchronous frames; its reads
// support deadlines.
type Stream struct {
	session  *Session
	id       uint32
	readable chan struct{}

	mu       sync.Mutex
	buf      bytes.Buffer
	err      error // after buf: io.EOF on FIN or the session's end
	closed   bool
	deadline time.Time
}

func (st *Stream) ID() uint32 { return st.id }

func (st *Stream) push(data []byte, err error) {
	st.mu.Lock()
	st.buf.Write(data)
	if st.err == nil {
		st.err = err
	}
	st.mu.Unlock()
	select {
	case st.readable <- struct{}{}:
	default:
	}
}

func (st *Stream) Read(b []byte) (int, error) {
	for {
		st.mu.Lock()
		if st.closed {
			st.mu.Unlock()
			return 0, io.ErrClosedPipe
		}
		if st.buf.Len() > 0 {
			n, _ := st.buf.Read(b)
			st.mu.Unlock()
			return n, nil
		}
		err, deadline := st.err, st.deadline
		st.mu.Unlock()
		if err != nil {
			return 0, err
		}
		if deadline.IsZero() {
			<-st.readable
			continue
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-st.readable:
			timer.Stop()
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (st *Stream) Write(b []byte) (int, error) {
	st.mu.Lock()
	closed := st.closed
	st.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(b) > 0 {
		n := min(len(b), maxFrame)
		if err := st.session.WriteFrame(Version, CmdPSH, st.id, b[:n]); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

// Close sends FIN; reads fail afterwards.
func (st *Stream) Close() error {
	st.mu.Lock()
	closed := st.closed
	st.closed = true
	st.mu.Unlock()
	if closed {
		return io.ErrClosedPipe
	}
	st.push(nil, nil)
	return st.session.WriteFrame(Version, CmdFIN, st.id, nil)
}

func (st *Stream) LocalAddr() net.Addr  { return st.session.conn.LocalAddr() }
func (st *Stream) RemoteAddr() net.Addr { return st.session.conn.RemoteAddr() }

// SetDeadline bounds reads only: writes are synchronous carrier writes.
func (st *Stream) SetDeadline(t time.Time) error { return st.SetReadDeadline(t) }

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.deadline = t
	st.mu.Unlock()
	st.push(nil, nil)
	return nil
}

func (*Stream) SetWriteDeadline(time.Time) error { return nil }
