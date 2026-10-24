// Package aeadframe reads the chunk stream shared by Shadowsocks AEAD and
// Shadowsocks 2022: a sealed 2-byte big-endian length, then the sealed payload
// of that length, each with its own tag and the next nonce.
package aeadframe

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

const (
	// restSize bounds the buffer a drained reader keeps for its next header.
	restSize = 1 << 10
	// maxEmptyReads consecutive (0, nil) reads fail with io.ErrNoProgress, as in bufio.
	maxEmptyReads = 100
)

// Reader opens chunks in place in one pooled buffer, reading ahead as far as
// the buffer allows. A chunk is only usable whole, so the socket is asked to
// wake the reader once the rest of the current chunk has arrived.
//
// Reader is not safe for concurrent use. Close it only after closing Conn has
// interrupted a blocked call and later calls are excluded.
type Reader struct {
	Conn net.Conn

	sock    socket
	buf     []byte // pooled; len == cap
	r, w    int    // unread ciphertext is buf[r:w]
	plain   []byte // opened payload not yet returned; aliases buf
	aead    cipher.AEAD
	nonce   []byte
	pending int   // ciphertext size of the payload chunk whose length is opened; 0 before a length chunk
	later   error // read error returned with data, reported when more data is needed
	err     error // sticky
}

// Peek returns the next n bytes without consuming them; they stay valid until
// the next call. Errors follow Read.
func (r *Reader) Peek(n int) ([]byte, error) {
	if err := r.fill(n); err != nil {
		return nil, err
	}
	return r.buf[r.r : r.r+n], nil
}

// Discard consumes n bytes returned by Peek.
func (r *Reader) Discard(n int) { r.r += n }

// Start opens chunks from here with aead, starting at nonce, which r then
// owns. A non-negative length announces the first payload chunk, as the
// Shadowsocks 2022 response header does; otherwise a length chunk comes first.
func (r *Reader) Start(aead cipher.AEAD, nonce []byte, length int) {
	r.aead, r.nonce = aead, nonce
	if length >= 0 {
		r.pending = length + aead.Overhead()
	}
}

// Fail makes err the result of every later call and returns it.
func (r *Reader) Fail(err error) error {
	r.err = err
	return err
}

// Read returns opened payload. After a timeout buffered ciphertext is kept, so
// a retry resumes anywhere. Any other failure inside a chunk is sticky: a
// truncated chunk reports io.ErrUnexpectedEOF.
func (r *Reader) Read(b []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if len(b) == 0 {
		return 0, nil
	}
	for len(r.plain) == 0 {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n := copy(b, r.plain)
	r.plain = r.plain[n:]
	if len(r.plain) == 0 && r.r == r.w {
		r.r, r.w = 0, 0
		if len(r.buf) > restSize {
			pool.PutBuffer(r.buf)
			r.buf = nil
		}
	}
	return n, nil
}

// Close returns the buffer to the pool; later calls fail with net.ErrClosed.
func (r *Reader) Close() {
	pool.PutBuffer(r.buf)
	r.buf, r.plain = nil, nil
	r.r, r.w = 0, 0
	r.err = net.ErrClosed
}

// open authenticates the next payload chunk. The nonce advances only past
// chunks that opened, and an opened length survives a failed payload read.
func (r *Reader) open() error {
	overhead := r.aead.Overhead()
	if r.pending == 0 {
		chunk, err := r.Peek(2 + overhead)
		if err != nil {
			return err
		}
		if _, err := r.aead.Open(chunk[:0], r.nonce, chunk, nil); err != nil {
			return r.Fail(authFailure())
		}
		common.BytesIncLittleEndian(r.nonce)
		r.r += len(chunk)
		r.pending = int(binary.BigEndian.Uint16(chunk)) + overhead
	}
	chunk, err := r.Peek(r.pending)
	if err != nil {
		return err
	}
	plain, err := r.aead.Open(chunk[:0], r.nonce, chunk, nil)
	if err != nil {
		return r.Fail(authFailure())
	}
	common.BytesIncLittleEndian(r.nonce)
	r.r += len(chunk)
	r.pending = 0
	r.plain = plain
	return nil
}

// fill buffers at least n unread bytes, reading into the whole buffer.
func (r *Reader) fill(n int) error {
	if r.err != nil {
		return r.err
	}
	if r.w-r.r >= n {
		return nil
	}
	if len(r.buf)-r.r < n {
		if len(r.buf) >= n {
			r.w = copy(r.buf, r.buf[r.r:r.w])
		} else {
			buf := pool.GetBuffer(max(n, restSize))
			buf = buf[:cap(buf)]
			r.w = copy(buf, r.buf[r.r:r.w])
			pool.PutBuffer(r.buf)
			r.buf = buf
		}
		r.r = 0
	}
	for empty := 0; r.w-r.r < n; {
		if err := r.later; err != nil {
			r.later = nil
			return r.failRead(err)
		}
		if empty == maxEmptyReads {
			return r.failRead(io.ErrNoProgress)
		}
		r.sock.demand(r.Conn, n-(r.w-r.r))
		var m int
		m, r.later = r.Conn.Read(r.buf[r.w:])
		r.w += m
		if m > 0 {
			empty = 0
		} else {
			empty++
		}
	}
	return nil
}

// failRead keeps buffered ciphertext after a timeout so a retry resumes. Other
// errors are final once a chunk has started: its stream position is lost.
func (r *Reader) failRead(err error) error {
	if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
		return err
	}
	if r.r == r.w && r.pending == 0 {
		return err
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return r.Fail(err)
}

// Invalid chunks belong to this proxy stream; they do not invalidate a
// multiplexed transport carrying other streams.
func authFailure() error {
	return netproxy.WrapFailure(protocol.ErrFailAuth, netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonAuth, Phase: netproxy.OpRead})
}
