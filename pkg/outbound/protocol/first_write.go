package protocol

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

const (
	firstWritePending uint32 = iota
	firstWriteSent
	firstWriteFailed
)

// FirstWrite defers a stream's request header to its first carrier write,
// which carries the header together with the first payload. Writes that may
// carry the header hold the embedded mutex, and every holder while the header
// is pending sends it in its first carrier write or records why it cannot.
//
// A Read that comes first sends the header alone, but never waits for a
// writer holding the lock: that writer is sending the header, and its carrier
// write may block until the client reads a reply the peer sends before
// reading on.
//
// A failure of the first carrier write, or of building the header, is
// permanent: the peer may hold part of the header, which cannot be resent.
type FirstWrite struct {
	sync.Mutex
	state atomic.Uint32
	err   error // set before state becomes firstWriteFailed
}

// Pending reports whether the first carrier write is still to come.
func (f *FirstWrite) Pending() bool { return f.state.Load() == firstWritePending }

// Err returns the failure of the first carrier write.
func (f *FirstWrite) Err() error {
	if f.state.Load() == firstWriteFailed {
		return f.err
	}
	return nil
}

// Done records the result of the first carrier write, or of building it, and
// returns err. The caller holds the lock.
func (f *FirstWrite) Done(err error) error {
	if err != nil {
		f.err = err
		f.state.Store(firstWriteFailed)
	} else {
		f.state.Store(firstWriteSent)
	}
	return err
}

// Flush serves a Read that may come before the first Write. Unless another
// goroutine holds the lock, it runs send, which sends the header alone and
// calls Done, with the lock held.
func (f *FirstWrite) Flush(send func() error) error {
	if f.Pending() && f.TryLock() {
		defer f.Unlock()
		return f.FlushLocked(send)
	}
	return f.Err()
}

// FlushLocked is Flush for a caller holding the lock, such as CloseWrite.
func (f *FirstWrite) FlushLocked(send func() error) error {
	if f.Pending() {
		return send()
	}
	return f.Err()
}

// Write writes p to w, preceded in the same carrier write by header while it
// is pending, and reports the bytes of p written. The caller holds the lock
// unless the header was sent.
func (f *FirstWrite) Write(w io.Writer, header, p []byte) (int, error) {
	switch f.state.Load() {
	case firstWriteSent:
		return w.Write(p)
	case firstWriteFailed:
		return 0, f.err
	}
	buf := pool.GetBuffer(len(header) + len(p))
	defer pool.PutBuffer(buf)
	copy(buf[copy(buf, header):], p)
	n, err := w.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	return min(max(n-len(header), 0), len(p)), f.Done(err)
}
