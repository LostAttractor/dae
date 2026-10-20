// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// net/http's HTTP/1 Body.Close drains unread input and waits for active Reads.
// Interrupt those reads only when the upload owner closes it, or the request
// ends. Receiving response headers alone must not stop a duplex upload.
type http1RequestBody struct {
	io.ReadCloser
	deadline func(time.Time) error
	eof      atomic.Bool
	mu       sync.Mutex
	closing  bool
	once     sync.Once
	err      error
}

func (b *http1RequestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.eof.Store(true)
	}
	return n, err
}

func (b *http1RequestBody) TryReadEOF() (bool, error) {
	reader, ok := b.ReadCloser.(interface{ TryReadEOF() (bool, error) })
	if !ok {
		return false, nil
	}
	ended, err := reader.TryReadEOF()
	if ended && err == nil {
		b.eof.Store(true)
	}
	return ended, err
}

func (b *http1RequestBody) setReadDeadline(deadline time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing {
		// A plugin finishing concurrently must not undo the interruption
		// before the underlying Close has finished waiting for its reader.
		return nil
	}
	return b.deadline(deadline)
}

func (b *http1RequestBody) Close() error {
	b.once.Do(func() {
		b.mu.Lock()
		b.closing = true
		if !b.eof.Load() {
			_ = b.deadline(time.Now())
		}
		b.mu.Unlock()
		b.err = b.ReadCloser.Close()
	})
	return b.err
}
