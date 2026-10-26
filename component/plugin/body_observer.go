// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"io"
	"sync"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

type bodyObserver struct {
	source   io.ReadCloser
	length   int64
	complete func([]byte)
	mu       sync.Mutex
	buffer   membuffer.Buffer
	stopped  bool
}

func (b *bodyObserver) Read(dst []byte) (int, error) {
	n, err := b.source.Read(dst)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return n, err
	}
	if err != nil && err != io.EOF {
		b.stopLocked()
		return n, err
	}
	if _, writeErr := b.buffer.Write(dst[:n]); writeErr != nil {
		b.stopLocked()
		return n, err
	}
	size := int64(b.buffer.Len())
	if b.length > 0 && (size > b.length || err == io.EOF && size != b.length) {
		b.stopLocked()
		return n, err
	}
	if err == io.EOF || b.length > 0 && size == b.length {
		defer b.stopLocked()
		view := b.buffer.View()
		defer view.Close()
		b.complete(view.Bytes())
	}
	return n, err
}

func (b *bodyObserver) stopLocked() {
	b.buffer.Close()
	b.complete = nil
	b.stopped = true
}

func (b *bodyObserver) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopLocked()
}

func (b *bodyObserver) Close() error {
	err := b.source.Close()
	b.stop()
	return err
}
