// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

const requestReplayLimit = 64 << 10

var errIncompleteUpload = errors.New("request body incomplete for retry")

// Complete plugin buffers already have their own budget and size limit. Share
// them regardless of size; apply the recording limit only to streaming input.
func prepareRequestReplay(r *http.Request, budget *membuffer.Budget) func() {
	if r.GetBody != nil || r.Body == nil || r.Body == http.NoBody {
		return func() {}
	}
	if view := membuffer.Snapshot(r.Body); view != nil {
		// GetBody runs inside RoundTrip; its returned cursors own independent
		// references. Immutable input needs no recording state or upload lock.
		r.GetBody = func() (io.ReadCloser, error) { return view.Open(), nil }
		return view.Close
	}
	if r.ContentLength > requestReplayLimit {
		return func() {}
	}
	replay := &requestReplay{buffer: membuffer.Buffer{Budget: budget, Limit: requestReplayLimit}, source: r.Body, readers: 1}
	r.Body = &recordingRequestBody{replay: replay}
	r.GetBody = replay.open
	return replay.release
}

// A recording is unread (nil error, no view), incomplete, complete (view), or
// unavailable (error). io.ErrClosedPipe ends retry ownership. Source readers
// have separate ownership so an early response cannot close a pending upload.
type requestReplay struct {
	mu      sync.Mutex
	buffer  membuffer.Buffer
	view    *membuffer.View
	err     error
	source  io.ReadCloser
	readers int
}

func (r *requestReplay) record(p []byte, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != errIncompleteUpload {
		return
	}
	if _, writeErr := r.buffer.Write(p); writeErr != nil {
		err = writeErr
	}
	if err == nil {
		return
	}
	if err == io.EOF {
		r.view, err = r.buffer.View(), nil
	} else {
		r.buffer.Close()
	}
	r.err = err
}

func (r *requestReplay) open() (io.ReadCloser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	if r.view != nil {
		return r.view.Open(), nil
	}
	// The previous attempt never read the source. An unusable connection may
	// be replaced without buffering or waiting for any request data.
	r.readers++
	return &recordingRequestBody{replay: r}, nil
}

func (r *requestReplay) release() {
	r.mu.Lock()
	r.err = io.ErrClosedPipe
	r.buffer.Close()
	r.view.Close()
	var source io.ReadCloser
	if r.readers == 0 {
		source, r.source = r.source, nil
	}
	r.mu.Unlock()
	if source != nil {
		_ = source.Close()
	}
}

type recordingRequestBody struct {
	replay  *requestReplay
	started bool // protected by replay.mu
	closed  bool
}

func (b *recordingRequestBody) Read(p []byte) (int, error) {
	r := b.replay
	r.mu.Lock()
	if b.closed {
		r.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	b.started = true
	if r.err == nil && r.view == nil {
		r.err = errIncompleteUpload
	}
	source := r.source
	r.mu.Unlock()
	n, err := source.Read(p)
	r.record(p[:n], err)
	return n, err
}

func (b *recordingRequestBody) Close() error {
	r := b.replay
	r.mu.Lock()
	var source io.ReadCloser
	if !b.closed {
		b.closed = true
		r.readers--
		if b.started || r.err == io.ErrClosedPipe && r.readers == 0 {
			source, r.source = r.source, nil
		}
	}
	r.mu.Unlock()
	// A started attempt must unblock its Read. An unused attempt keeps the
	// source available until a retry borrows it or RoundTrip finishes.
	if source != nil {
		return source.Close()
	}
	return nil
}
