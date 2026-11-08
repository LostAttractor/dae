// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

type Body struct {
	reader          io.ReadCloser
	budget          *membuffer.Budget
	request         *Request
	response        *Response
	sealed          bool
	mu              sync.Mutex
	closed          bool
	observeSnapshot func(time.Duration)
}

func (b *Body) editable() error {
	if b.sealed || b.closed {
		return errors.New("plugin: body ownership already transferred or closed")
	}
	if r := b.request; r != nil {
		if r.Head != r.head || r.Head.Body != nil || r.Head.GetBody != nil {
			return errors.New("plugin: request Head or body ownership was replaced")
		}
	} else if r := b.response; r != nil {
		if r.Head != r.head || r.Head.Body != nil {
			return errors.New("plugin: response Head or body ownership was replaced")
		}
	}
	return nil
}

func (b *Body) Observe(limit int64, complete func([]byte)) (stop func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.editable(); err != nil {
		panic(err)
	}
	if b.response != nil && b.response.Head.StatusCode == http.StatusSwitchingProtocols {
		return func() {}
	}
	length := b.contentLength()
	if complete == nil || limit <= 0 || limit >= int64(math.MaxInt) || length > limit {
		return func() {}
	}
	if b.reader == nil || b.reader == http.NoBody {
		if length <= 0 {
			complete(nil)
		}
		return func() {}
	}
	observer := &bodyObserver{source: b.reader, length: length, complete: complete,
		buffer: membuffer.Buffer{Budget: b.budget, Limit: limit}}
	b.reader = ownBody(observer)
	return observer.stop
}

func (b *Body) Snapshot(limit int64) (*membuffer.View, error) {
	b.mu.Lock()
	if err := b.editable(); err != nil {
		b.mu.Unlock()
		return nil, err
	}
	reader := b.reader
	b.mu.Unlock()
	if observe := b.observeSnapshot; observe != nil {
		started := time.Now()
		defer func() { observe(time.Since(started)) }()
	}
	view, err := snapshotBody(&reader, limit, b.budget)
	b.mu.Lock()
	closed := b.closed
	if !closed {
		b.reader = reader
	}
	b.mu.Unlock()
	if closed {
		if reader != nil {
			_ = reader.Close()
		}
		if view != nil {
			view.Close()
		}
		return nil, errors.Join(io.ErrClosedPipe, err)
	}
	return view, err
}

func (b *Body) Replace(view *membuffer.View) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.editable(); err != nil {
		panic(err)
	}
	if err := b.replaceable(); err != nil {
		return err
	}
	next := view.Open()
	if b.reader != nil {
		_ = b.reader.Close()
	}
	b.reader = ownBody(next)
	b.replaceMetadata(int64(len(view.Bytes())))
	return nil
}

func (b *Body) Transform(install func(io.ReadCloser) (io.ReadCloser, error)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.editable(); err != nil {
		return err
	}
	if err := b.replaceable(); err != nil {
		return err
	}
	source := b.reader
	if source == nil {
		source = http.NoBody
	}
	input := &transformInput{source: source}
	output, err := install(input)
	if input.premature || output == nil && err == nil {
		err = errors.New("plugin: transform installation must not consume input and must return a body")
	}
	if err != nil {
		if output != nil {
			_ = output.Close()
		}
		return err
	}
	input.active = true
	b.reader = ownBody(&transformedBody{ReadCloser: output, body: b})
	b.replaceMetadata(-1)
	return nil
}

func (b *Body) Close() error {
	b.mu.Lock()
	b.closed = true
	reader := b.reader
	b.mu.Unlock()
	if reader != nil {
		return reader.Close()
	}
	return nil
}

// A replaced body is a complete representation, not an upgraded stream or a range.
func (b *Body) replaceable() error {
	if b.response == nil {
		return nil
	}
	switch b.response.Head.StatusCode {
	case http.StatusSwitchingProtocols:
		return errors.New("plugin: cannot replace the body of an upgraded connection")
	case http.StatusPartialContent:
		return errors.New("plugin: cannot replace the body of a partial response")
	}
	return nil
}

func (b *Body) contentLength() int64 {
	if b.request != nil {
		return b.request.Head.ContentLength
	}
	return b.response.Head.ContentLength
}

func (b *Body) replaceMetadata(size int64) {
	if b.request != nil {
		r := b.request.Head
		r.Header, r.ContentLength = replaceBodyMetadata(r.Header, r.Trailer, size)
		r.TransferEncoding, r.GetBody = nil, nil
	} else {
		r := b.response.Head
		r.Header, r.ContentLength = replaceBodyMetadata(r.Header, r.Trailer, size)
		r.TransferEncoding = nil
		b.response.delivery = DeliveryDefault
	}
}

func stripRepresentationMetadata(h http.Header) {
	for _, key := range []string{"Content-Encoding", "Content-Length", "Transfer-Encoding", "Trailer", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "ETag", "Last-Modified", "Accept-Ranges"} {
		h.Del(key)
	}
}

func replaceBodyMetadata(header, trailer http.Header, size int64) (http.Header, int64) {
	if header == nil {
		header = make(http.Header)
	}
	stripRepresentationMetadata(header)
	stripRepresentationMetadata(trailer)
	if size < 0 || len(trailer) != 0 {
		return header, -1
	}
	header.Set("Content-Length", strconv.FormatInt(size, 10))
	return header, size
}

type transformInput struct {
	source            io.ReadCloser
	active, premature bool
}

func (b *transformInput) Read(dst []byte) (int, error) {
	if !b.active {
		b.premature = true
		return 0, errors.New("plugin: read during transform installation")
	}
	return b.source.Read(dst)
}

func (b *transformInput) Close() error {
	if !b.active {
		b.premature = true
		return errors.New("plugin: close during transform installation")
	}
	return b.source.Close()
}

type transformedBody struct {
	io.ReadCloser
	body *Body
}

func (b *transformedBody) Read(dst []byte) (int, error) {
	n, err := b.ReadCloser.Read(dst)
	if err == io.EOF {
		if b.body.request != nil {
			stripRepresentationMetadata(b.body.request.Head.Trailer)
		} else {
			stripRepresentationMetadata(b.body.response.Head.Trailer)
		}
	}
	return n, err
}
