// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"errors"
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/internal/pluginctx"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

type Delivery uint8

const (
	DeliveryDefault Delivery = iota
	DeliveryStreaming
)

type Request struct {
	Head *http.Request
	head *http.Request
	body Body
}

type Response struct {
	Head     *http.Response
	head     *http.Response
	body     Body
	delivery Delivery
}

func NewRequest(raw *http.Request, budget *membuffer.Budget) *Request {
	head := new(http.Request)
	*head = *raw
	head.Body, head.GetBody = nil, nil
	r := &Request{Head: head, head: head}
	r.body = Body{reader: ownBody(raw.Body), budget: budget, request: r,
		observeSnapshot: pluginctx.SnapshotObserver(raw.Context())}
	return r
}

func NewResponse(raw *http.Response, budget *membuffer.Budget) *Response {
	reader := raw.Body
	raw.Body = nil
	r := &Response{Head: raw, head: raw}
	r.body = Body{reader: ownBody(reader), budget: budget, response: r}
	return r
}

func (r *Request) Body() *Body         { return &r.body }
func (r *Response) Body() *Body        { return &r.body }
func (r *Response) Close() error       { return r.body.Close() }
func (r *Response) Delivery() Delivery { return r.delivery }

func (r *Response) SetDelivery(delivery Delivery) {
	r.body.mu.Lock()
	defer r.body.mu.Unlock()
	if err := r.body.editable(); err != nil {
		panic(err)
	}
	if delivery != DeliveryDefault && delivery != DeliveryStreaming {
		panic("plugin: invalid response delivery")
	}
	r.delivery = delivery
}

func (e *Exchange) NewResponse(raw *http.Response) *Response {
	r := NewResponse(raw, e.Request.body.budget)
	r.Head.Request = e.Request.Head
	r.body.observeSnapshot = e.Request.body.observeSnapshot
	return r
}

func (r *Request) Forward() (*http.Request, error) {
	r.body.mu.Lock()
	defer r.body.mu.Unlock()
	if err := r.body.editable(); err != nil {
		return nil, err
	}
	r.body.sealed = true
	wire := new(http.Request)
	*wire = *r.Head
	wire.Body = r.body.reader
	return wire, nil
}

func (r *Response) TakeHTTP() (*http.Response, Delivery, error) {
	r.body.mu.Lock()
	defer r.body.mu.Unlock()
	if err := r.body.editable(); err != nil {
		return nil, DeliveryDefault, err
	}
	if r.Head.Header == nil || r.body.reader == nil {
		return nil, DeliveryDefault, errors.New("plugin: response requires headers and body")
	}
	r.body.sealed = true
	wire := new(http.Response)
	*wire = *r.Head
	wire.Body = r.body.reader
	if wire.StatusCode == http.StatusSwitchingProtocols {
		return wire, r.delivery, nil
	}
	head := wire.Request != nil && wire.Request.Method == http.MethodHead
	if head || wire.StatusCode < 200 || wire.StatusCode == http.StatusNoContent || wire.StatusCode == http.StatusResetContent || wire.StatusCode == http.StatusNotModified {
		_ = wire.Body.Close()
		r.body.reader, wire.Body = http.NoBody, http.NoBody
		wire.TransferEncoding, wire.Trailer = nil, nil
		wire.Header.Del("Transfer-Encoding")
		wire.Header.Del("Trailer")
		maps.DeleteFunc(wire.Header, func(name string, _ []string) bool {
			return strings.HasPrefix(name, http.TrailerPrefix)
		})
		if wire.StatusCode == http.StatusResetContent {
			wire.ContentLength = 0
			wire.Header.Set("Content-Length", "0")
		} else if wire.StatusCode < 200 || wire.StatusCode == http.StatusNoContent {
			wire.ContentLength = 0
			wire.Header.Del("Content-Length")
		} else if wire.StatusCode != http.StatusNotModified {
			// HEAD describes the corresponding representation's length. A 304 keeps
			// its header as is: HTTP/1 transports report ContentLength 0 for it.
			if wire.ContentLength < 0 {
				wire.Header.Del("Content-Length")
			} else {
				wire.Header.Set("Content-Length", strconv.FormatInt(wire.ContentLength, 10))
			}
		}
	} else {
		wire.Body = &responseTrailerBody{ReadCloser: wire.Body, head: r.Head, wire: wire}
	}
	return wire, r.delivery, nil
}

type responseTrailerBody struct {
	io.ReadCloser
	head, wire *http.Response
}

func (b *responseTrailerBody) Read(dst []byte) (int, error) {
	n, err := b.ReadCloser.Read(dst)
	if err == io.EOF {
		b.wire.Trailer = b.head.Trailer
	}
	return n, err
}

type ownedBody struct {
	io.ReadCloser
	close func() error
}

func ownBody(reader io.ReadCloser) io.ReadCloser {
	if reader == nil || reader == http.NoBody {
		return reader
	}
	b := &ownedBody{ReadCloser: reader, close: sync.OnceValue(reader.Close)}
	if writer, ok := reader.(io.Writer); ok {
		return &ownedReadWriteBody{ownedBody: b, Writer: writer}
	}
	return b
}

func (b *ownedBody) Close() error              { return b.close() }
func (b *ownedBody) Snapshot() *membuffer.View { return membuffer.Snapshot(b.ReadCloser) }
func (b *ownedBody) TryReadEOF() (bool, error) {
	if reader, ok := b.ReadCloser.(interface{ TryReadEOF() (bool, error) }); ok {
		return reader.TryReadEOF()
	}
	if view := membuffer.Snapshot(b.ReadCloser); view != nil {
		defer view.Close()
		return len(view.Bytes()) == 0, nil
	}
	return false, nil
}

type ownedReadWriteBody struct {
	*ownedBody
	io.Writer
}

func (b *ownedReadWriteBody) CloseWrite() error {
	if writer, ok := b.ReadCloser.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}
