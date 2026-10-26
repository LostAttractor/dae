// SPDX-License-Identifier: AGPL-3.0-only

package codec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

type Message struct {
	wire, decoded *membuffer.View
}

func (m *Message) Wire() []byte { return m.wire.Bytes() }
func (m *Message) Payload() []byte {
	if m.decoded != nil {
		return m.decoded.Bytes()
	}
	return m.wire.Bytes()[5:]
}
func (m *Message) Close() {
	if m != nil {
		m.wire.Close()
		m.decoded.Close()
	}
}

type Decoder struct {
	codec       *Codec
	encoding    string
	input       *grpcInput
	closeSource func() error
	closed      atomic.Bool
	mu          sync.Mutex
	stop        func() bool
	failed      error
	truncated   bool
	header      [5]byte
	headn       int
	partial     *membuffer.View
}

func (c *Codec) GRPCDecoder(source io.ReadCloser, encoding string) (*Decoder, error) {
	if source == nil {
		return nil, errors.New("codec: gRPC source is required")
	}
	if c.limits.Wire < 5 {
		return nil, membuffer.ErrInvalidLimit
	}
	return &Decoder{codec: c, encoding: strings.ToLower(strings.TrimSpace(encoding)),
		input: &grpcInput{ctx: c.ctx, source: source}, closeSource: sync.OnceValue(source.Close)}, nil
}

func (d *Decoder) Next() (*Message, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	if d.failed != nil {
		return nil, d.failed
	}
	if err := d.codec.ctx.Err(); err != nil {
		return d.fail(err)
	}
	if d.stop == nil {
		d.stop = context.AfterFunc(d.codec.ctx, func() { _ = d.closeSource() })
	}
	n, err := io.ReadFull(d.input, d.header[:])
	d.headn = n
	if err != nil {
		d.truncated = err == io.ErrUnexpectedEOF && d.input.err == io.EOF
		return d.fail(err)
	}
	size := int64(binary.BigEndian.Uint32(d.header[1:])) + 5
	if size > d.codec.limits.Wire {
		return d.fail(membuffer.ErrTooLarge)
	}
	if d.header[0] > 1 {
		return d.fail(fmt.Errorf("%w: gRPC flag %d", ErrUnsupported, d.header[0]))
	}
	if d.header[0] == 0 && size-5 > d.codec.limits.Decoded {
		return d.fail(membuffer.ErrTooLarge)
	}
	if d.header[0] == 1 && d.encoding != "gzip" {
		return d.fail(fmt.Errorf("%w: gRPC encoding %q", ErrUnsupported, d.encoding))
	}
	framed := io.MultiReader(bytes.NewReader(d.header[:]), d.input)
	d.partial, err = membuffer.ReadExact(framed, size, d.codec.budget)
	if err != nil {
		d.truncated = err == io.ErrUnexpectedEOF && d.input.err == io.EOF
		return d.fail(err)
	}
	if d.input.err != nil && d.input.err != io.EOF {
		return d.fail(d.input.err)
	}
	var decoded *membuffer.View
	if d.header[0] == 1 {
		decoded, err = d.codec.decodeBytes(d.partial.Bytes()[5:], "gzip", d.codec.limits.Decoded)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return d.fail(err)
		}
	}
	if err := d.codec.ctx.Err(); err != nil {
		decoded.Close()
		return d.fail(err)
	}
	if d.closed.Load() {
		decoded.Close()
		return d.fail(io.ErrClosedPipe)
	}
	m := &Message{wire: d.partial, decoded: decoded}
	d.partial, d.headn = nil, 0
	return m, nil
}

func (d *Decoder) fail(err error) (*Message, error) {
	if d.input.err != nil && d.input.err != io.EOF {
		err = d.input.err
	}
	d.failed = err
	return nil, err
}

func (d *Decoder) Close() error {
	d.closed.Store(true)
	err := d.closeSource()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stop != nil {
		d.stop()
		d.stop = nil
	}
	d.partial.Close()
	d.partial = nil
	return err
}

func (d *Decoder) remainder() (io.Reader, *membuffer.Reader) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var readers []io.Reader
	var prefix *membuffer.Reader
	covered := 0
	if d.partial != nil {
		covered = min(len(d.partial.Bytes()), d.headn)
		prefix = d.partial.Open()
		d.partial.Close()
		d.partial = nil
		readers = append(readers, prefix)
	}
	if covered < d.headn {
		readers = append(readers, bytes.NewReader(d.header[covered:d.headn]))
	}
	var tail io.Reader = d.input
	if d.truncated {
		tail = grpcReadError{io.ErrUnexpectedEOF}
	}
	readers = append(readers, tail)
	return io.MultiReader(readers...), prefix
}

type grpcInput struct {
	ctx    context.Context
	source io.Reader
	err    error
}

func (r *grpcInput) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.ctx.Err(); err != nil {
		r.err = err
	}
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.source.Read(p)
	r.err = err
	if n != 0 {
		return n, nil
	}
	return n, err
}

type grpcReadError struct{ err error }

func (r grpcReadError) Read([]byte) (int, error) { return 0, r.err }

func (c *Codec) GRPCFrame(parts ...[]byte) (*membuffer.View, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	limit := min(c.limits.Decoded, c.limits.Wire-5, int64(math.MaxUint32))
	var size int64
	for _, part := range parts {
		if int64(len(part)) > limit-size {
			return nil, membuffer.ErrTooLarge
		}
		size += int64(len(part))
	}
	if limit < 0 {
		return nil, membuffer.ErrTooLarge
	}
	b := membuffer.Buffer{Budget: c.budget, Limit: size + 5}
	defer b.Close()
	if err := b.Grow(int(size + 5)); err != nil {
		return nil, err
	}
	var header [5]byte
	binary.BigEndian.PutUint32(header[1:], uint32(size))
	if _, err := b.Write(header[:]); err != nil {
		return nil, err
	}
	for _, part := range parts {
		if _, err := b.Write(part); err != nil {
			return nil, err
		}
	}
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	return b.View(), nil
}
