// SPDX-License-Identifier: AGPL-3.0-only

package codec

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func (c *Codec) GRPCTransform(source io.ReadCloser, httpEncoding, grpcEncoding string, rewrite func(*Message) (*membuffer.View, error)) (io.ReadCloser, error) {
	for _, encoding := range strings.Split(httpEncoding, ",") {
		if encoding = strings.TrimSpace(encoding); encoding != "" && !strings.EqualFold(encoding, "identity") {
			return nil, fmt.Errorf("%w: streaming gRPC HTTP encoding %q", ErrUnsupported, httpEncoding)
		}
	}
	if rewrite == nil {
		return nil, errors.New("codec: gRPC rewrite callback is required")
	}
	d, err := c.GRPCDecoder(source, grpcEncoding)
	if err != nil {
		return nil, err
	}
	return &grpcTransform{decoder: d, rewrite: rewrite}, nil
}

type grpcTransform struct {
	decoder  *Decoder
	rewrite  func(*Message) (*membuffer.View, error)
	closed   atomic.Bool
	mu       sync.Mutex
	output   *membuffer.Reader
	bypass   io.Reader
	prefix   *membuffer.Reader
	terminal error
}

func (r *grpcTransform) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if r.terminal != nil {
			return 0, r.terminal
		}
		if err := r.decoder.codec.ctx.Err(); err != nil {
			return 0, r.finish(err)
		}
		if r.output != nil {
			n, err := r.output.Read(p)
			if err == io.EOF {
				_ = r.output.Close()
				r.output = nil
				err = nil
			}
			if n != 0 || err != nil {
				return n, err
			}
		}
		if r.bypass != nil {
			n, err := r.bypass.Read(p)
			if err != nil {
				err = r.finish(err)
			}
			return n, err
		}
		message, err := r.decoder.Next()
		if r.closed.Load() {
			message.Close()
			return 0, r.finish(io.ErrClosedPipe)
		}
		if canceled := r.decoder.codec.ctx.Err(); canceled != nil {
			message.Close()
			return 0, r.finish(canceled)
		}
		if err == io.EOF {
			return 0, r.finish(io.EOF)
		}
		if err != nil {
			r.bypass, r.prefix = r.decoder.remainder()
			continue
		}
		r.output, err = r.transform(message)
		if err != nil {
			r.prefix = message.wire.Open()
			r.bypass = io.MultiReader(r.prefix, r.decoder.input)
		}
		message.Close()
	}
}

func (r *grpcTransform) transform(message *Message) (_ *membuffer.Reader, err error) {
	defer func() {
		if value := recover(); value != nil {
			message.Close()
			panic(value)
		}
	}()
	replacement, err := r.rewrite(message)
	defer replacement.Close()
	if err != nil {
		return nil, err
	}
	if replacement == nil {
		return message.wire.Open(), nil
	}
	c := r.decoder.codec
	if replacement.Budget() != c.budget {
		return nil, ErrBudgetMismatch
	}
	frame, err := c.GRPCFrame(replacement.Bytes())
	if err != nil {
		return nil, err
	}
	defer frame.Close()
	return frame.Open(), nil
}

func (r *grpcTransform) finish(err error) error {
	r.terminal = err
	if r.output != nil {
		_ = r.output.Close()
		r.output = nil
	}
	if r.prefix != nil {
		_ = r.prefix.Close()
		r.prefix = nil
	}
	r.bypass = nil
	_ = r.decoder.Close()
	return err
}

func (r *grpcTransform) Close() error {
	r.closed.Store(true)
	err := r.decoder.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finish(io.ErrClosedPipe)
	return err
}
