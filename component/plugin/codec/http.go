// SPDX-License-Identifier: AGPL-3.0-only

package codec

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/andybalholm/brotli"
	"github.com/daeuniverse/dae/common/fileio"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

const (
	httpFlateWorkspace = 1 << 20
	maxHTTPLayers      = 4
	// Allow a maximum-window Brotli decoder plus three flate decoders.
	maxHTTPWorkspace = 40 << 20
)

func httpEncodings(encoding string) ([]string, error) {
	var layers []string
	compressed := 0
	for part := range strings.SplitSeq(encoding, ",") {
		switch part = strings.ToLower(strings.TrimSpace(part)); part {
		case "":
		case "identity":
			if len(layers) == 0 || layers[len(layers)-1] != part {
				layers = append(layers, part)
			}
		case "gzip", "deflate", "br":
			compressed++
			if compressed > maxHTTPLayers {
				return nil, fmt.Errorf("%w: too many Content-Encoding layers", ErrUnsupported)
			}
			layers = append(layers, part)
		default:
			return nil, fmt.Errorf("%w: Content-Encoding %q", ErrUnsupported, part)
		}
	}
	return layers, nil
}

func (c *Codec) HTTPView(view *membuffer.View, encoding string) (_ *membuffer.View, err error) {
	defer func() {
		if err != nil {
			view.Close()
		}
	}()
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	if view == nil {
		return nil, fmt.Errorf("HTTPView requires a view")
	}
	if view.Budget() != c.budget {
		return nil, ErrBudgetMismatch
	}
	layers, err := httpEncodings(encoding)
	if err != nil {
		return nil, err
	}
	if int64(len(view.Bytes())) > c.limits.Wire {
		return nil, membuffer.ErrTooLarge
	}
	if len(layers) == 0 && int64(len(view.Bytes())) > c.limits.Decoded {
		return nil, membuffer.ErrTooLarge
	}
	for i := len(layers) - 1; i >= 0; i-- {
		if layers[i] == "identity" {
			if int64(len(view.Bytes())) > c.limits.Decoded {
				return nil, membuffer.ErrTooLarge
			}
			continue
		}
		decoded, err := c.decodeBytes(view.Bytes(), layers[i], c.limits.Decoded)
		if err != nil {
			return nil, err
		}
		view.Close()
		view = decoded
	}
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	return view, nil
}

func (c *Codec) decodeBytes(raw []byte, encoding string, limit int64) (*membuffer.View, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	layers, err := httpEncodings(encoding)
	if err != nil {
		return nil, err
	}
	r := c.httpReader(httpMemorySource{bytes.NewReader(raw)}, layers, int64(len(raw)), limit)
	defer r.Close()
	view, err := membuffer.Read(r, limit, c.budget)
	if err != nil {
		view.Close()
		return nil, err
	}
	return view, nil
}

// httpMemorySource is bounded by its length and readable byte-wise at no cost.
type httpMemorySource struct{ *bytes.Reader }

func (httpMemorySource) Close() error { return nil }

func (c *Codec) HTTPReader(source io.ReadCloser, encoding string) (io.ReadCloser, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil {
		return nil, fmt.Errorf("HTTPReader requires a source")
	}
	layers, err := httpEncodings(encoding)
	if err != nil {
		return nil, err
	}
	return c.httpReader(source, layers, c.limits.Wire, c.limits.Decoded), nil
}

func (c *Codec) httpReader(source io.ReadCloser, layers []string, wire, decoded int64) *httpReader {
	return &httpReader{codec: c, source: source, layers: layers, wireLimit: wire, decodedLimit: decoded}
}

type httpReader struct {
	codec                   *Codec
	source                  io.ReadCloser
	layers                  []string
	wireLimit, decodedLimit int64
	mu                      sync.Mutex
	closed                  atomic.Bool
	closeOnce               sync.Once
	closeErr                error
	stop                    func() bool
	reader                  io.Reader
	bounds                  []*httpBoundedReader
	closers                 []io.Closer
	memory                  []membuffer.Reservation
	workspace               int64
	terminal                error
}

func (r *httpReader) closeSource() error {
	r.closeOnce.Do(func() { r.closeErr = r.source.Close() })
	return r.closeErr
}

func (r *httpReader) Close() error {
	r.closed.Store(true)
	err := r.closeSource()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.release()
	return err
}

func (r *httpReader) release() {
	if r.stop != nil {
		r.stop()
		r.stop = nil
	}
	for i := len(r.closers) - 1; i >= 0; i-- {
		_ = r.closers[i].Close()
	}
	r.closers, r.reader, r.bounds = nil, nil, nil
	for i := range r.memory {
		r.memory[i].Close()
	}
	r.memory = nil
	r.workspace = 0
}

func (r *httpReader) bounded(input io.Reader, limit int64) *httpBoundedReader {
	b := &httpBoundedReader{reader: fileio.NewContextReader(r.codec.ctx, input), remaining: limit}
	r.bounds = append(r.bounds, b)
	return b
}

func (r *httpReader) failure() error {
	if err := r.codec.ctx.Err(); err != nil {
		return err
	}
	for _, bound := range r.bounds {
		if bound.err != nil && bound.err != io.EOF {
			return bound.err
		}
	}
	return nil
}

func (r *httpReader) reserve(size int64) error {
	if err := r.codec.ctx.Err(); err != nil {
		return err
	}
	if size > maxHTTPWorkspace-r.workspace {
		return fmt.Errorf("%w: Content-Encoding workspace limit exceeded", ErrUnsupported)
	}
	memory, err := r.codec.budget.Reserve(size)
	if err != nil {
		return err
	}
	r.workspace += size
	r.memory = append(r.memory, memory)
	return nil
}

func (r *httpReader) initialize() error {
	r.stop = context.AfterFunc(r.codec.ctx, func() { _ = r.Close() })
	var input io.Reader
	if source, ok := r.source.(httpMemorySource); ok {
		input = source.Reader
	} else {
		input = r.bounded(r.source, r.wireLimit)
	}
	for i := len(r.layers) - 1; i >= 0; i-- {
		var decoder io.Reader
		var closer io.Closer
		switch r.layers[i] {
		case "identity":
			input = r.bounded(input, r.decodedLimit)
			continue
		case "gzip":
			if err := r.reserve(httpFlateWorkspace); err != nil {
				return err
			}
			compressed := httpByteInput(input)
			gz, err := gzip.NewReader(compressed)
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return err
			}
			decoder, closer, input = gz, gz, compressed
		case "deflate":
			if err := r.reserve(httpFlateWorkspace); err != nil {
				return err
			}
			compressed := httpByteInput(input)
			header := &httpDeflateHeader{input: compressed}
			z, err := zlib.NewReader(header)
			if err != nil {
				if sourceErr := r.failure(); sourceErr != nil {
					return sourceErr
				}
				z = flate.NewReader(io.MultiReader(bytes.NewReader(header.bytes[:header.n]), compressed))
			}
			decoder, closer, input = z, z, compressed
		case "br":
			first := make([]byte, 1)
			if _, err := io.ReadFull(input, first); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return err
			}
			size, err := httpBrotliWorkspace(first[0])
			if err != nil {
				return err
			}
			if err := r.reserve(size); err != nil {
				return err
			}
			// Brotli buffers its input itself.
			decoder = brotli.NewReader(io.MultiReader(bytes.NewReader(first), input))
		}
		if closer != nil {
			r.closers = append(r.closers, closer)
		}
		input = r.bounded(&httpDecodedReader{decoder: decoder, input: input}, r.decodedLimit)
	}
	if len(r.layers) == 0 {
		input = r.bounded(input, r.decodedLimit)
	}
	r.reader = input
	return r.failure()
}

func (r *httpReader) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func() {
		if err != nil {
			r.terminal = err
			r.release()
		}
	}()
	if err := r.codec.ctx.Err(); err != nil {
		_ = r.closeSource()
		return 0, err
	}
	if r.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if r.terminal != nil {
		return 0, r.terminal
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.reader == nil {
		if err := r.initialize(); err != nil {
			if sourceErr := r.failure(); sourceErr != nil {
				err = sourceErr
			}
			return 0, err
		}
	}
	n, err = r.reader.Read(p)
	if sourceErr := r.failure(); sourceErr != nil {
		err = sourceErr
	}
	return n, err
}

type httpBoundedReader struct {
	reader    io.Reader
	remaining int64
	err       error
}

func (r *httpBoundedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 && (err == nil || err == io.EOF) {
			err = membuffer.ErrTooLarge
		}
		r.err = err
		return 0, err
	}
	p = p[:min(int64(len(p)), r.remaining)]
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	r.err = err
	return n, err
}

// Flate decoders read byte-wise from an io.ByteReader; buffering above a bound
// lets it and its context check see chunks instead of single bytes.
func httpByteInput(input io.Reader) flate.Reader {
	if reader, ok := input.(flate.Reader); ok {
		return reader
	}
	return bufio.NewReader(input)
}

type httpDeflateHeader struct {
	input flate.Reader
	bytes [6]byte
	n     int
}

func (r *httpDeflateHeader) Read(p []byte) (int, error) {
	n, err := r.input.Read(p)
	r.n += copy(r.bytes[r.n:], p[:n])
	return n, err
}

func (r *httpDeflateHeader) ReadByte() (byte, error) {
	b, err := r.input.ReadByte()
	if err == nil && r.n < len(r.bytes) {
		r.bytes[r.n] = b
		r.n++
	}
	return b, err
}

type httpDecodedReader struct {
	decoder io.Reader
	input   io.Reader
	done    bool
}

func (r *httpDecodedReader) Read(p []byte) (int, error) {
	if !r.done {
		n, err := r.decoder.Read(p)
		if err != io.EOF {
			return n, err
		}
		r.done = true
		if n > 0 {
			return n, nil
		}
	}
	for {
		_, err := r.input.Read(p)
		if err != nil {
			return 0, err
		}
	}
}

func httpBrotliWorkspace(first byte) (int64, error) {
	bits := uint(16)
	if first&1 != 0 {
		n := uint(first >> 1 & 7)
		if n != 0 {
			bits = 17 + n
		} else {
			n = uint(first >> 4 & 7)
			if n == 1 {
				return 0, fmt.Errorf("%w: Brotli Large Window", ErrUnsupported)
			}
			bits = 17
			if n != 0 {
				bits = 8 + n
			}
		}
	}
	return 2*(int64(1)<<bits) + (2 << 20), nil
}
