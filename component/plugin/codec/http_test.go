// SPDX-License-Identifier: AGPL-3.0-only

package codec

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/andybalholm/brotli"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func httpFixture(t testing.TB, raw []byte, layers ...string) []byte {
	t.Helper()
	for _, layer := range layers {
		var out bytes.Buffer
		var w io.WriteCloser
		switch layer {
		case "gzip":
			w = gzip.NewWriter(&out)
		case "deflate":
			w = zlib.NewWriter(&out)
		case "raw":
			var err error
			w, err = flate.NewWriter(&out, flate.DefaultCompression)
			if err != nil {
				t.Fatal(err)
			}
		case "br":
			w = brotli.NewWriter(&out)
		default:
			t.Fatalf("unknown fixture %q", layer)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		raw = out.Bytes()
	}
	return raw
}

func httpTestCodec(t testing.TB, ctx context.Context, memory int64, limits Limits) (*Codec, *membuffer.Budget) {
	t.Helper()
	budget := membuffer.NewBudget(memory)
	c, err := New(ctx, budget, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if status := budget.Status(); status.Used != 0 {
			t.Errorf("leaked memory: %+v", status)
		}
	})
	return c, budget
}

func TestHTTPFormats(t *testing.T) {
	plain := []byte(strings.Repeat("按需解码", 200))
	for _, test := range []struct {
		encoding string
		layers   []string
	}{
		{"", nil}, {"identity", nil}, {"gzip", []string{"gzip"}},
		{"deflate", []string{"deflate"}}, {"deflate", []string{"raw"}},
		{"br", []string{"br"}}, {" GZip , identity, BR ", []string{"gzip", "br"}},
		{"deflate,gzip,br", []string{"raw", "gzip", "br"}},
	} {
		t.Run(strings.Join(test.layers, "+")+test.encoding, func(t *testing.T) {
			raw := httpFixture(t, plain, test.layers...)
			c, budget := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 8192, Decoded: 8192})
			view, err := membuffer.Copy(raw, budget)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := c.HTTPView(view, test.encoding)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded.Bytes(), plain) {
				t.Fatal("view changed decoded bytes")
			}
			decoded.Close()
			r, err := c.HTTPReader(io.NopCloser(bytes.NewReader(raw)), test.encoding)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			_ = r.Close()
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("reader decoded %q: %v", got, err)
			}
		})
	}
}

func TestHTTPViewOwnership(t *testing.T) {
	t.Run("identity", func(t *testing.T) {
		c, budget := httpTestCodec(t, t.Context(), 3, Limits{Wire: 3, Decoded: 3})
		view, err := membuffer.Copy([]byte("abc"), budget)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.HTTPView(view, "identity")
		if err != nil || got != view || budget.Status().Peak != 3 {
			t.Fatalf("identity copied: got=%p input=%p err=%v budget=%+v", got, view, err, budget.Status())
		}
		got.Close()
	})
	t.Run("budget mismatch", func(t *testing.T) {
		c, _ := httpTestCodec(t, t.Context(), 1024, Limits{Wire: 1024, Decoded: 1024})
		other := membuffer.NewBudget(1024)
		view, err := membuffer.Copy([]byte("abc"), other)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.HTTPView(view, "")
		got.Close()
		if !errors.Is(err, ErrBudgetMismatch) || other.Status().Used != 0 {
			t.Fatalf("error=%v other=%+v", err, other.Status())
		}
	})
	for _, encoding := range []string{"", "gzip", "deflate", "br", "unknown"} {
		t.Run("cancel "+encoding, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			c, budget := httpTestCodec(t, ctx, 1024, Limits{Wire: 1024, Decoded: 1024})
			view, err := membuffer.Copy([]byte("abc"), budget)
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			got, err := c.HTTPView(view, encoding)
			got.Close()
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPEmptyAndUnsupported(t *testing.T) {
	for _, test := range []struct {
		encoding string
		want     error
	}{
		{"", nil}, {"identity", nil}, {"gzip", io.ErrUnexpectedEOF},
		{"deflate", io.ErrUnexpectedEOF}, {"br", io.ErrUnexpectedEOF},
		{"zstd", ErrUnsupported}, {"gzip,unknown", ErrUnsupported},
	} {
		t.Run(test.encoding, func(t *testing.T) {
			c, budget := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 1024, Decoded: 1024})
			view, err := membuffer.Copy(nil, budget)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.HTTPView(view, test.encoding)
			got.Close()
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
	for _, encoding := range []string{"gzip", "deflate", "br"} {
		t.Run("encoded empty "+encoding, func(t *testing.T) {
			c, _ := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 1024, Decoded: 1024})
			raw := httpFixture(t, nil, encoding)
			view, err := c.decodeBytes(raw, encoding, 1024)
			defer view.Close()
			if err != nil || len(view.Bytes()) != 0 {
				t.Fatalf("empty error=%v", err)
			}
		})
	}
}

func TestHTTPBounds(t *testing.T) {
	plain := bytes.Repeat([]byte("x"), 1024)
	for _, encoding := range []string{"", "gzip", "deflate", "br"} {
		var layers []string
		if encoding != "" {
			layers = []string{encoding}
		}
		raw := httpFixture(t, plain, layers...)
		for _, test := range []struct {
			name   string
			limits Limits
			want   error
		}{
			{"exact", Limits{Wire: int64(len(raw)), Decoded: int64(len(plain))}, nil},
			{"wire", Limits{Wire: int64(len(raw) - 1), Decoded: 1024}, membuffer.ErrTooLarge},
			{"decoded", Limits{Wire: int64(len(raw)), Decoded: 1023}, membuffer.ErrTooLarge},
		} {
			t.Run(encoding+"/"+test.name, func(t *testing.T) {
				c, budget := httpTestCodec(t, t.Context(), 64<<20, test.limits)
				view, err := membuffer.Copy(raw, budget)
				if err != nil {
					t.Fatal(err)
				}
				got, err := c.HTTPView(view, encoding)
				got.Close()
				if !errors.Is(err, test.want) {
					t.Fatalf("view error=%v want=%v", err, test.want)
				}
				r, err := c.HTTPReader(io.NopCloser(bytes.NewReader(raw)), encoding)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := io.ReadAll(r)
				_ = r.Close()
				if !errors.Is(err, test.want) || int64(len(decoded)) > test.limits.Decoded {
					t.Fatalf("reader length=%d error=%v want=%v", len(decoded), err, test.want)
				}
			})
		}
	}
	for _, outer := range []string{"br", "identity"} {
		t.Run("intermediate "+outer, func(t *testing.T) {
			raw := httpFixture(t, []byte("x"), "gzip")
			if outer == "br" {
				raw = httpFixture(t, raw, "br")
			}
			c, budget := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 1024, Decoded: 8})
			view, err := membuffer.Copy(raw, budget)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.HTTPView(view, "gzip,"+outer)
			got.Close()
			if !errors.Is(err, membuffer.ErrTooLarge) {
				t.Fatalf("intermediate view limit: %v", err)
			}
			r, err := c.HTTPReader(io.NopCloser(bytes.NewReader(raw)), "gzip,"+outer)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(r)
			_ = r.Close()
			if !errors.Is(err, membuffer.ErrTooLarge) {
				t.Fatalf("intermediate reader limit: %v", err)
			}
		})
	}
}

func TestHTTPWorkspace(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate", "br"} {
		t.Run(encoding, func(t *testing.T) {
			raw := httpFixture(t, []byte("small"), encoding)
			scratch := int64(httpFlateWorkspace)
			if encoding == "br" {
				var err error
				scratch, err = httpBrotliWorkspace(raw[0])
				if err != nil {
					t.Fatal(err)
				}
			}
			c, budget := httpTestCodec(t, t.Context(), scratch-1, Limits{Wire: 1024, Decoded: 1024})
			r, err := c.HTTPReader(io.NopCloser(bytes.NewReader(raw)), encoding)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(r)
			_ = r.Close()
			if !errors.Is(err, membuffer.ErrBudgetExhausted) || budget.Status().Denied != 1 {
				t.Fatalf("scratch bypassed budget: error=%v status=%+v", err, budget.Status())
			}
		})
	}
	t.Run("large window", func(t *testing.T) {
		c, _ := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 1024, Decoded: 1024})
		view, err := c.decodeBytes([]byte{0x11}, "br", 1024)
		view.Close()
		if !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	})
}

type httpSpySource struct {
	io.Reader
	reads, closes atomic.Int32
}

func (s *httpSpySource) Read(p []byte) (int, error) {
	s.reads.Add(1)
	return s.Reader.Read(p)
}

func (s *httpSpySource) Close() error { s.closes.Add(1); return nil }

func TestHTTPReaderLazy(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "deflate", "br", "unknown"} {
		t.Run(encoding, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				c, budget := httpTestCodec(t, ctx, 64<<20, Limits{Wire: 1024, Decoded: 1024})
				source := &httpSpySource{Reader: strings.NewReader("not read")}
				r, err := c.HTTPReader(source, encoding)
				if encoding == "unknown" && !errors.Is(err, ErrUnsupported) || encoding != "unknown" && err != nil {
					t.Fatal(err)
				}
				cancel()
				synctest.Wait()
				if source.reads.Load() != 0 || source.closes.Load() != 0 || budget.Status().Used != 0 {
					t.Fatal("installation consumed input or registered cancellation")
				}
				if r != nil {
					_, err := r.Read(make([]byte, 1))
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
					_ = r.Close()
					_ = r.Close()
					if source.closes.Load() != 1 {
						t.Fatal("source closed more than once")
					}
				}
			})
		})
	}
}

type httpErrorSource struct {
	data *bytes.Reader
	err  error
}

func (s *httpErrorSource) Read(p []byte) (int, error) {
	n, err := s.data.Read(p)
	if s.data.Len() == 0 {
		err = s.err
	}
	return n, err
}

func (*httpErrorSource) Close() error { return nil }

func TestHTTPReaderStickySourceError(t *testing.T) {
	want := errors.New("source failed with final bytes")
	for _, encoding := range []string{"", "gzip", "deflate", "raw", "br", "gzip,br"} {
		t.Run(encoding, func(t *testing.T) {
			var layers []string
			if encoding != "" {
				layers = strings.Split(encoding, ",")
			}
			raw := httpFixture(t, []byte("complete payload"), layers...)
			c, _ := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 1024, Decoded: 1024})
			r, err := c.HTTPReader(&httpErrorSource{data: bytes.NewReader(raw), err: want}, strings.ReplaceAll(encoding, "raw", "deflate"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(r)
			_ = r.Close()
			if !errors.Is(err, want) {
				t.Fatalf("source error swallowed: %v", err)
			}
		})
	}
	for _, header := range [][]byte{{0x78}, {0x78, 0x9c}, {0x78, 0x20, 0, 0, 0, 0}} {
		c, _ := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 1024, Decoded: 1024})
		r, err := c.HTTPReader(&httpErrorSource{data: bytes.NewReader(header), err: want}, "deflate")
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(r)
		_ = r.Close()
		if !errors.Is(err, want) {
			t.Fatalf("deflate fallback swallowed header error: %v", err)
		}
	}
}

func TestHTTPDeflateSixByteFallback(t *testing.T) {
	plain := bytes.Repeat([]byte("x"), 32)
	raw := append([]byte{0x78, 0x20, 0x00, 0xdf, 0xff}, plain...)
	raw = append(raw, 1, 0, 0, 0xff, 0xff)
	c, _ := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 1024, Decoded: 1024})
	view, err := c.decodeBytes(raw, "deflate", 1024)
	defer view.Close()
	if err != nil || !bytes.Equal(view.Bytes(), plain) {
		t.Fatalf("six-byte replay failed: %v", err)
	}
}

func TestHTTPTruncatedAndChecksum(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate", "br", "raw"} {
		raw := httpFixture(t, []byte("complete payload"), encoding)
		for _, size := range []int{1, len(raw) - 1} {
			t.Run(encoding+" truncated", func(t *testing.T) {
				c, _ := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 1024, Decoded: 1024})
				view, err := c.decodeBytes(raw[:size], strings.ReplaceAll(encoding, "raw", "deflate"), 1024)
				view.Close()
				if err == nil || errors.Is(err, io.EOF) {
					t.Fatalf("accepted truncated content: %v", err)
				}
			})
		}
		if encoding == "gzip" || encoding == "deflate" {
			t.Run(encoding+" checksum", func(t *testing.T) {
				raw[len(raw)-1] ^= 0xff
				c, _ := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 1024, Decoded: 1024})
				view, err := c.decodeBytes(raw, encoding, 1024)
				view.Close()
				if err == nil {
					t.Fatal("accepted bad checksum")
				}
			})
		}
	}
}

type httpGatedSource struct {
	data   *bytes.Reader
	gate   chan struct{}
	closed chan struct{}
	once   sync.Once
	eof    atomic.Bool
}

func (s *httpGatedSource) Read(p []byte) (int, error) {
	if s.data.Len() != 0 {
		return s.data.Read(p)
	}
	select {
	case <-s.gate:
		s.eof.Store(true)
		return 0, io.EOF
	case <-s.closed:
		return 0, io.ErrClosedPipe
	}
}

func (s *httpGatedSource) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func TestHTTPReaderTrueEOF(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "deflate", "br", "gzip,br"} {
		t.Run(encoding, func(t *testing.T) {
			var layers []string
			if encoding != "" {
				layers = strings.Split(encoding, ",")
			}
			plain := []byte("payload before final trailer")
			raw := httpFixture(t, plain, layers...)
			synctest.Test(t, func(t *testing.T) {
				c, _ := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: int64(len(raw)), Decoded: 1024})
				source := &httpGatedSource{data: bytes.NewReader(raw), gate: make(chan struct{}), closed: make(chan struct{})}
				r, err := c.HTTPReader(source, encoding)
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					got, err := io.ReadAll(r)
					if err != nil || !bytes.Equal(got, plain) || !source.eof.Load() {
						t.Errorf("decoded=%q error=%v real EOF=%v", got, err, source.eof.Load())
					}
				}()
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("decoder EOF escaped before source EOF")
				default:
				}
				close(source.gate)
				<-done
				_ = r.Close()
			})
		})
	}
}

func TestHTTPReaderCloseAndCancel(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "deflate", "br"} {
		for _, cancelRead := range []bool{false, true} {
			t.Run(encoding+map[bool]string{false: " close", true: " cancel"}[cancelRead], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					c, budget := httpTestCodec(t, ctx, 64<<20, Limits{Wire: 1024, Decoded: 1024})
					source := &httpGatedSource{data: bytes.NewReader(nil), gate: make(chan struct{}), closed: make(chan struct{})}
					r, err := c.HTTPReader(source, encoding)
					if err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					go func() { _, err := io.ReadAll(r); done <- err }()
					synctest.Wait()
					if cancelRead {
						cancel()
					} else {
						_ = r.Close()
					}
					err = <-done
					if err == nil || cancelRead && !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
					_ = r.Close()
					synctest.Wait()
					if budget.Status().Used != 0 {
						t.Fatal(budget.Status())
					}
				})
			})
		}
	}
}

func TestHTTPReaderIdleCancellation(t *testing.T) {
	raw := httpFixture(t, bytes.Repeat([]byte("x"), 2048), "gzip")
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		c, budget := httpTestCodec(t, ctx, 64<<20, Limits{Wire: 4096, Decoded: 4096})
		source := &httpSpySource{Reader: bytes.NewReader(raw)}
		r, err := c.HTTPReader(source, "gzip")
		if err != nil {
			t.Fatal(err)
		}
		var first [1]byte
		if n, err := r.Read(first[:]); n != 1 || err != nil || budget.Status().Used == 0 {
			t.Fatalf("first read=%d error=%v budget=%+v", n, err, budget.Status())
		}
		cancel()
		synctest.Wait()
		if source.closes.Load() != 1 || budget.Status().Used != 0 {
			t.Fatalf("idle cancellation leaked: closes=%d budget=%+v", source.closes.Load(), budget.Status())
		}
		if _, err := r.Read(first[:]); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		_ = r.Close()
	})
}

func TestHTTPReaderTrailingWireBound(t *testing.T) {
	for _, encoding := range []string{"deflate", "br"} {
		t.Run(encoding, func(t *testing.T) {
			raw := httpFixture(t, []byte("plain"), encoding)
			c, _ := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: int64(len(raw)), Decoded: 1024})
			raw = append(raw, bytes.Repeat([]byte{0}, 2048)...)
			r, err := c.HTTPReader(io.NopCloser(bytes.NewReader(raw)), encoding)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			_ = r.Close()
			if !errors.Is(err, membuffer.ErrTooLarge) || !bytes.Equal(got, []byte("plain")) {
				t.Fatalf("tail was appended or unbounded: got=%q error=%v", got, err)
			}
		})
	}
}

func FuzzHTTPContent(f *testing.F) {
	for _, encoding := range []string{"gzip", "deflate", "br", "gzip,br"} {
		f.Add(httpFixture(f, []byte("small fixture"), strings.Split(encoding, ",")...), encoding)
	}
	f.Add([]byte{0x11}, "br")
	f.Add([]byte{0x78, 0x9c}, "deflate")
	f.Fuzz(func(t *testing.T, raw []byte, encoding string) {
		if len(raw) > 4096 || len(encoding) > 32 {
			t.Skip()
		}
		c, budget := httpTestCodec(t, t.Context(), 64<<20, Limits{Wire: 4096, Decoded: 4096})
		view, err := membuffer.Copy(raw, budget)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := c.HTTPView(view, encoding)
		if err == nil && len(decoded.Bytes()) > 4096 {
			t.Fatal("decoded limit bypassed")
		}
		decoded.Close()
		r, err := c.HTTPReader(io.NopCloser(bytes.NewReader(raw)), encoding)
		if err == nil {
			n, _ := io.Copy(io.Discard, r)
			_ = r.Close()
			if n > 4096 {
				t.Fatal("stream limit bypassed")
			}
		}
	})
}

func BenchmarkHTTPViewGzip(b *testing.B) {
	raw := httpFixture(b, bytes.Repeat([]byte("x"), 4096), "gzip")
	c, budget := httpTestCodec(b, b.Context(), 64<<20, Limits{Wire: 8192, Decoded: 8192})
	b.ReportAllocs()
	for b.Loop() {
		view, err := membuffer.Copy(raw, budget)
		if err != nil {
			b.Fatal(err)
		}
		decoded, err := c.HTTPView(view, "gzip")
		if err != nil {
			b.Fatal(err)
		}
		decoded.Close()
	}
}
