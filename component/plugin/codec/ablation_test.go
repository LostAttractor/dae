// SPDX-License-Identifier: AGPL-3.0-only

package codec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func ablationPayload(size int, random bool) []byte {
	p := bytes.Repeat([]byte("x"), size)
	if random {
		rng := rand.New(rand.NewPCG(1, 2))
		for i := range p {
			p[i] = byte(rng.Uint32())
		}
	}
	return p
}

func BenchmarkCodecHTTP(b *testing.B) {
	for _, random := range []bool{false, true} {
		name := map[bool]string{false: "repeated", true: "random"}[random]
		plain := ablationPayload(64<<10, random)
		wire := httpFixture(b, plain, "gzip")
		for _, snapshot := range []bool{false, true} {
			b.Run(name+map[bool]string{false: "/reader", true: "/view"}[snapshot], func(b *testing.B) {
				c, budget := grpcCodec(b, b.Context(), 16<<20, Limits{1 << 20, 1 << 20})
				input, err := membuffer.Copy(wire, budget)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(plain)))
				for b.Loop() {
					if snapshot {
						out, err := c.HTTPView(input.Clone(), "gzip")
						if err != nil || !bytes.Equal(out.Bytes(), plain) {
							b.Fatal(err)
						}
						out.Close()
					} else {
						r, err := c.HTTPReader(io.NopCloser(bytes.NewReader(wire)), "gzip")
						if err != nil {
							b.Fatal(err)
						}
						n, err := io.Copy(io.Discard, r)
						_ = r.Close()
						if err != nil || n != int64(len(plain)) {
							b.Fatal(n, err)
						}
					}
				}
				input.Close()
				if budget.Status().Used != 0 {
					b.Fatal(budget.Status())
				}
				b.ReportMetric(float64(budget.Status().Peak), "budget-peak-B")
			})
		}
	}
}

func BenchmarkCodecGRPC(b *testing.B) {
	for _, tc := range []struct {
		name       string
		compressed bool
		rewrite    bool
		decodeOnly bool
	}{
		{name: "decode", decodeOnly: true},
		{name: "passthrough"},
		{name: "rewrite", rewrite: true},
		{name: "gzip-rewrite", compressed: true, rewrite: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			c, budget := grpcCodec(b, b.Context(), 16<<20, Limits{128 << 10, 128 << 10})
			payload := ablationPayload(64<<10, false)
			wire := grpcFixture(payload, tc.compressed)
			replacement, err := membuffer.Copy(payload, budget)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				source := io.NopCloser(bytes.NewReader(wire))
				if tc.decodeOnly {
					d, err := c.GRPCDecoder(source, "gzip")
					if err != nil {
						b.Fatal(err)
					}
					m, err := d.Next()
					if err != nil || !bytes.Equal(m.Payload(), payload) {
						b.Fatal(err)
					}
					m.Close()
					if _, err := d.Next(); err != io.EOF {
						b.Fatal(err)
					}
					_ = d.Close()
				} else {
					r, err := c.GRPCTransform(source, "", "gzip", func(*Message) (*membuffer.View, error) {
						if tc.rewrite {
							return replacement.Clone(), nil
						}
						return nil, nil
					})
					if err != nil {
						b.Fatal(err)
					}
					n, err := io.Copy(io.Discard, r)
					_ = r.Close()
					if err != nil || n != int64(len(payload)+5) {
						b.Fatal(n, err)
					}
				}
			}
			replacement.Close()
			if budget.Status().Used != 0 {
				b.Fatal(budget.Status())
			}
			b.ReportMetric(float64(budget.Status().Peak), "budget-peak-B")
		})
	}
}

func BenchmarkCodecFrame(b *testing.B) {
	for _, tc := range []struct {
		name  string
		size  int
		parts int
	}{
		{"512/one", 512, 1},
		{"513/one", 513, 1},
		{"64KiB/one", 64 << 10, 1},
		{"64KiB/many", 64 << 10, 16},
	} {
		b.Run(tc.name, func(b *testing.B) {
			c, budget := grpcCodec(b, b.Context(), 1<<20, Limits{1 << 20, 1 << 20})
			payload := ablationPayload(tc.size-5, false)
			parts := make([][]byte, tc.parts)
			for i := range parts {
				parts[i] = payload[len(payload)*i/len(parts) : len(payload)*(i+1)/len(parts)]
			}
			b.ReportAllocs()
			b.SetBytes(int64(tc.size))
			for b.Loop() {
				frame, err := c.GRPCFrame(parts...)
				if err != nil || len(frame.Bytes()) != tc.size {
					b.Fatal(err)
				}
				frame.Close()
			}
			if budget.Status().Used != 0 {
				b.Fatal(budget.Status())
			}
			b.ReportMetric(float64(budget.Status().Peak), "budget-peak-B")
		})
	}
}

func TestCodecFrameExactBudget(t *testing.T) {
	for _, size := range []int{5, 512, 513, 64 << 10} {
		for _, count := range []int{1, 16} {
			c, budget := grpcCodec(t, t.Context(), int64(size), Limits{1 << 20, 1 << 20})
			payload := ablationPayload(size-5, false)
			parts := make([][]byte, count)
			for i := range parts {
				parts[i] = payload[len(payload)*i/count : len(payload)*(i+1)/count]
			}
			frame, err := c.GRPCFrame(parts...)
			if err != nil {
				t.Fatalf("known-size frame requires extra allocation: size=%d parts=%d err=%v", size, count, err)
			}
			if !bytes.Equal(frame.Bytes(), grpcFixture(payload, false)) || budget.Status().Peak != int64(size) {
				t.Fatal(size, count, budget.Status())
			}
			frame.Close()
			if budget.Status().Used != 0 {
				t.Fatal(budget.Status())
			}
		}
	}
}

func TestCodecRewriteCoexistingBudget(t *testing.T) {
	original := grpcFixture([]byte("x"), false)
	payload := ablationPayload(508, false)
	wanted := grpcFixture(payload, false)
	exact := int64(len(original) + len(payload) + len(wanted))
	for _, limit := range []int64{exact, exact - 1} {
		c, budget := grpcCodec(t, t.Context(), limit, Limits{1024, 1024})
		r, _ := c.GRPCTransform(io.NopCloser(bytes.NewReader(original)), "", "", func(*Message) (*membuffer.View, error) {
			return membuffer.Copy(payload, budget)
		})
		got, err := io.ReadAll(r)
		_ = r.Close()
		want := wanted
		if limit < exact {
			want = original
			if budget.Status().Denied == 0 {
				t.Fatal("output exceeded its shared budget")
			}
		}
		if err != nil || !bytes.Equal(got, want) || budget.Status().Used != 0 {
			t.Fatalf("coexisting representations: limit=%d bytes=%d err=%v budget=%+v", limit, len(got), err, budget.Status())
		}
	}
}

type codecOneShotError struct {
	*bytes.Reader
	err error
}

func (r *codecOneShotError) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.Len() == 0 && r.err != nil {
		err, r.err = r.err, nil
	}
	return n, err
}

func TestCodecSourceErrorAtFrameBoundary(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("x")} {
		wire := grpcFixture(payload, false)
		failure := errors.New("one-shot source failure")
		c, budget := grpcCodec(t, t.Context(), 1024, Limits{128, 128})
		source := io.NopCloser(&codecOneShotError{bytes.NewReader(wire), failure})
		calls := 0
		r, _ := c.GRPCTransform(source, "", "", func(*Message) (*membuffer.View, error) {
			calls++
			return nil, nil
		})
		got, err := io.ReadAll(r)
		_ = r.Close()
		if !errors.Is(err, failure) || calls != 0 || !bytes.Equal(got, wire) {
			t.Fatalf("source error at complete frame was lost: bytes=%x err=%v calls=%d", got, err, calls)
		}
		if budget.Status().Used != 0 {
			t.Fatal(budget.Status())
		}
	}
}

type codecEnteredSource struct {
	*httpGatedSource
	entered chan struct{}
	once    sync.Once
}

func (r *codecEnteredSource) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	return r.httpGatedSource.Read(p)
}

func TestCodecCloseUnblocksSource(t *testing.T) {
	for _, grpc := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "grpc"}[grpc], func(t *testing.T) {
			c, budget := grpcCodec(t, t.Context(), 1<<20, Limits{1024, 1024})
			source := &codecEnteredSource{
				httpGatedSource: &httpGatedSource{data: bytes.NewReader(nil), gate: make(chan struct{}), closed: make(chan struct{})},
				entered:         make(chan struct{}),
			}
			var r io.ReadCloser
			if grpc {
				r, _ = c.GRPCTransform(source, "", "", func(*Message) (*membuffer.View, error) { return nil, nil })
			} else {
				r, _ = c.HTTPReader(source, "")
			}
			var wg sync.WaitGroup
			wg.Go(func() { _, _ = io.Copy(io.Discard, r) })
			<-source.entered
			closed := make(chan struct{})
			wg.Go(func() { _ = r.Close(); close(closed) })
			completed := false
			select {
			case <-closed:
				completed = true
			case <-time.After(time.Second):
			}
			close(source.gate)
			wg.Wait()
			if !completed {
				t.Error("Close waited for Read instead of interrupting its source")
			}
			if budget.Status().Used != 0 {
				t.Fatal(budget.Status())
			}
		})
	}
}

func TestCodecFirstMessageBeforeTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, budget := grpcCodec(t, context.Background(), 1024, Limits{128, 128})
		wire := grpcFixture([]byte("first"), false)
		source := &httpGatedSource{data: bytes.NewReader(wire), gate: make(chan struct{}), closed: make(chan struct{})}
		r, _ := c.GRPCTransform(source, "", "", func(*Message) (*membuffer.View, error) { return nil, nil })
		done := make(chan []byte, 1)
		go func() {
			var buf [128]byte
			n, err := r.Read(buf[:])
			if err != nil {
				t.Error(err)
			}
			done <- buf[:n]
		}()
		synctest.Wait()
		select {
		case got := <-done:
			if !bytes.Equal(got, wire) {
				t.Errorf("first message=%x, want=%x", got, wire)
			}
		default:
			t.Error("first message waited for the tail")
		}
		close(source.gate)
		_ = r.Close()
		synctest.Wait()
		if budget.Status().Used != 0 {
			t.Fatal(budget.Status())
		}
	})
}
