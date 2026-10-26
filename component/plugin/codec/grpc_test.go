// SPDX-License-Identifier: AGPL-3.0-only

package codec

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"testing/synctest"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func grpcFixture(payload []byte, compressed bool) []byte {
	flag := byte(0)
	if compressed {
		var out bytes.Buffer
		writer := gzip.NewWriter(&out)
		_, _ = writer.Write(payload)
		_ = writer.Close()
		payload, flag = out.Bytes(), 1
	}
	frame := make([]byte, 5, 5+len(payload))
	frame[0] = flag
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	return append(frame, payload...)
}

func grpcCodec(t testing.TB, ctx context.Context, budget int64, limits Limits) (*Codec, *membuffer.Budget) {
	t.Helper()
	memory := membuffer.NewBudget(budget)
	c, err := New(ctx, memory, limits)
	if err != nil {
		t.Fatal(err)
	}
	return c, memory
}

func TestGRPCDecoderMessages(t *testing.T) {
	frames := [][]byte{grpcFixture([]byte("one"), false), grpcFixture(nil, false), grpcFixture([]byte("compressed"), true)}
	wire := bytes.Join(frames, nil)
	for _, split := range []bool{false, true} {
		t.Run(map[bool]string{false: "coalesced", true: "one-byte"}[split], func(t *testing.T) {
			c, budget := grpcCodec(t, t.Context(), 4<<20, Limits{1024, 1024})
			var source io.Reader = bytes.NewReader(wire)
			if split {
				source = iotest.OneByteReader(source)
			}
			d, err := c.GRPCDecoder(io.NopCloser(source), "gzip")
			if err != nil {
				t.Fatal(err)
			}
			for i, want := range []string{"one", "", "compressed"} {
				message, err := d.Next()
				if err != nil {
					t.Fatal(err)
				}
				if string(message.Payload()) != want || !bytes.Equal(message.Wire(), frames[i]) {
					t.Fatal(message.Payload(), message.Wire())
				}
				message.Close()
			}
			if m, err := d.Next(); m != nil || err != io.EOF {
				t.Fatal(m, err)
			}
			_ = d.Close()
			_ = d.Close()
			if budget.Status().Used != 0 {
				t.Fatal(budget.Status())
			}
		})
	}
}

func TestGRPCDecoderInvalidMessages(t *testing.T) {
	frame := grpcFixture([]byte("payload"), true)
	for _, tt := range []struct {
		name     string
		wire     []byte
		encoding string
		want     error
	}{
		{"missing-encoding", frame, "", ErrUnsupported},
		{"explicit-identity", frame, "identity", ErrUnsupported},
		{"unknown-encoding", frame, "zstd", ErrUnsupported},
		{"unknown-flag", []byte{2, 0, 0, 0, 0}, "gzip", ErrUnsupported},
		{"header-truncated", []byte{0, 0}, "", io.ErrUnexpectedEOF},
		{"payload-truncated", []byte{0, 0, 0, 0, 2, 1}, "", io.ErrUnexpectedEOF},
		{"empty-gzip", []byte{1, 0, 0, 0, 0}, "gzip", io.ErrUnexpectedEOF},
		{"length-limit", []byte{0, 255, 255, 255, 255}, "", membuffer.ErrTooLarge},
		{"identity-limit", grpcFixture(bytes.Repeat([]byte{1}, 65), false), "", membuffer.ErrTooLarge},
		{"gzip-expansion", grpcFixture(bytes.Repeat([]byte{1}, 65), true), "gzip", membuffer.ErrTooLarge},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, budget := grpcCodec(t, t.Context(), 4<<20, Limits{256, 64})
			d, _ := c.GRPCDecoder(io.NopCloser(bytes.NewReader(tt.wire)), tt.encoding)
			m, err := d.Next()
			m.Close()
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			_ = d.Close()
			if budget.Status().Used != 0 {
				t.Fatal(budget.Status())
			}
		})
	}
}

func TestGRPCDecoderReturnedMessageOwnsMemory(t *testing.T) {
	c, budget := grpcCodec(t, t.Context(), 1024, Limits{64, 64})
	d, _ := c.GRPCDecoder(io.NopCloser(bytes.NewReader(grpcFixture([]byte("x"), false))), "zstd")
	m, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if string(m.Payload()) != "x" || budget.Status().Used == 0 {
		t.Fatal(budget.Status())
	}
	m.Close()
	if budget.Status().Used != 0 {
		t.Fatal(budget.Status())
	}
}

type grpcFinalError struct {
	data []byte
	err  error
}

func (r *grpcFinalError) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}
func (*grpcFinalError) Close() error { return nil }

func TestGRPCTransformReplay(t *testing.T) {
	failure := errors.New("source failed")
	for _, tt := range []struct {
		name                 string
		wire                 []byte
		budget               int64
		wireLimit            int64
		encoding             string
		readError, wantError error
		callbackError        bool
	}{
		{"budget-before-header-copy", grpcFixture([]byte("x"), false), 4, 128, "", nil, nil, false},
		{"budget-mid-payload", grpcFixture(bytes.Repeat([]byte{1}, 1000), false), 600, 2048, "", nil, nil, false},
		{"wire-limit", grpcFixture([]byte("too long"), false), 1024, 6, "", nil, nil, false},
		{"unsupported", grpcFixture([]byte("x"), true), 1024, 128, "", nil, nil, false},
		{"flag", []byte{7, 0, 0, 0, 1, 9}, 1024, 128, "", nil, nil, false},
		{"gzip-invalid", []byte{1, 0, 0, 0, 1, 9}, 4 << 20, 128, "gzip", nil, nil, false},
		{"gzip-empty", []byte{1, 0, 0, 0, 0}, 4 << 20, 128, "gzip", nil, nil, false},
		{"callback", bytes.Repeat(grpcFixture([]byte("x"), false), 2), 1024, 128, "", nil, nil, true},
		{"header-truncated", []byte{0, 0}, 1024, 128, "", nil, io.ErrUnexpectedEOF, false},
		{"payload-truncated", []byte{0, 0, 0, 0, 2, 1}, 1024, 128, "", nil, io.ErrUnexpectedEOF, false},
		{"header-source-error", []byte{0, 0}, 1024, 128, "", failure, failure, false},
		{"frame-source-error", grpcFixture([]byte("x"), false), 1024, 128, "", failure, failure, false},
		{"empty-frame-source-error", grpcFixture(nil, false), 1024, 128, "", failure, failure, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, budget := grpcCodec(t, t.Context(), tt.budget, Limits{tt.wireLimit, 4096})
			var source io.ReadCloser = io.NopCloser(bytes.NewReader(tt.wire))
			if tt.readError != nil {
				source = &grpcFinalError{bytes.Clone(tt.wire), tt.readError}
			}
			calls := 0
			r, err := c.GRPCTransform(source, "", tt.encoding, func(*Message) (*membuffer.View, error) {
				calls++
				if tt.callbackError {
					return nil, errors.New("cannot rewrite")
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if !bytes.Equal(got, tt.wire) || !errors.Is(err, tt.wantError) {
				t.Fatalf("got %x, %v; want %x, %v", got, err, tt.wire, tt.wantError)
			}
			if tt.callbackError && calls != 1 {
				t.Fatal("remaining stream was rewritten after failure", calls)
			}
			_ = r.Close()
			if budget.Status().Used != 0 {
				t.Fatal(budget.Status())
			}
		})
	}
}

func TestGRPCTransformMixedFrames(t *testing.T) {
	first, second := grpcFixture([]byte("first"), true), grpcFixture([]byte("second"), true)
	c, budget := grpcCodec(t, t.Context(), 4<<20, Limits{128, 128})
	r, err := c.GRPCTransform(io.NopCloser(bytes.NewReader(append(bytes.Clone(first), second...))), "identity", "gzip", func(m *Message) (*membuffer.View, error) {
		if string(m.Payload()) == "first" {
			return membuffer.Copy([]byte("changed"), budget)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	want := append(grpcFixture([]byte("changed"), false), second...)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal(got, err)
	}
	_ = r.Close()
	if budget.Status().Used != 0 {
		t.Fatal(budget.Status())
	}
}

func TestGRPCTransformOutputBudgetFailure(t *testing.T) {
	original := grpcFixture([]byte("x"), false)
	c, budget := grpcCodec(t, t.Context(), 12, Limits{64, 64})
	r, _ := c.GRPCTransform(io.NopCloser(bytes.NewReader(original)), "", "", func(*Message) (*membuffer.View, error) {
		return membuffer.Copy([]byte("more"), budget)
	})
	got, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || !bytes.Equal(got, original) || budget.Status().Denied == 0 || budget.Status().Used != 0 {
		t.Fatal(got, err, budget.Status())
	}
}

func TestGRPCTransformFirstMessageDoesNotWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, budget := grpcCodec(t, t.Context(), 1024, Limits{64, 64})
		source, writer := io.Pipe()
		r, _ := c.GRPCTransform(source, "", "", func(*Message) (*membuffer.View, error) { return nil, nil })
		result := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 1024)
			n, err := r.Read(buf)
			if err != nil {
				t.Error(err)
			}
			result <- buf[:n]
		}()
		first := grpcFixture([]byte("one"), false)
		if _, err := writer.Write(first); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case got := <-result:
			if !bytes.Equal(got, first) {
				t.Fatal(got)
			}
		default:
			t.Fatal("first message waited for more input")
		}
		_ = r.Close()
		_ = writer.Close()
		if budget.Status().Used != 0 {
			t.Fatal(budget.Status())
		}
	})
}

func TestGRPCTransformCancellationAndClose(t *testing.T) {
	for _, cancelContext := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "cancel"}[cancelContext], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				c, budget := grpcCodec(t, ctx, 1024, Limits{64, 64})
				source, writer := io.Pipe()
				r, _ := c.GRPCTransform(source, "", "", func(*Message) (*membuffer.View, error) { return nil, nil })
				result := make(chan error, 1)
				go func() { _, err := io.Copy(io.Discard, r); result <- err }()
				_, _ = writer.Write([]byte{0, 0, 0, 0, 8, 1})
				synctest.Wait()
				if cancelContext {
					cancel()
				} else {
					_ = r.Close()
				}
				if err := <-result; err == nil {
					t.Fatal("cancellation was reported as normal EOF")
				}
				_ = r.Close()
				_ = writer.Close()
				if budget.Status().Used != 0 {
					t.Fatal(budget.Status())
				}
			})
		})
	}
}

func TestGRPCStreamMemoryDoesNotAccumulate(t *testing.T) {
	c, budget := grpcCodec(t, t.Context(), 64, Limits{64, 64})
	wire := bytes.Repeat(grpcFixture([]byte("x"), false), 10000)
	r, _ := c.GRPCTransform(io.NopCloser(bytes.NewReader(wire)), "", "", func(*Message) (*membuffer.View, error) { return nil, nil })
	n, err := io.Copy(io.Discard, r)
	_ = r.Close()
	if err != nil || n != int64(len(wire)) || budget.Status().Used != 0 || budget.Status().Peak > 8 {
		t.Fatal(n, err, budget.Status())
	}
}

func TestGRPCFrameAndLimits(t *testing.T) {
	c, budget := grpcCodec(t, t.Context(), 1024, Limits{8, 3})
	frame, err := c.GRPCFrame([]byte("a"), []byte("bc"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame.Bytes(), grpcFixture([]byte("abc"), false)) {
		t.Fatal(frame.Bytes())
	}
	frame.Close()
	if frame, err := c.GRPCFrame([]byte("abcd")); frame != nil || !errors.Is(err, membuffer.ErrTooLarge) {
		t.Fatal(frame, err)
	}
	if budget.Status().Used != 0 {
		t.Fatal(budget.Status())
	}
	if _, err := New(t.Context(), nil, Limits{1, 1}); !errors.Is(err, membuffer.ErrBudgetRequired) {
		t.Fatal(err)
	}
	if _, err := New(t.Context(), budget, Limits{0, 1}); !errors.Is(err, membuffer.ErrInvalidLimit) {
		t.Fatal(err)
	}
}

func FuzzGRPCPassthrough(f *testing.F) {
	f.Add(grpcFixture([]byte("seed"), false), uint16(1024))
	f.Add([]byte{0, 0}, uint16(6))
	f.Add([]byte{1, 255, 255, 255, 255}, uint16(128))
	f.Fuzz(func(t *testing.T, wire []byte, memory uint16) {
		if len(wire) > 8192 {
			t.Skip()
		}
		c, budget := grpcCodec(t, t.Context(), int64(memory)+1, Limits{4096, 4096})
		r, _ := c.GRPCTransform(io.NopCloser(bytes.NewReader(wire)), "", "", func(*Message) (*membuffer.View, error) { return nil, nil })
		got, _ := io.ReadAll(r)
		_ = r.Close()
		if !bytes.Equal(got, wire) || budget.Status().Used != 0 {
			t.Fatal(got, wire, budget.Status())
		}
	})
}

func BenchmarkGRPCMessages(b *testing.B) {
	c, budget := grpcCodec(b, b.Context(), 1<<20, Limits{4096, 4096})
	wire := bytes.Repeat(grpcFixture([]byte(strings.Repeat("x", 1024)), false), 32)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		r, _ := c.GRPCTransform(io.NopCloser(bytes.NewReader(wire)), "", "", func(*Message) (*membuffer.View, error) { return nil, nil })
		if _, err := io.Copy(io.Discard, r); err != nil {
			b.Fatal(err)
		}
		_ = r.Close()
	}
	if budget.Status().Used != 0 {
		b.Fatal(budget.Status())
	}
}
