// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestSnapshotCancellationDoesNotPublishReplay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := membuffer.NewBudget(4096)
		reader, writer := io.Pipe()
		r := NewRequest(&http.Request{Body: reader, ContentLength: -1}, budget)
		finished := make(chan error, 1)
		go func() {
			view, err := r.Body().Snapshot(64)
			if view != nil {
				view.Close()
				t.Error("snapshot returned after Close")
			}
			finished <- err
		}()
		if _, err := writer.Write([]byte("prefix")); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := r.Body().Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-finished; !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
		_ = writer.Close()
		_ = r.Body().Close()
		if budget.Status().Used != 0 {
			t.Fatal("replay buffer leaked after cancellation", budget.Status())
		}
		if _, err := r.Forward(); err == nil {
			t.Fatal("closed request published a new body cursor")
		}
	})
}

func TestObserveEmptyAndInvalidLimits(t *testing.T) {
	for _, tt := range []struct {
		length, limit int64
		want          int
	}{
		{0, 1, 1}, {-1, 1, 1}, {1, 2, 0}, {0, 0, 0}, {0, -1, 0}, {0, int64(math.MaxInt), 0},
	} {
		r := NewRequest(&http.Request{Body: http.NoBody, ContentLength: tt.length}, nil)
		calls := 0
		stop := r.Body().Observe(tt.limit, func([]byte) { calls++ })
		stop()
		_ = r.Body().Close()
		if calls != tt.want {
			t.Fatalf("%+v: %d", tt, calls)
		}
	}
}

func TestObservePanicReleasesBudget(t *testing.T) {
	budget := membuffer.NewBudget(4096)
	r := NewRequest(&http.Request{Body: io.NopCloser(strings.NewReader("x")), ContentLength: 1}, budget)
	stop := r.Body().Observe(8, func([]byte) { panic("fixture") })
	wire, err := r.Forward()
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() != "fixture" {
				t.Error("callback was not invoked")
			}
		}()
		_, _ = wire.Body.Read(make([]byte, 1))
	}()
	stop()
	_ = r.Body().Close()
	if budget.Status().Used != 0 {
		t.Fatal(budget.Status())
	}
}

type eofDataBody struct {
	finish func()
	done   bool
}

func (b *eofDataBody) Read(dst []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	b.done = true
	b.finish()
	return copy(dst, "x"), io.EOF
}
func (b *eofDataBody) Close() error { b.finish(); return nil }

func TestResponseTrailerPublicationRequiresEOF(t *testing.T) {
	for _, read := range []bool{true, false} {
		raw := &http.Response{StatusCode: 200, Header: make(http.Header), Trailer: http.Header{"Grpc-Status": nil}}
		raw.Body = &eofDataBody{finish: func() { raw.Trailer = http.Header{"Grpc-Status": {"0"}} }}
		r := NewResponse(raw, nil)
		wire, _, err := r.TakeHTTP()
		if err != nil {
			t.Fatal(err)
		}
		if read {
			n, err := wire.Body.Read(make([]byte, 1))
			if n != 1 || err != io.EOF || wire.Trailer.Get("Grpc-Status") != "0" {
				t.Fatal(n, err, wire.Trailer)
			}
		}
		_ = wire.Body.Close()
		if !read && wire.Trailer.Get("Grpc-Status") != "" {
			t.Fatal("Close published trailers without observing EOF")
		}
	}
}
