// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestMessageObserve(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		length, limit, budget int64
		readEOF, complete     bool
	}{
		{"known", 7, 32, 4096, true, true},
		{"known-without-eof", 7, 32, 4096, false, true},
		{"unknown", -1, 32, 4096, true, true},
		{"zero-is-unknown", 0, 32, 4096, true, true},
		{"early-response", -1, 32, 4096, false, false},
		{"truncated", 8, 32, 4096, true, false},
		{"exceeds-declaration", 6, 32, 4096, true, false},
		{"oversize", -1, 4, 4096, true, false},
		{"known-oversize", 7, 4, 4096, true, false},
		{"budget", -1, 32, 1, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			budget := membuffer.NewBudget(tt.budget)
			original := &countedBody{Reader: strings.NewReader("payload")}
			r := NewRequest(&http.Request{Body: original, ContentLength: tt.length}, budget)
			var result string
			calls := 0
			stop := r.Body().Observe(tt.limit, func(data []byte) { result = string(data); calls++ })
			if original.reads != 0 {
				t.Fatal("observer pre-read the body")
			}
			wire, err := r.Forward()
			if err != nil {
				t.Fatal(err)
			}
			var got []byte
			if tt.readEOF {
				got, err = io.ReadAll(wire.Body)
			} else {
				got = make([]byte, 7)
				_, err = io.ReadFull(wire.Body, got)
			}
			stop()
			stop()
			if err != nil || string(got) != "payload" || (calls == 1) != tt.complete || calls > 1 {
				t.Fatalf("body=%q error=%v callbacks=%d", got, err, calls)
			}
			if tt.complete && result != "payload" {
				t.Fatal(result)
			}
			if budget.Status().Used != 0 {
				t.Fatal("budget remains reserved after stop", budget.Status())
			}
			_ = wire.Body.Close()
			_ = r.Body().Close()
			if original.closes != 1 {
				t.Fatal("source closed more than once", original.closes)
			}
		})
	}
}

func TestMessageObservePreservesError(t *testing.T) {
	budget := membuffer.NewBudget(4096)
	original := &countedBody{Reader: &onceReadError{}}
	r := NewRequest(&http.Request{Body: original, ContentLength: -1}, budget)
	stop := r.Body().Observe(32, func([]byte) { t.Error("read error triggered the completion callback") })
	wire, err := r.Forward()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(wire.Body)
	stop()
	_ = wire.Body.Close()
	if string(got) != "partial" || !errors.Is(err, io.ErrUnexpectedEOF) || budget.Status().Used != 0 {
		t.Fatal(string(got), err, budget.Status())
	}
}

func TestMessageObserveConcurrentStopAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := membuffer.NewBudget(4096)
		reader, writer := io.Pipe()
		r := NewRequest(&http.Request{Body: reader, ContentLength: -1}, budget)
		stop := r.Body().Observe(64, func([]byte) { t.Error("incomplete upload triggered the completion callback") })
		wire, err := r.Forward()
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Go(func() { _, _ = io.Copy(io.Discard, wire.Body) })
		if _, err := writer.Write([]byte("prefix")); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if budget.Status().Used == 0 {
			t.Fatal("prefix was not captured")
		}
		stop()
		if budget.Status().Used != 0 {
			t.Fatal("stop waited for the upload or failed to release the budget")
		}
		if _, err := writer.Write([]byte("tail")); err != nil {
			t.Fatal("stop closed the upload", err)
		}
		_ = r.Body().Close()
		wg.Wait()
		_ = writer.Close()
		if budget.Status().Used != 0 {
			t.Fatal("capture resumed after stop")
		}
	})
}

func TestMessageObserveStopSynchronizesCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := membuffer.NewBudget(4096)
		r := NewRequest(&http.Request{Body: io.NopCloser(strings.NewReader("x")), ContentLength: 1}, budget)
		entered, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
		value := ""
		stop := r.Body().Observe(8, func(data []byte) { close(entered); <-release; value = string(data) })
		wire, err := r.Forward()
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Go(func() { _, _ = io.Copy(io.Discard, wire.Body) })
		<-entered
		starting := make(chan struct{})
		wg.Go(func() { close(starting); stop(); close(stopped) })
		<-starting
		select {
		case <-stopped:
			t.Fatal("stop returned before the callback completed")
		default:
		}
		close(release)
		<-stopped
		if value != "x" {
			t.Fatal("callback result is not visible after stop returns")
		}
		wg.Wait()
		_ = wire.Body.Close()
		if budget.Status().Used != 0 {
			t.Fatal(budget.Status())
		}
	})
}

type messageUpgradeBody struct {
	countedBody
	written    strings.Builder
	halfCloses int
}

func (b *messageUpgradeBody) Write(p []byte) (int, error) { return b.written.Write(p) }
func (b *messageUpgradeBody) CloseWrite() error           { b.halfCloses++; return nil }

func TestMessageObserveUpgrade(t *testing.T) {
	budget := membuffer.NewBudget(4096)
	source := new(messageUpgradeBody)
	source.Reader = strings.NewReader("server")
	response := NewResponse(&http.Response{
		StatusCode: http.StatusSwitchingProtocols, ContentLength: -1,
		Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"test"}}, Body: source,
	}, budget)
	defer response.Close()
	response.SetDelivery(DeliveryStreaming)
	stop := response.Body().Observe(64, func([]byte) { t.Error("observer processed an upgraded connection") })
	if source.reads != 0 || source.closes != 0 {
		t.Fatal("observer installation accessed the upgraded connection")
	}
	wire, delivery, err := response.TakeHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Body.Close()
	duplex, ok := wire.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("observer lost write access to the upgraded connection")
	}
	half, ok := wire.Body.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("observer lost half-close support on the upgraded connection")
	}
	if _, err := io.WriteString(duplex, "client"); err != nil {
		t.Fatal(err)
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(duplex)
	stop()
	stop()
	if err != nil || string(data) != "server" || source.written.String() != "client" || source.halfCloses != 1 {
		t.Fatal(string(data), source.written.String(), source.halfCloses, err)
	}
	if delivery != DeliveryStreaming || wire.ContentLength != -1 || wire.Header.Get("Upgrade") != "test" {
		t.Fatal("observer changed upgrade response metadata")
	}
	_ = wire.Body.Close()
	_ = response.Close()
	if source.closes != 1 || budget.Status() != (membuffer.Status{Limit: 4096}) {
		t.Fatal(source.closes, budget.Status())
	}
}

func TestMessageRepresentationOwnsDelivery(t *testing.T) {
	budget := membuffer.NewBudget(4096)
	original := &countedBody{Reader: strings.NewReader("original")}
	r := NewResponse(&http.Response{StatusCode: 200, Body: original, ContentLength: 8, Header: http.Header{"Etag": {"original"}}}, budget)
	r.SetDelivery(DeliveryStreaming)
	stop := r.Body().Observe(64, func(data []byte) {
		if string(data) != "original" {
			t.Error(string(data))
		}
	})
	view, err := r.Body().Snapshot(64)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if r.Delivery() != DeliveryStreaming || r.Head.ContentLength != 8 || r.Head.Header.Get("ETag") != "original" {
		t.Fatal("observation or snapshot changed the representation")
	}
	r.Body().Replace(view)
	view.Close()
	if r.Delivery() != DeliveryDefault || r.Head.Header.Get("ETag") != "" || original.closes != 1 {
		t.Fatal("replacement did not atomically update delivery and ownership")
	}
	wire, delivery, err := r.TakeHTTP()
	if err != nil || delivery != DeliveryDefault {
		t.Fatal(delivery, err)
	}
	data, err := io.ReadAll(wire.Body)
	_ = wire.Body.Close()
	_ = r.Close()
	if err != nil || string(data) != "original" || budget.Status().Used != 0 || original.closes != 1 {
		t.Fatal(string(data), err, budget.Status(), original.closes)
	}
	if _, _, err := r.TakeHTTP(); err == nil {
		t.Fatal("final body cursor was acquired more than once")
	}
}

func TestMessageTransformInstallationIsTransactional(t *testing.T) {
	for _, action := range []string{"error", "read", "close", "nil"} {
		t.Run(action, func(t *testing.T) {
			original := &countedBody{Reader: strings.NewReader("old")}
			r := NewResponse(&http.Response{Header: http.Header{"Etag": {"original"}}, Body: original, ContentLength: 3}, membuffer.NewBudget(4096))
			r.SetDelivery(DeliveryStreaming)
			err := r.Body().Transform(func(input io.ReadCloser) (io.ReadCloser, error) {
				switch action {
				case "read":
					_, _ = input.Read(make([]byte, 1))
					return input, nil
				case "close":
					_ = input.Close()
					return input, nil
				case "nil":
					return nil, nil
				default:
					return nil, errors.New("install failed")
				}
			})
			if err == nil || original.reads != 0 || original.closes != 0 || r.Delivery() != DeliveryStreaming || r.Head.ContentLength != 3 || r.Head.Header.Get("ETag") != "original" {
				t.Fatal("failed installation changed the original representation", err)
			}
			_ = r.Close()
		})
	}
}

type lateTrailerBody struct {
	io.Reader
	finish func()
}

func (b *lateTrailerBody) Read(dst []byte) (int, error) {
	n, err := b.Reader.Read(dst)
	if err == io.EOF {
		b.finish()
	}
	return n, err
}
func (b *lateTrailerBody) Close() error { return nil }

func TestMessageTransformPublishesFinalTrailers(t *testing.T) {
	raw := &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: 3, Trailer: http.Header{"Grpc-Status": nil}}
	raw.Body = &lateTrailerBody{Reader: strings.NewReader("old"), finish: func() {
		raw.Trailer = http.Header{"Grpc-Status": {"0"}, "Etag": {"stale"}, "Content-Digest": {"stale"}}
	}}
	r := NewResponse(raw, membuffer.NewBudget(4096))
	r.SetDelivery(DeliveryStreaming)
	if err := r.Body().Transform(func(source io.ReadCloser) (io.ReadCloser, error) { return source, nil }); err != nil {
		t.Fatal(err)
	}
	if r.Head.ContentLength != -1 || r.Delivery() != DeliveryDefault {
		t.Fatal("transform inherited the old representation metadata")
	}
	r.SetDelivery(DeliveryStreaming)
	wire, mode, err := r.TakeHTTP()
	if err != nil || mode != DeliveryStreaming {
		t.Fatal(mode, err)
	}
	_, err = io.Copy(io.Discard, wire.Body)
	_ = wire.Body.Close()
	if err != nil || wire.Trailer.Get("Grpc-Status") != "0" || wire.Trailer.Get("ETag") != "" || wire.Trailer.Get("Content-Digest") != "" {
		t.Fatal("final trailers were not synchronized or sanitized", wire.Trailer, err)
	}
}

func TestMessageRejectsNativeBodyMutation(t *testing.T) {
	request := NewRequest(&http.Request{}, membuffer.NewBudget(4096))
	request.Head.Body = http.NoBody
	if _, err := request.Forward(); err == nil {
		t.Fatal("Head.Body mutation was silently ignored")
	}
	response := NewResponse(&http.Response{Header: make(http.Header), Body: http.NoBody}, membuffer.NewBudget(4096))
	response.Head = &http.Response{Header: make(http.Header), Body: http.NoBody}
	if _, _, err := response.TakeHTTP(); err == nil {
		t.Fatal("replacing the Head pointer was allowed")
	}
}
