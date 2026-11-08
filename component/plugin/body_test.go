// SPDX-License-Identifier: AGPL-3.0-only
package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

type countedBody struct {
	io.Reader
	reads, closes int
}

func (b *countedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.reads += n
	return n, err
}
func (b *countedBody) Close() error { b.closes++; return nil }

func TestBodyRejectsReplacingPartialOrUpgradedResponse(t *testing.T) {
	for _, status := range []int{http.StatusPartialContent, http.StatusSwitchingProtocols} {
		for _, transform := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/transform=%t", status, transform), func(t *testing.T) {
				budget := membuffer.NewBudget(4096)
				original := &countedBody{Reader: strings.NewReader("partial")}
				header := http.Header{"Content-Range": {"bytes 0-6/5000"}, "Content-Length": {"7"}, "Etag": {`"original"`}}
				r := NewResponse(&http.Response{StatusCode: status, Header: header.Clone(), Body: original, ContentLength: 7}, budget)
				defer r.Close()
				r.SetDelivery(DeliveryStreaming)
				var err error
				if transform {
					err = r.Body().Transform(func(io.ReadCloser) (io.ReadCloser, error) {
						t.Error("transform was installed")
						return nil, nil
					})
				} else {
					view, copyErr := membuffer.Copy([]byte("replacement"), budget)
					if copyErr != nil {
						t.Fatal(copyErr)
					}
					err = r.Body().Replace(view)
					view.Close()
				}
				if err == nil {
					t.Fatal("body was replaced")
				}
				wire, delivery, err := r.TakeHTTP()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(wire.Body)
				_ = wire.Body.Close()
				if err != nil || string(data) != "partial" || original.closes != 1 || delivery != DeliveryStreaming || wire.ContentLength != 7 || !reflect.DeepEqual(wire.Header, header) {
					t.Fatalf("body=%q err=%v closes=%d delivery=%v length=%d header=%v", data, err, original.closes, delivery, wire.ContentLength, wire.Header)
				}
			})
		}
	}
}

func TestBodySnapshotReplay(t *testing.T) {
	for _, data := range []string{"", "12345678", "1234567890123456"} {
		original := &countedBody{Reader: strings.NewReader(data)}
		var body io.ReadCloser = original
		snapshot, err := snapshotBody(&body, 8, membuffer.NewBudget(1<<20))
		if len(data) > 8 {
			if !errors.Is(err, membuffer.ErrTooLarge) {
				t.Fatalf("overflow: %v", err)
			}
		} else if err != nil || string(snapshot.Bytes()) != data {
			t.Fatalf("snapshot: %v", err)
		}
		snapshot.Close()
		if original.reads > 9 || original.closes != 0 {
			t.Fatal("unbounded read or premature close")
		}
		replay, err := io.ReadAll(body)
		if err != nil || string(replay) != data {
			t.Fatalf("replay %q: %v", replay, err)
		}
		body.Close()
		if original.closes != 1 {
			t.Fatalf("close count %d", original.closes)
		}
	}
}

type onceReadError struct{ done bool }

func (r *onceReadError) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, "partial"), io.ErrUnexpectedEOF
}
func TestSnapshotPreservesReadError(t *testing.T) {
	original := &countedBody{Reader: &onceReadError{}}
	var body io.ReadCloser = original
	if _, err := snapshotBody(&body, 32, membuffer.NewBudget(1<<20)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	replay, err := io.ReadAll(body)
	if string(replay) != "partial" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("hidden read error: %q %v", replay, err)
	}
	body.Close()
	if original.closes != 1 {
		t.Fatal("leaked original body")
	}
}
func TestSnapshotInvalidLimitAndRepeatedReads(t *testing.T) {
	original := &countedBody{Reader: strings.NewReader("abc")}
	var body io.ReadCloser = original
	for _, limit := range []int64{-1, 0, math.MaxInt64} {
		if _, err := snapshotBody(&body, limit, membuffer.NewBudget(1<<20)); err == nil || body != original || original.reads != 0 {
			t.Fatal("invalid limit consumed body")
		}
	}
	for range 2 {
		raw, err := snapshotBody(&body, 8, membuffer.NewBudget(1<<20))
		if err != nil || string(raw.Bytes()) != "abc" {
			t.Fatalf("repeat: %v", err)
		}
		raw.Close()
	}
	body.Close()
	if original.closes != 1 {
		t.Fatal("repeated snapshot leaked body")
	}
}

func TestReplaceBodyMetadataAndTrailers(t *testing.T) {
	for _, withTrailers := range []bool{false, true} {
		original := &countedBody{Reader: strings.NewReader("old")}
		response := &http.Response{StatusCode: http.StatusOK, Body: original, Header: make(http.Header), TransferEncoding: []string{"chunked"}}
		for _, key := range []string{"Content-Encoding", "Content-MD5", "Content-Digest", "Repr-Digest", "ETag", "Content-Length", "Trailer"} {
			response.Header.Set(key, "old")
		}
		if withTrailers {
			response.Trailer = make(http.Header)
			response.Trailer.Set("Grpc-Status", "0")
			response.Trailer.Set("Content-Digest", "old")
		}
		view, err := membuffer.Copy([]byte("new bytes"), membuffer.NewBudget(1<<20))
		if err != nil {
			t.Fatal(err)
		}
		managed := NewResponse(response, view.Budget())
		managed.Body().Replace(view)
		response, _, err = managed.TakeHTTP()
		if err != nil {
			t.Fatal(err)
		}
		view.Close()
		if original.closes != 1 || len(response.TransferEncoding) != 0 {
			t.Fatal("ownership/framing not updated")
		}
		for _, key := range []string{"Content-Encoding", "Content-MD5", "Content-Digest", "Repr-Digest", "ETag", "Trailer"} {
			if response.Header.Get(key) != "" || response.Trailer.Get(key) != "" {
				t.Fatalf("stale %s", key)
			}
		}
		if withTrailers {
			if response.ContentLength != -1 || response.Header.Get("Content-Length") != "" || response.Trailer.Get("Grpc-Status") != "0" {
				t.Fatal("lost trailers or invalid framing")
			}
		} else if response.ContentLength != 9 || response.Header.Get("Content-Length") != "9" {
			t.Fatal("wrong length")
		}
		got, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(got) != "new bytes" {
			t.Fatal(string(got))
		}
	}
	request := &http.Request{}
	view, err := membuffer.Copy([]byte("retry"), membuffer.NewBudget(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	managed := NewRequest(request, view.Budget())
	managed.Body().Replace(view)
	request, err = managed.Forward()
	if err != nil {
		t.Fatal(err)
	}
	view.Close()
	got, err := io.ReadAll(request.Body)
	if err != nil || !bytes.Equal(got, []byte("retry")) {
		t.Fatalf("body=%q err=%v", got, err)
	}
	request.Body.Close()
}
