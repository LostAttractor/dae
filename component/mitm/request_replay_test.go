// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestRequestReplayPreservesRepresentationAndSharesSnapshots(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		t.Run(map[bool]string{false: "streamed", true: "snapshot"}[snapshot], func(t *testing.T) {
			budget := membuffer.NewBudget(4096)
			original := &replayCountedBody{Reader: strings.NewReader("original bytes")}
			r := &http.Request{Body: original, ContentLength: -1, TransferEncoding: []string{"chunked"},
				Header:  http.Header{"Content-Encoding": {"gzip"}, "Content-Digest": {"digest"}, "Trailer": {"X-Checksum"}},
				Trailer: http.Header{"X-Checksum": {"checksum"}}}
			metadata := r.Clone(t.Context())
			var snapshotStorage *byte
			if snapshot {
				view, err := plugin.SnapshotBody(&r.Body, 64, budget)
				if err != nil {
					t.Fatal(err)
				}
				snapshotStorage = &view.Bytes()[0]
				view.Close()
			}
			release := prepareRequestReplay(r, budget)
			defer release()
			if !snapshot && original.reads != 0 {
				t.Fatal("read the source before forwarding")
			}
			if snapshot {
				body, err := r.GetBody()
				if err != nil {
					t.Fatal(err)
				}
				view := body.(*membuffer.Reader).Snapshot()
				if &view.Bytes()[0] != snapshotStorage {
					t.Error("copied an existing snapshot")
				}
				view.Close()
				body.Close()
			}
			got, err := io.ReadAll(r.Body)
			r.Body.Close() // The failed attempt closes before the retry.
			if err != nil || string(got) != "original bytes" {
				t.Fatalf("forwarded body: %q, %v", got, err)
			}
			for range 2 {
				body, err := r.GetBody()
				if err != nil {
					t.Fatal(err)
				}
				got, err = io.ReadAll(body)
				body.Close()
				if err != nil || string(got) != "original bytes" {
					t.Fatalf("retry body: %q, %v", got, err)
				}
			}
			if r.ContentLength != metadata.ContentLength || !reflect.DeepEqual(r.Header, metadata.Header) ||
				!reflect.DeepEqual(r.Trailer, metadata.Trailer) || !reflect.DeepEqual(r.TransferEncoding, metadata.TransferEncoding) {
				t.Fatal("changed body metadata")
			}
			retry, err := r.GetBody()
			if err != nil {
				t.Fatal(err)
			}
			release()
			release()
			got, err = io.ReadAll(retry)
			retry.Close()
			if err != nil || string(got) != "original bytes" || budget.Status().Used != 0 || original.closes != 1 {
				t.Fatalf("retry ownership: body=%q err=%v closes=%d budget=%+v", got, err, original.closes, budget.Status())
			}
		})
	}
}

func TestRequestReplayFallbackPreservesForwarding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		length  int64
		budget  int64
		payload string
		err     error
	}{
		{"known large", requestReplayLimit + 1, 2 << 20, strings.Repeat("a", requestReplayLimit+1), nil},
		{"unknown large", -1, 2 << 20, strings.Repeat("b", requestReplayLimit+1), membuffer.ErrTooLarge},
		{"memory pressure", -1, 1, "payload", membuffer.ErrBudgetExhausted},
		{"empty without allocation", -1, 1, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := membuffer.NewBudget(tc.budget)
			r := &http.Request{Body: io.NopCloser(strings.NewReader(tc.payload)), ContentLength: tc.length}
			release := prepareRequestReplay(r, budget)
			defer release()
			got, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || string(got) != tc.payload {
				t.Fatalf("corrupted forwarding: %q %v", got, err)
			}
			if tc.length > requestReplayLimit {
				if r.GetBody != nil || budget.Status().Peak != 0 {
					t.Fatal("buffered a known large body")
				}
			} else {
				body, err := r.GetBody()
				if !errors.Is(err, tc.err) {
					t.Fatalf("retry: %v, want %v", err, tc.err)
				}
				if body != nil {
					body.Close()
				}
			}
			release()
			if budget.Status().Used != 0 || budget.Status().Peak > tc.budget {
				t.Fatalf("unbounded recording: %+v", budget.Status())
			}
		})
	}
}

func TestRequestReplayRejectsIncompleteAndFailedUploads(t *testing.T) {
	budget := membuffer.NewBudget(4096)
	r := &http.Request{Body: io.NopCloser(io.MultiReader(strings.NewReader("prefix"), replayReadError{io.ErrUnexpectedEOF})), ContentLength: -1}
	release := prepareRequestReplay(r, budget)
	defer release()
	prefix := make([]byte, len("prefix"))
	if _, err := io.ReadFull(r.Body, prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetBody(); err == nil {
		t.Fatal("replayed an incomplete body")
	}
	got, err := io.ReadAll(r.Body)
	if len(got) != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("lost source error: %q %v", got, err)
	}
	if _, err := r.GetBody(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("replayed an incomplete upload: %v", err)
	}
	r.Body.Close()
	if budget.Status().Used != 0 {
		t.Fatal("retained failed recording")
	}
}

func TestRequestReplayBeforeUploadStarts(t *testing.T) {
	for _, retry := range []bool{false, true} {
		budget := membuffer.NewBudget(4096)
		original := &replayCountedBody{Reader: strings.NewReader("body")}
		r := &http.Request{Body: original, ContentLength: 4}
		release := prepareRequestReplay(r, budget)
		// A transport may discard its connection before reading any body.
		r.Body.Close()
		if retry {
			body, err := r.GetBody()
			if err != nil {
				t.Fatal(err)
			}
			if original.closes != 0 || original.reads != 0 {
				t.Fatal("unused attempt consumed or closed the source")
			}
			got, err := io.ReadAll(body)
			body.Close()
			if err != nil || string(got) != "body" {
				t.Fatalf("unused-body retry: %q %v", got, err)
			}
		}
		release()
		if original.closes != 1 || budget.Status().Used != 0 {
			t.Fatalf("unused-body cleanup: closes=%d memory=%+v", original.closes, budget.Status())
		}
	}
}

func TestRequestReplayCleanupDuringUpload(t *testing.T) {
	budget := membuffer.NewBudget(4096)
	source, writer := io.Pipe()
	defer writer.Close()
	r := &http.Request{Body: source, ContentLength: -1}
	release := prepareRequestReplay(r, budget)
	defer release()
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, r.Body)
		done <- err
	}()
	if _, err := io.WriteString(writer, "prefix"); err != nil {
		t.Fatal(err)
	}
	// An early response can end RoundTrip while the source is still open.
	release()
	if _, err := io.WriteString(writer, "tail"); err != nil {
		t.Fatalf("cleanup closed the upload: %v", err)
	}
	r.Body.Close() // Must unblock Read, even though recording has ended.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("body Close did not unblock Read")
	}
	if _, err := r.GetBody(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("retry after cleanup: %v", err)
	}
	if budget.Status().Used != 0 {
		t.Fatalf("upload retained memory after cleanup: %+v", budget.Status())
	}
}

type replayCountedBody struct {
	io.Reader
	reads, closes int
}

func (b *replayCountedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.reads += n
	return n, err
}
func (b *replayCountedBody) Close() error { b.closes++; return nil }

type replayReadError struct{ error }

func (r replayReadError) Read([]byte) (int, error) { return 0, r.error }

func TestReplayAdmissionDoesNotWaitForUpload(t *testing.T) {
	source, writer := io.Pipe()
	defer source.Close()
	defer writer.Close()
	r := &http.Request{Body: source, ContentLength: 1}
	done := make(chan func(), 1)
	go func() { done <- prepareRequestReplay(r, membuffer.NewBudget(1<<20)) }()
	select {
	case release := <-done:
		r.Body.Close()
		release()
	case <-time.After(50 * time.Millisecond):
		writer.Close()
		release := <-done
		r.Body.Close()
		release()
		t.Fatal("replay admission waited for upload")
	}
}
func TestReplayEarlyResponseBeforeUpload(t *testing.T) {
	source, writer := io.Pipe()
	defer source.Close()
	defer writer.Close()
	r := &http.Request{Body: source, ContentLength: 4}
	release := prepareRequestReplay(r, membuffer.NewBudget(1<<20))
	release() // RoundTrip returned response headers before its upload goroutine ran.
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(writer, "body"); writer.Close(); done <- err }()
	got, err := io.ReadAll(r.Body)
	r.Body.Close()
	writeErr := <-done
	if err != nil || writeErr != nil || string(got) != "body" {
		t.Fatalf("cleanup interrupted upload: body=%q read=%v write=%v", got, err, writeErr)
	}
}
