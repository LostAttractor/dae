// SPDX-License-Identifier: AGPL-3.0-only
package plugin

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/http"
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

func TestBodySnapshotReplay(t *testing.T) {
	for _, data := range []string{"", "12345678", "1234567890123456"} {
		original := &countedBody{Reader: strings.NewReader(data)}
		var body io.ReadCloser = original
		snapshot, err := SnapshotBody(&body, 8, BodyMemory)
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
	if _, err := SnapshotBody(&body, 32, BodyMemory); !errors.Is(err, io.ErrUnexpectedEOF) {
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
		if _, err := SnapshotBody(&body, limit, BodyMemory); err == nil || body != original || original.reads != 0 {
			t.Fatal("invalid limit consumed body")
		}
	}
	for range 2 {
		raw, err := SnapshotBody(&body, 8, BodyMemory)
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
		response := &http.Response{Body: original, Header: make(http.Header), TransferEncoding: []string{"chunked"}}
		for _, key := range []string{"Content-Encoding", "Content-MD5", "Content-Digest", "Repr-Digest", "ETag", "Content-Length", "Trailer"} {
			response.Header.Set(key, "old")
		}
		if withTrailers {
			response.Trailer = make(http.Header)
			response.Trailer.Set("Grpc-Status", "0")
			response.Trailer.Set("Content-Digest", "old")
		}
		view, err := membuffer.Copy([]byte("new bytes"), BodyMemory)
		if err != nil {
			t.Fatal(err)
		}
		SetResponseBody(response, view)
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
	view, err := membuffer.Copy([]byte("retry"), BodyMemory)
	if err != nil {
		t.Fatal(err)
	}
	SetRequestBody(request, view)
	view.Close()
	got, err := io.ReadAll(request.Body)
	if err != nil || !bytes.Equal(got, []byte("retry")) {
		t.Fatalf("body=%q err=%v", got, err)
	}
	request.Body.Close()
}
