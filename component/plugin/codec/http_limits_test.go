// SPDX-License-Identifier: AGPL-3.0-only

package codec

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestHTTPEncodingLayerLimit(t *testing.T) {
	c, budget := httpTestCodec(t, t.Context(), 256<<20, Limits{Wire: 4096, Decoded: 4096})
	encoding := strings.Repeat("gzip,", maxHTTPLayers+1)
	source := &httpSpySource{Reader: strings.NewReader("unread")}
	if _, err := c.HTTPReader(source, encoding); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("reader accepted too many layers: %v", err)
	}
	if source.reads.Load() != 0 || source.closes.Load() != 0 || budget.Status().Used != 0 {
		t.Fatal("rejected reader consumed source or memory")
	}
	view, err := membuffer.Copy([]byte("unread"), budget)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := c.HTTPView(view, encoding)
	decoded.Close()
	if !errors.Is(err, ErrUnsupported) || budget.Status().Used != 0 {
		t.Fatalf("view rejection: %v, budget=%+v", err, budget.Status())
	}

	layers := make([]string, maxHTTPLayers)
	for i := range layers {
		layers[i] = "gzip"
	}
	raw := httpFixture(t, []byte("payload"), layers...)
	encoding = strings.Repeat("identity,", 1000) + strings.Join(layers, ",identity,")
	r, err := c.HTTPReader(io.NopCloser(bytes.NewReader(raw)), encoding)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || string(got) != "payload" {
		t.Fatalf("boundary failed: %q, %v", got, err)
	}
}

func TestHTTPReaderCombinedWorkspaceLimit(t *testing.T) {
	raw := []byte("small payload")
	for range 2 {
		var out bytes.Buffer
		w := brotli.NewWriterOptions(&out, brotli.WriterOptions{Quality: 5, LGWin: 24})
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		raw = out.Bytes()
	}
	c, budget := httpTestCodec(t, t.Context(), 256<<20, Limits{Wire: 4096, Decoded: 4096})
	r, err := c.HTTPReader(io.NopCloser(bytes.NewReader(raw)), "br,br")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(r)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("accepted oversized decoder stack: %v", err)
	}
	if status := budget.Status(); status.Used != 0 || status.Peak > maxHTTPWorkspace || status.Denied != 0 {
		t.Fatalf("decoder stack affected shared budget: %+v", status)
	}
	_ = r.Close()

	// View decoding releases each decoder before starting the next layer.
	view, err := membuffer.Copy(raw, budget)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := c.HTTPView(view, "br,br")
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if string(decoded.Bytes()) != "small payload" {
		t.Fatalf("decoded %q", decoded.Bytes())
	}
}
