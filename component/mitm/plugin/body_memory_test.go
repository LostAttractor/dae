// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestBodyViewSharesStorageUntilLastOwner(t *testing.T) {
	budget := membuffer.NewBudget(4096)
	var body io.ReadCloser = io.NopCloser(strings.NewReader("original"))
	a, err := SnapshotBody(&body, 64, budget)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SnapshotBody(&body, 64, budget)
	if err != nil {
		t.Fatal(err)
	}
	if &a.Bytes()[0] != &b.Bytes()[0] || budget.Status().Used != 65 {
		t.Fatalf("snapshots copied: %+v", budget.Status())
	}
	got, err := io.ReadAll(body)
	if err != nil || string(got) != "original" {
		t.Fatalf("replay %q: %v", got, err)
	}
	_ = body.Close()
	a.Close()
	if budget.Status().Used != 65 || string(b.Bytes()) != "original" {
		t.Fatal("premature release")
	}
	b.Close()
	b.Close()
	if budget.Status().Used != 0 {
		t.Fatal("leaked view")
	}
}

func TestBodyMemoryPressurePreservesUnreadTail(t *testing.T) {
	for _, size := range []int64{1, 4096, 8192} {
		budget := membuffer.NewBudget(size)
		payload := strings.Repeat("abcdef", 3000)
		original := &countedBody{Reader: strings.NewReader(payload)}
		var body io.ReadCloser = original
		_, err := SnapshotBody(&body, 1<<20, budget)
		if !errors.Is(err, membuffer.ErrBudgetExhausted) {
			t.Fatalf("budget=%d err=%v", size, err)
		}
		if budget.Status().Peak > size || size == 1 && original.reads != 0 {
			t.Fatal("read before admission")
		}
		got, err := io.ReadAll(body)
		_ = body.Close()
		if err != nil || string(got) != payload || original.closes != 1 || budget.Status().Used != 0 {
			t.Fatalf("corrupt fallback: bytes=%d err=%v closes=%d memory=%+v", len(got), err, original.closes, budget.Status())
		}
	}
}

func TestBodyViewRequestAndResponseLifetime(t *testing.T) {
	budget := membuffer.NewBudget(1024)
	view, err := membuffer.Read(strings.NewReader("retry me"), 64, budget)
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{}
	SetRequestBody(req, view)
	view.Close()
	if budget.Status().Used == 0 {
		t.Fatal("released pending request body")
	}
	got, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil || string(got) != "retry me" || budget.Status().Used != 0 {
		t.Fatal("request cursor lifetime")
	}

	view, err = membuffer.Read(strings.NewReader("response"), 64, budget)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{}
	SetResponseBody(resp, view)
	view.Close()
	if budget.Status().Used == 0 {
		t.Fatal("unaccounted output awaiting delivery")
	}
	_ = resp.Body.Close() // Client disconnects without reading.
	if budget.Status().Used != 0 {
		t.Fatal("output leaked after disconnect")
	}
}

func BenchmarkRepeatedBodySnapshot(b *testing.B) {
	payload := bytes.Repeat([]byte{'x'}, 256<<10)
	budget := membuffer.NewBudget(16 << 20)
	b.ReportAllocs()
	for b.Loop() {
		var body io.ReadCloser = io.NopCloser(bytes.NewReader(payload))
		for range 4 {
			view, err := SnapshotBody(&body, 1<<20, budget)
			if err != nil {
				b.Fatal(err)
			}
			view.Close()
		}
		_ = body.Close()
	}
	if budget.Status().Used != 0 {
		b.Fatal(budget.Status())
	}
}
