// SPDX-License-Identifier: AGPL-3.0-only

package membuffer_test

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestIndependentBudgetsAndExplicitSelection(t *testing.T) {
	a, b := membuffer.NewBudget(64), membuffer.NewBudget(64)
	held, _ := a.Reserve(64)
	defer held.Close()
	source := strings.NewReader("abc")
	view, err := membuffer.Read(source, 8, nil)
	if !errors.Is(err, membuffer.ErrBudgetRequired) || view != nil || source.Len() != 3 {
		t.Fatal("read without a budget")
	}
	writer := membuffer.Buffer{Limit: 8}
	if _, err := writer.Write([]byte("abc")); !errors.Is(err, membuffer.ErrBudgetRequired) {
		t.Fatal(err)
	}
	view, err = membuffer.Read(source, 8, b)
	if err != nil || view.Budget() != b || string(view.Bytes()) != "abc" {
		t.Fatalf("budgets interfered: %v", err)
	}
	view.Close()
	if a.Status().Used != 64 || b.Status().Used != 0 {
		t.Fatal("released the wrong budget")
	}
	view, err = membuffer.Read(strings.NewReader(""), 8, b)
	if err != nil || view.Budget() != b || view.Bytes() == nil || b.Status().Used != 0 {
		t.Fatal("empty read lost budget or retained allocation")
	}
	view.Close()
	for _, limit := range []int64{0, -1, math.MaxInt64} {
		view, err = membuffer.Read(strings.NewReader("abc"), limit, b)
		if !errors.Is(err, membuffer.ErrInvalidLimit) || view != nil {
			t.Fatal("invalid read limit")
		}
	}
}

func TestViewsReadersAndBufferReuseHaveIndependentLifetimes(t *testing.T) {
	budget := membuffer.NewBudget(1024)
	writer := membuffer.Buffer{Budget: budget, Limit: 64}
	_, _ = writer.Write([]byte("original"))
	first := writer.View()
	clone := first.Clone()
	reader := first.Open()
	borrow := reader.Snapshot()
	if borrow == nil || &borrow.Bytes()[0] != &first.Bytes()[0] || &clone.Bytes()[0] != &first.Bytes()[0] {
		t.Fatal("copied shared storage")
	}
	borrow.Close()
	first.Close()
	_, _ = writer.Write([]byte("replacement"))
	second := writer.View()
	writer.Close()
	second.Close()
	if string(clone.Bytes()) != "original" {
		t.Fatal("buffer reuse changed shared data")
	}
	var prefix [2]byte
	if n, err := reader.Read(prefix[:]); n != 2 || err != nil || string(prefix[:]) != "or" {
		t.Fatal("cursor read")
	}
	if view := reader.Snapshot(); view != nil {
		view.Close()
		t.Fatal("snapshotted a partially consumed cursor")
	}
	clone.Close()
	if budget.Status().Used != 64 {
		t.Fatal("released an open cursor")
	}
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "iginal" || budget.Status().Used != 0 {
		t.Fatal("EOF did not release the last owner")
	}
	_ = reader.Close()
	_ = reader.Close()
	if _, err := reader.Read(prefix[:]); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestReadAndWriteGrowthChargeTheSameCapacities(t *testing.T) {
	for _, capacity := range []int64{1000, 1536} {
		for _, read := range []bool{true, false} {
			budget := membuffer.NewBudget(capacity)
			data := bytes.Repeat([]byte{'a'}, 513)
			var view *membuffer.View
			var err error
			if read {
				view, err = membuffer.Read(bytes.NewReader(data), 2048, budget)
			} else {
				writer := membuffer.Buffer{Budget: budget, Limit: 2048}
				if _, err := writer.Write(data[:512]); err != nil {
					t.Fatal(err)
				}
				_, err = writer.Write(data[512:])
				view = writer.View()
				writer.Close()
			}
			wantLength, wantCapacity, wantPeak := 513, int64(1024), int64(1536)
			if capacity == 1000 {
				wantLength, wantCapacity, wantPeak = 512, 512, 512
				if !errors.Is(err, membuffer.ErrBudgetExhausted) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(view.Bytes(), data[:wantLength]) || budget.Status().Used != wantCapacity || budget.Status().Peak != wantPeak {
				t.Fatalf("read=%v budget=%+v", read, budget.Status())
			}
			view.Close()
			if budget.Status().Used != 0 {
				t.Fatal("allocation leaked")
			}
		}
	}
}

type failedRead struct{}

func (failedRead) Read(p []byte) (int, error) { return copy(p, "partial"), io.ErrUnexpectedEOF }

func TestReadReturnsConsumedPrefixWithOriginalError(t *testing.T) {
	budget := membuffer.NewBudget(1024)
	for _, limit := range []int64{4, 32} {
		view, err := membuffer.Read(failedRead{}, limit, budget)
		if !errors.Is(err, io.ErrUnexpectedEOF) || string(view.Bytes()) != "partial"[:min(7, limit+1)] {
			t.Fatalf("lost read error or prefix: %q %v", view.Bytes(), err)
		}
		view.Close()
	}
	view, err := membuffer.Read(strings.NewReader("oversize"), 4, budget)
	if !errors.Is(err, membuffer.ErrTooLarge) || string(view.Bytes()) != "overs" {
		t.Fatal("overflow did not retain the lookahead byte")
	}
	view.Close()
	if budget.Status().Used != 0 {
		t.Fatal("error path leaked")
	}
}

func TestReaderCloseConcurrentWithRead(t *testing.T) {
	budget := membuffer.NewBudget(1 << 20)
	view, err := membuffer.Read(strings.NewReader(strings.Repeat("x", 4096)), 8192, budget)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 32 {
		reader := view.Open()
		workers.Go(func() { _, _ = io.Copy(io.Discard, reader) })
		workers.Go(func() { _ = reader.Close() })
	}
	view.Close()
	workers.Wait()
	if budget.Status().Used != 0 {
		t.Fatal(budget.Status())
	}
}
