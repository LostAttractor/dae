// SPDX-License-Identifier: AGPL-3.0-only

package membuffer

import (
	"errors"
	"sync"
	"testing"
)

func TestBudgetLimitRegistrationAndConcurrentAdmission(t *testing.T) {
	budget := NewBudget(100)
	old := budget.UseLimit(200)
	held, _ := budget.Reserve(150)
	candidate := budget.UseLimit(80)
	if _, err := budget.Reserve(1); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatal("lowered limit admitted more")
	}
	candidate.Close() // Withdrawing a registration restores the other limit.
	if budget.Status().Limit != 200 {
		t.Fatal("candidate limit leaked")
	}
	held.Close()
	old.Close()
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() {
			for range 100 {
				r, err := budget.Reserve(40)
				if err == nil {
					r.Close()
					r.Close()
				}
			}
		})
	}
	workers.Wait()
	if budget.Status().Used != 0 || budget.Status().Limit != 100 {
		t.Fatal(budget.Status())
	}
}

func TestBufferFailedGrowthPreservesPreviousOutput(t *testing.T) {
	budget := NewBudget(8192)
	w := &Buffer{Budget: budget, Limit: 1 << 20}
	if _, err := w.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte{1}); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatal(err)
	}
	if w.Len() != 4096 || budget.Status().Used != 4096 {
		t.Fatal("failed write changed output")
	}
	w.Close()
	if budget.Status().Used != 0 {
		t.Fatal("writer leaked")
	}
}
