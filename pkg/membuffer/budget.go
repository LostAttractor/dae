// SPDX-License-Identifier: AGPL-3.0-only

// Package membuffer provides budgeted byte storage with explicit ownership.
// Budgets are supplied by callers; this package has no process-wide defaults or
// protocol-specific policies. Shared views are immutable by contract.
package membuffer

import (
	"errors"
	"sync"
)

var ErrBudgetExhausted = errors.New("buffer memory budget exhausted")

type Status struct {
	Limit  int64  `json:"limit"`
	Used   int64  `json:"used"`
	Peak   int64  `json:"peak"`
	Denied uint64 `json:"denied"`
}

type Budget struct {
	mu     sync.Mutex
	status Status
	base   int64
	limits map[*Limit]int64
}

// NewBudget creates an independent budget. The limit must be positive.
func NewBudget(limit int64) *Budget {
	if limit <= 0 {
		panic("memory budget requires a positive limit")
	}
	return &Budget{base: limit, status: Status{Limit: limit}}
}

func (b *Budget) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status
}

// UseLimit registers a temporary limit until its handle is closed. The smallest
// registered limit applies, or the constructor's limit if none remain. Lowering
// a limit preserves existing reservations and only restricts new allocations.
func (b *Budget) UseLimit(limit int64) *Limit {
	if limit <= 0 {
		panic("memory budget requires a positive limit")
	}
	l := &Limit{budget: b}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limits == nil {
		b.limits = make(map[*Limit]int64)
	}
	b.limits[l] = limit
	b.updateLimit()
	return l
}

func (b *Budget) updateLimit() {
	limit := b.base
	first := true
	for _, n := range b.limits {
		if first || n < limit {
			limit = n
			first = false
		}
	}
	b.status.Limit = limit
}

type Limit struct {
	budget *Budget
}

func (l *Limit) Close() {
	if l == nil {
		return
	}
	l.budget.mu.Lock()
	defer l.budget.mu.Unlock()
	delete(l.budget.limits, l)
	l.budget.updateLimit()
}

type Reservation struct {
	budget *Budget
	size   int64
}

// Reserve never waits for other owners to release memory. Close the returned
// reservation only when the accounted allocation is no longer needed.
func (b *Budget) Reserve(size int64) (Reservation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if size < 0 || size > 0 && size > b.status.Limit-b.status.Used {
		b.status.Denied++
		return Reservation{}, ErrBudgetExhausted
	}
	b.status.Used += size
	b.status.Peak = max(b.status.Peak, b.status.Used)
	return Reservation{budget: b, size: size}, nil
}

// Close releases a single owner's reservation. Ownership may be transferred by
// value, but copies must not be released independently or used concurrently.
func (r *Reservation) Close() {
	if r.size == 0 {
		return
	}
	r.budget.mu.Lock()
	r.budget.status.Used -= r.size
	r.budget.mu.Unlock()
	r.size = 0
}
