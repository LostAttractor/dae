// SPDX-License-Identifier: AGPL-3.0-only

package membuffer

import (
	"errors"
	"io"
	"math"
)

// Copy creates immutable storage from borrowed bytes. Admission happens before
// allocation; the returned view owns exactly len(data) bytes of the budget.
func Copy(data []byte, budget *Budget) (*View, error) {
	memory, err := budget.Reserve(int64(len(data)))
	if err != nil {
		return nil, err
	}
	owned := make([]byte, len(data))
	copy(owned, data)
	return newView(owned, memory, budget), nil
}

var (
	ErrTooLarge       = errors.New("buffer exceeds size limit")
	ErrInvalidLimit   = errors.New("buffer requires a positive, bounded limit")
	ErrBudgetRequired = errors.New("buffer requires an explicit memory budget")
)

// Buffer owns mutable output. Write and Read use the same growth mechanism,
// charging both arrays while reallocating. View transfers ownership to shared
// immutable storage; Close releases unfinished output. Buffer is not concurrent
// and must not be copied. Set Budget and Limit before writing, and leave them
// unchanged until View or Close.
type Buffer struct {
	Budget *Budget
	Limit  int64
	data   []byte
	memory Reservation
}

func (b *Buffer) Len() int { return len(b.data) }

// grow reserves space for n additional bytes without changing the length.
// A failed reservation leaves all current bytes and capacity intact.
func (b *Buffer) grow(n int) error {
	if b.Limit <= 0 || b.Limit > int64(math.MaxInt) || n < 0 || int64(n) > b.Limit-int64(len(b.data)) {
		return ErrTooLarge
	}
	if b.Budget == nil {
		return ErrBudgetRequired
	}
	needed := int64(len(b.data)) + int64(n)
	capacity := int64(cap(b.data))
	if needed <= capacity {
		return nil
	}
	// Saturate doubling at Limit, including on 32-bit architectures.
	growth := min(capacity, b.Limit-capacity)
	size := min(b.Limit, max(needed, max(512, capacity+growth)))
	memory, err := b.Budget.Reserve(size)
	if err != nil {
		return err
	}
	data := make([]byte, len(b.data), int(size))
	copy(data, b.data)
	b.data = data
	b.memory.Close()
	b.memory = memory
	return nil
}

func (b *Buffer) Write(p []byte) (int, error) {
	if err := b.grow(len(p)); err != nil {
		return 0, err
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// View transfers storage without copying. The buffer can then be reused.
func (b *Buffer) View() *View {
	v := newView(b.data, b.memory, b.Budget)
	b.data, b.memory = nil, Reservation{}
	return v
}

func (b *Buffer) Close() {
	b.memory.Close()
	b.data, b.memory = nil, Reservation{}
}

// Read consumes at most limit+1 bytes to detect overflow. Except for invalid
// arguments, it returns a view even on error: the view contains every consumed
// byte, allowing the caller to replay a prefix followed by the unread source.
// Always close the returned view, including on errors. Read never closes r.
func Read(r io.Reader, limit int64, budget *Budget) (*View, error) {
	if limit <= 0 || limit >= int64(math.MaxInt) {
		return nil, ErrInvalidLimit
	}
	if budget == nil {
		return nil, ErrBudgetRequired
	}
	b := Buffer{Budget: budget, Limit: limit + 1}
	for {
		if len(b.data) == cap(b.data) {
			if err := b.grow(1); err != nil {
				return b.View(), err
			}
		}
		n, err := r.Read(b.data[len(b.data):cap(b.data)])
		b.data = b.data[:len(b.data)+n]
		if err != nil && err != io.EOF {
			return b.View(), err
		}
		if int64(len(b.data)) > limit {
			return b.View(), ErrTooLarge
		}
		if err != nil {
			if len(b.data) == 0 {
				b.Close()
				b.data = []byte{}
			}
			return b.View(), nil // EOF; any other read error was returned above.
		}
	}
}
