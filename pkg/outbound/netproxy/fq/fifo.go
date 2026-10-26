package fq

import "iter"

// FIFO is a slice-backed queue that reuses its storage.
type FIFO[T any] struct {
	items []T
	head  int
}

func (q *FIFO[T]) Len() int { return len(q.items) - q.head }

func (q *FIFO[T]) Push(v T) {
	if q.head > 0 && len(q.items) == cap(q.items) {
		n := copy(q.items, q.items[q.head:])
		clear(q.items[n:])
		q.items, q.head = q.items[:n], 0
	}
	q.items = append(q.items, v)
}

func (q *FIFO[T]) Peek() T { return q.items[q.head] }

func (q *FIFO[T]) Last() *T { return &q.items[len(q.items)-1] }

func (q *FIFO[T]) Pop() T { return q.remove(0) }

// All yields the queued values from the oldest.
func (q *FIFO[T]) All() iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, v := range q.items[q.head:] {
			if !yield(v) {
				return
			}
		}
	}
}

// remove takes out the i-th oldest value, moving the older ones up.
func (q *FIFO[T]) remove(i int) T {
	i += q.head
	v := q.items[i]
	copy(q.items[q.head+1:i+1], q.items[q.head:i])
	var zero T
	q.items[q.head] = zero
	if q.head++; q.head == len(q.items) {
		q.items, q.head = q.items[:0], 0
	}
	return v
}
