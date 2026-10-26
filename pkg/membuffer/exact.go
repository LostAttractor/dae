// SPDX-License-Identifier: AGPL-3.0-only

package membuffer

import (
	"io"
	"math"
)

func ReadExact(r io.Reader, size int64, budget *Budget) (*View, error) {
	if size < 0 || size > int64(math.MaxInt) {
		return nil, ErrInvalidLimit
	}
	if budget == nil {
		return nil, ErrBudgetRequired
	}
	memory, err := budget.Reserve(size)
	if err != nil {
		return nil, err
	}
	data := make([]byte, int(size))
	used := 0
	for used < len(data) {
		n, err := r.Read(data[used:])
		used += n
		if err != nil {
			if err == io.EOF {
				err = nil
				if used != len(data) {
					err = io.ErrUnexpectedEOF
				}
			}
			return newView(data[:used], memory, budget), err
		}
	}
	return newView(data, memory, budget), nil
}
