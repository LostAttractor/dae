// SPDX-License-Identifier: AGPL-3.0-only

package membuffer

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type exactErrorReader struct {
	data  string
	err   error
	calls int
}

func (r *exactErrorReader) Read(p []byte) (int, error) {
	r.calls++
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, r.err
}

func TestReadExactAdmissionAndErrors(t *testing.T) {
	failure := errors.New("read failed")
	for _, tt := range []struct {
		name, data           string
		size, budget         int64
		readError, wantError error
	}{
		{"exact", "abc", 3, 3, io.EOF, nil},
		{"short", "ab", 3, 3, io.EOF, io.ErrUnexpectedEOF},
		{"full-error", "abc", 3, 3, failure, failure},
		{"short-error", "ab", 3, 3, failure, failure},
		{"denied", "abc", 3, 2, nil, ErrBudgetExhausted},
		{"empty", "", 0, 1, nil, nil},
		{"invalid", "", -1, 1, nil, ErrInvalidLimit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			budget := NewBudget(tt.budget)
			r := &exactErrorReader{data: tt.data, err: tt.readError}
			view, err := ReadExact(r, tt.size, budget)
			if !errors.Is(err, tt.wantError) {
				t.Fatal(err)
			}
			if tt.name == "denied" || tt.name == "invalid" || tt.name == "empty" {
				if r.calls != 0 {
					t.Fatal("source read before admission or for a zero-length request")
				}
			}
			if view != nil && string(view.Bytes()) != tt.data {
				t.Fatal(view.Bytes())
			}
			view.Close()
			if budget.Status().Used != 0 {
				t.Fatal(budget.Status())
			}
		})
	}
	budget := NewBudget(8)
	source := strings.NewReader("firsttail")
	view, err := ReadExact(source, 5, budget)
	if err != nil || string(view.Bytes()) != "first" || source.Len() != 4 {
		t.Fatal(view, err, source.Len())
	}
	view.Close()
	if _, err := ReadExact(source, 1, nil); !errors.Is(err, ErrBudgetRequired) {
		t.Fatal(err)
	}
}
