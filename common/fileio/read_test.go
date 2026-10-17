// SPDX-License-Identifier: AGPL-3.0-only

package fileio

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestReadBounded(t *testing.T) {
	for _, test := range []struct {
		data     string
		limit    int64
		tooLarge bool
	}{
		{"", 1, false}, {"test", 4, false}, {"tests", 4, true},
	} {
		input := strings.NewReader(test.data)
		got, err := ReadBounded(t.Context(), input, test.limit)
		if errors.Is(err, ErrTooLarge) != test.tooLarge || !test.tooLarge && (err != nil || string(got) != test.data) {
			t.Fatalf("read %q with limit %d = %q, %v", test.data, test.limit, got, err)
		}
	}
	for _, limit := range []int64{-1, 0, math.MaxInt64} {
		input := strings.NewReader("untouched")
		if _, err := ReadBounded(t.Context(), input, limit); err == nil || input.Len() != 9 {
			t.Fatalf("invalid limit %d consumed input or succeeded: %v", limit, err)
		}
	}
	input := strings.NewReader(strings.Repeat("x", 100))
	if _, err := ReadBounded(t.Context(), input, 10); !errors.Is(err, ErrTooLarge) || input.Len() != 89 {
		t.Fatalf("oversize read consumed more than limit+1: remaining=%d err=%v", input.Len(), err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	input = strings.NewReader("untouched")
	if _, err := ReadBounded(ctx, input, 10); !errors.Is(err, context.Canceled) || input.Len() != 9 {
		t.Fatalf("canceled read consumed input: %v", err)
	}
}
