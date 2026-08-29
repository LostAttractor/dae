//go:build linux && dae_splice

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"errors"
	"testing"
)

type writeFunc func([]byte) (int, error)

func (f writeFunc) Write(p []byte) (int, error) { return f(p) }

func TestWriteFullAndRecordIncludesPartialWriteBeforeError(t *testing.T) {
	wantErr := errors.New("write failed")
	writes := 0
	writer := writeFunc(func(p []byte) (int, error) {
		writes++
		if writes == 1 {
			return 2, nil
		}
		return 1, wantErr
	})
	var counted uint64
	err := writeFullAndRecord(writer, []byte("payload"), func(n uint64) { counted += n })
	if !errors.Is(err, wantErr) {
		t.Fatalf("writeFullAndRecord error = %v, want %v", err, wantErr)
	}
	if counted != 3 {
		t.Fatalf("counted bytes = %d, want 3", counted)
	}
}
