/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"testing"
)

func TestSniffQuicBlockRejectsOversizedVarintLengths(t *testing.T) {
	header := []byte{0xc0, 0, 0, 0, 1, 0, 0}
	maxVarint := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	tests := []struct {
		name string
		buf  []byte
	}{
		{name: "token", buf: append(append([]byte{}, header...), maxVarint...)},
		{name: "packet", buf: append(append(append([]byte{}, header...), 0), maxVarint...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := sniffQuicBlock(nil, tt.buf)
			if !errors.Is(err, ErrNotApplicable) {
				t.Fatalf("error = %v, want ErrNotApplicable", err)
			}
		})
	}
}
