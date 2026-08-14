/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"errors"
	"io"
	"testing"
)

func TestBigEndianUvarintRejectsTruncatedValues(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{name: "two bytes", buf: []byte{0x40}},
		{name: "four bytes", buf: []byte{0x80, 0, 0}},
		{name: "eight bytes", buf: []byte{0xc0, 0, 0, 0, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, n, err := BigEndianUvarint(tt.buf)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("error = %v, want io.ErrUnexpectedEOF", err)
			}
			if n != 0 {
				t.Fatalf("bytes read = %d, want 0", n)
			}
		})
	}
}
