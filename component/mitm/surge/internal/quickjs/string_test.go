// SPDX-License-Identifier: AGPL-3.0-only

package quickjs

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func FuzzHostString(f *testing.F) {
	for _, units := range [][]uint16{
		nil, {0, 'a', 0}, {'你', '好'}, {0xd83d, 0xde80},
		{0xd800, 0xd800, 'x', 0xdc00, 0xdc00}, {0xdc00, 0xd800},
		{0xd7ff, 0xe000, 0xffff},
	} {
		data := make([]byte, len(units)*2)
		for i, unit := range units {
			binary.LittleEndian.PutUint16(data[i*2:], unit)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		units := make([]uint16, len(data)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(data[i*2:])
		}
		want := string(utf16.Decode(units))
		got, err := hostString(units, uint64(len(want)))
		if err != nil || got != want {
			t.Fatalf("conversion=%q, error=%v, want %q", got, err, want)
		}
		if len(want) > 0 {
			if _, err := hostString(units, uint64(len(want)-1)); err == nil {
				t.Fatal("accepted string exceeding UTF-8 byte budget")
			}
		}
	})
}
