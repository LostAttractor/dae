// SPDX-License-Identifier: AGPL-3.0-only

package quickjs

import (
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// hostString preserves NUL and replaces unpaired surrogates just like
// string(utf16.Decode(units)), without allocating a growing intermediate rune
// slice. Check the UTF-8 byte budget before allocating the output string.
func hostString(units []uint16, limit uint64) (string, error) {
	limit = min(limit, uint64(^uint(0)>>1))
	if uint64(len(units)) > limit {
		return "", errors.New("host argument strings exceed memory limit")
	}
	var size uint64
	for rest := units; len(rest) > 0; {
		r, n := hostRune(rest)
		size += uint64(utf8.RuneLen(r))
		if size > limit {
			return "", errors.New("host argument strings exceed memory limit")
		}
		rest = rest[n:]
	}
	var text strings.Builder
	text.Grow(int(size))
	for len(units) > 0 {
		r, n := hostRune(units)
		text.WriteRune(r)
		units = units[n:]
	}
	return text.String(), nil
}

func hostRune(units []uint16) (rune, int) {
	r := rune(units[0])
	if !utf16.IsSurrogate(r) {
		return r, 1
	}
	if r < 0xdc00 && len(units) > 1 && units[1] >= 0xdc00 && units[1] <= 0xdfff {
		return utf16.DecodeRune(r, rune(units[1])), 2
	}
	return utf8.RuneError, 1
}
