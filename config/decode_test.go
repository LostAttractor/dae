// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestFuzzyDecodeSignedIntegers(t *testing.T) {
	type namedInt int
	type namedInt8 int8
	type namedInt16 int16
	type namedInt32 int32
	type namedInt64 int64
	for _, zero := range []any{int(0), int8(0), int16(0), int32(0), int64(0), namedInt(0), namedInt8(0), namedInt16(0), namedInt32(0), namedInt64(0)} {
		typ := reflect.TypeOf(zero)
		t.Run(typ.String(), func(t *testing.T) {
			max := int64(uint64(1)<<(typ.Bits()-1) - 1)
			min := -max - 1
			for _, test := range []struct {
				input string
				want  int64
			}{
				{strconv.FormatInt(min, 10), min},
				{strconv.FormatInt(max, 10), max},
				{"0", 0}, {"+42", 42}, {"-0x2a", -42},
				{"0x2a", 42}, {"052", 42}, {"0o52", 42}, {"0b101010", 42}, {"0x2_a", 42},
			} {
				got := reflect.New(typ)
				if !FuzzyDecode(got.Interface(), test.input) || got.Elem().Int() != test.want {
					t.Errorf("decode %q = %v, want %d", test.input, got.Elem().Interface(), test.want)
				}
			}
			for _, input := range []string{strconv.FormatUint(uint64(max)+1, 10), strconv.FormatInt(min, 10) + "0", "", "08", "1.5", "1s", " 42"} {
				got := reflect.New(typ)
				got.Elem().SetInt(7)
				if FuzzyDecode(got.Interface(), input) || got.Elem().Int() != 7 {
					t.Errorf("invalid integer %q accepted or mutated destination: %v", input, got.Elem().Interface())
				}
			}
		})
	}
}

func TestFuzzyDecodeUnsignedIntegers(t *testing.T) {
	type namedUint uint
	type namedUint8 uint8
	type namedUint16 uint16
	type namedUint32 uint32
	type namedUint64 uint64
	for _, zero := range []any{uint(0), uint8(0), uint16(0), uint32(0), uint64(0), namedUint(0), namedUint8(0), namedUint16(0), namedUint32(0), namedUint64(0)} {
		typ := reflect.TypeOf(zero)
		t.Run(typ.String(), func(t *testing.T) {
			max := uint64(1)<<typ.Bits() - 1
			overflow := "18446744073709551616"
			if typ.Bits() < 64 {
				overflow = strconv.FormatUint(max+1, 10)
			}
			for _, test := range []struct {
				input string
				want  uint64
			}{
				{strconv.FormatUint(max, 10), max},
				{"0", 0}, {"42", 42}, {"0x2a", 42}, {"052", 42}, {"0o52", 42}, {"0b101010", 42}, {"0x2_a", 42},
			} {
				got := reflect.New(typ)
				if !FuzzyDecode(got.Interface(), test.input) || got.Elem().Uint() != test.want {
					t.Errorf("decode %q = %v, want %d", test.input, got.Elem().Interface(), test.want)
				}
			}
			for _, input := range []string{overflow, "-1", "", "08", "1.5", "1s", " 42"} {
				got := reflect.New(typ)
				got.Elem().SetUint(7)
				if FuzzyDecode(got.Interface(), input) || got.Elem().Uint() != 7 {
					t.Errorf("invalid integer %q accepted or mutated destination: %v", input, got.Elem().Interface())
				}
			}
		})
	}
}

func TestFuzzyDecodeDuration(t *testing.T) {
	for _, test := range []struct {
		input string
		want  time.Duration
	}{
		{"0", 0}, {"1h30m", 90 * time.Minute}, {"-1ms", -time.Millisecond}, {"1.5s", 1500 * time.Millisecond},
	} {
		var got time.Duration
		if !FuzzyDecode(&got, test.input) || got != test.want {
			t.Errorf("decode %q = %v, want %v", test.input, got, test.want)
		}
	}
	for _, input := range []string{"", "1", "0x10", "1d", "9223372036854775808ns"} {
		got := time.Second
		if FuzzyDecode(&got, input) || got != time.Second {
			t.Errorf("invalid duration %q accepted or mutated destination: %v", input, got)
		}
	}
	for _, destination := range []any{nil, (*int)(nil), 1} {
		if FuzzyDecode(destination, "1") {
			t.Errorf("invalid destination accepted: %v", destination)
		}
	}
}
