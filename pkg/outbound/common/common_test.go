package common

import (
	"bytes"
	"testing"
)

func TestStringToUUID5(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
	}{
		{"empty", "", "e129f27c-5103-5c5c-844b-cdf0a15e160d"},
		{"ASCII", "example", "feb54431-301b-52bb-a6dd-e1e93e81bb9e"},
		{"Unicode", "你好，世界", "1c7fb245-3284-57ed-9627-4559294b0dc8"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := StringToUUID5(test.input); got != test.want {
				t.Fatalf("StringToUUID5(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestBytesAddBigEndian(t *testing.T) {
	tt := [][2][]byte{
		{{0, 0, 0}, {0, 0, 1}},
		{{0, 0, 255}, {0, 1, 0}},
		{{0, 255, 255}, {1, 0, 0}},
		{{255, 255, 255}, {0, 0, 0}},
		{{55, 255, 255}, {56, 0, 0}},
		{{56, 23, 255}, {56, 24, 0}},
		{{56, 24, 22}, {56, 24, 23}},
	}
	for i, test := range tt {
		BytesIncBigEndian(test[0])
		if !bytes.Equal(test[0], test[1]) {
			t.Fatal(i, test[0], "!=", test[1])
		}
	}
}

func TestBytesAddLittleEndian(t *testing.T) {
	tt := [][2][]byte{
		{{0, 0, 0}, {1, 0, 0}},
		{{255, 0, 0}, {0, 1, 0}},
		{{255, 255, 0}, {0, 0, 1}},
		{{255, 255, 255}, {0, 0, 0}},
		{{255, 255, 55}, {0, 0, 56}},
		{{255, 23, 56}, {0, 24, 56}},
		{{22, 24, 56}, {23, 24, 56}},
	}
	for i, test := range tt {
		BytesIncLittleEndian(test[0])
		if !bytes.Equal(test[0], test[1]) {
			t.Fatal(i, test[0], "!=", test[1])
		}
	}
}
