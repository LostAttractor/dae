package tls

import (
	"net/url"
	"testing"
)

func testRealityURL(spider string) string {
	return "reality://example.test:443?" + url.Values{
		"fp": {"chrome"}, "pbk": {"YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"sid": {"0123456789abcdef"}, "spx": {spider},
	}.Encode()
}
func TestRealityRejectsInvalidSpiderParameters(t *testing.T) {
	for _, field := range []string{"p", "c", "t", "i", "r"} {
		for _, value := range []string{"10-5", "100000000000", "-1", "no", "", "1-2-3", "9223372036854775808"} {
			t.Run(field+"="+value, func(t *testing.T) {
				if _, err := NewReality(testRealityURL("/?"+field+"="+value), nil); err == nil {
					t.Fatal("accepted invalid spider parameter")
				}
			})
		}
	}
}
func TestRealityRandomRangeDoesNotPanic(t *testing.T) {
	for _, pair := range [][2]int64{{10, 5}, {0, -1}, {0, 0}, {8, 8}} {
		if got := randBetween(pair[0], pair[1]); got != pair[0] {
			t.Fatalf("unexpected fallback: %d", got)
		}
	}
}
