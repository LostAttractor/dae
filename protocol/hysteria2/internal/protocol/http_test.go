package protocol

import (
	"math"
	"net/http"
	"testing"
)

func TestAuthResponseBandwidth(t *testing.T) {
	for _, tc := range []struct {
		value         string
		rx            uint64
		auto, invalid bool
	}{
		{"", 0, false, false},
		{"auto", 0, true, false},
		{"0", 0, false, false},
		{"125000000", 125_000_000, false, false},
		{"18446744073709551615", math.MaxUint64, false, false},
		{"18446744073709551616", 0, false, true},
		{"-1", 0, false, true},
		{"invalid", 0, false, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			h := make(http.Header)
			h.Set(CommonHeaderCCRX, tc.value)
			response, err := AuthResponseFromHeader(h)
			if (err != nil) != tc.invalid || response.Rx != tc.rx || response.RxAuto != tc.auto {
				t.Fatalf("unexpected bandwidth response: %+v, %v", response, err)
			}
		})
	}
}
