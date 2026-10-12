package client

import (
	"math"
	"testing"
)

func TestBandwidthConfigurationBounds(t *testing.T) {
	for _, tc := range []struct {
		bandwidth BandwidthConfig
		invalid   bool
	}{
		{BandwidthConfig{}, false},
		{BandwidthConfig{MaxTx: 125_000_000, MaxRx: 250_000_000}, false},
		{BandwidthConfig{MaxTx: math.MaxInt64, MaxRx: math.MaxInt64}, false},
		{BandwidthConfig{MaxTx: math.MaxInt64 + 1}, true},
		{BandwidthConfig{MaxRx: math.MaxUint64}, true},
	} {
		client, err := NewClient(&Config{NextDialer: authTestDialer{}, BandwidthConfig: tc.bandwidth})
		if (err != nil) != tc.invalid {
			t.Fatalf("bandwidth %+v: %v", tc.bandwidth, err)
		}
		if client != nil {
			_ = client.Close()
		}
	}
}
