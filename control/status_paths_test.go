// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"math"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestPathStatsHistoryAggregation(t *testing.T) {
	var total api.PathStats
	addPathStats(&total, api.PathStats{History: api.TrafficHistory{
		UploadBytesPerSecond:   []uint64{1, 2},
		DownloadBytesPerSecond: []uint64{3, 4},
	}})
	addPathStats(&total, api.PathStats{History: api.TrafficHistory{
		UploadBytesPerSecond: []uint64{10, math.MaxUint64}, DownloadBytesPerSecond: []uint64{30, math.MaxUint64},
	}})
	want := api.TrafficHistory{
		UploadBytesPerSecond: []uint64{11, math.MaxUint64}, DownloadBytesPerSecond: []uint64{33, math.MaxUint64},
	}
	if !reflect.DeepEqual(total.History, want) {
		t.Fatalf("aggregated history = %+v, want %+v", total.History, want)
	}
}
