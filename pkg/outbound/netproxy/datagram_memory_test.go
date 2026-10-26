package netproxy

import (
	"testing"
	"time"
)

// A delay counts in the first bucket whose bound it does not exceed.
func TestQueueDelayBuckets(t *testing.T) {
	q := &QueueDelay{transport: t.Name()}
	for _, d := range []time.Duration{0, time.Millisecond, time.Millisecond + 1, 3 * time.Second} {
		q.Observe(d)
	}
	count, sum, cumulative := q.Snapshot()
	if count != 4 || sum != 3*time.Second+2*time.Millisecond+1 {
		t.Fatalf("count %d, sum %v", count, sum)
	}
	if cumulative[0] != 2 || cumulative[1] != 3 || cumulative[len(cumulative)-1] != 3 {
		t.Fatalf("cumulative buckets %v", cumulative)
	}
}
