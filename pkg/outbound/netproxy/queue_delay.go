package netproxy

import (
	"iter"
	"slices"
	"sync/atomic"
	"time"
)

// QueueDelayBuckets are the upper bounds of the QueueDelay buckets.
var QueueDelayBuckets = [...]time.Duration{
	time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond,
	20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond,
	200 * time.Millisecond, 500 * time.Millisecond, time.Second,
}

// QueueDelay is the histogram of how long the datagrams one transport sent
// had waited in its send queue, over the process lifetime.
type QueueDelay struct {
	transport string
	// counts[i] counts delays up to QueueDelayBuckets[i] and above the
	// previous bound; the last counts those beyond every bound.
	counts [len(QueueDelayBuckets) + 1]atomic.Uint64
	sum    atomic.Int64 // nanoseconds
}

var queueDelays []*QueueDelay

// NewQueueDelay registers the histogram of a transport. It is called during
// package initialization, once for each transport.
func NewQueueDelay(transport string) *QueueDelay {
	if slices.ContainsFunc(queueDelays, func(q *QueueDelay) bool { return q.transport == transport }) {
		panic("netproxy: duplicate queue delay histogram " + transport)
	}
	q := &QueueDelay{transport: transport}
	queueDelays = append(queueDelays, q)
	return q
}

// QueueDelays yields every registered histogram.
func QueueDelays() iter.Seq[*QueueDelay] { return slices.Values(queueDelays) }

func (q *QueueDelay) Transport() string { return q.transport }

func (q *QueueDelay) Observe(d time.Duration) {
	i, _ := slices.BinarySearch(QueueDelayBuckets[:], d)
	q.counts[i].Add(1)
	q.sum.Add(int64(d))
}

// Snapshot returns the number of delays observed, their sum and the
// cumulative count of each bucket, as Prometheus histograms report them.
func (q *QueueDelay) Snapshot() (count uint64, sum time.Duration, cumulative []uint64) {
	cumulative = make([]uint64, len(QueueDelayBuckets))
	for i := range q.counts {
		count += q.counts[i].Load()
		if i < len(cumulative) {
			cumulative[i] = count
		}
	}
	return count, time.Duration(q.sum.Load()), cumulative
}
