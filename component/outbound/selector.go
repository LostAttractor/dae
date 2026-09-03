package outbound

import (
	"math"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func saturatingDurationAdd(a, b time.Duration) time.Duration {
	if b > 0 && a > time.Duration(math.MaxInt64)-b {
		return time.Duration(math.MaxInt64)
	}
	if b < 0 && a < time.Duration(math.MinInt64)-b {
		return time.Duration(math.MinInt64)
	}
	return a + b
}

type selectorCandidate struct {
	dialer         *dialer.Dialer
	latency        time.Duration
	sortingLatency time.Duration
	priority       int
}

func candidateLatency(policy consts.DialerSelectionPolicy, snapshot dialer.SelectionSnapshot) time.Duration {
	if !snapshot.HasLatency {
		return 0
	}
	switch policy {
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		return snapshot.Latency.Avg10
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return snapshot.Latency.MovingAvg
	default:
		return snapshot.Latency.Last
	}
}

func (g *DialerGroup) candidate(d *dialer.Dialer, networkType *common.NetworkType) (selectorCandidate, bool) {
	snapshot := d.SelectionSnapshot(networkType)
	if !snapshot.Usable {
		return selectorCandidate{}, false
	}
	latency := candidateLatency(g.selectionPolicy.Policy, snapshot)
	sortingLatency := saturatingDurationAdd(latency, g.dialerToAnnotation[d].AddLatency)
	return selectorCandidate{
		dialer:         d,
		latency:        latency,
		sortingLatency: sortingLatency,
		priority:       g.dialerToAnnotation[d].PriorityAt(sortingLatency),
	}, true
}

func (g *DialerGroup) candidates(networkType *common.NetworkType) []selectorCandidate {
	candidates := make([]selectorCandidate, 0, len(g.Dialers))
	for _, d := range g.Dialers {
		if candidate, ok := g.candidate(d, networkType); ok {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}
