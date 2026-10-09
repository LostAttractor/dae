package outbound

import (
	"math"
	"time"

	"github.com/daeuniverse/dae/api"
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
	degraded       bool
}

func candidateLatency(policy consts.DialerSelectionPolicy, latency api.LatencyStats) time.Duration {
	switch policy {
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		return latency.Avg10
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return latency.MovingAvg
	default:
		return latency.Last
	}
}

func (g *DialerGroup) candidate(d *dialer.Dialer, networkType *common.NetworkType) (selectorCandidate, bool) {
	if d == nil {
		return selectorCandidate{}, false
	}
	snapshot := d.SelectionSnapshot(networkType)
	if !snapshot.Usable {
		return selectorCandidate{}, false
	}
	return g.scoreCandidate(d, snapshot), true
}

func (g *DialerGroup) scoreCandidate(d *dialer.Dialer, snapshot dialer.SelectionSnapshot) selectorCandidate {
	latency := candidateLatency(g.selectionPolicy.Policy, snapshot.Latency)
	sortingLatency := saturatingDurationAdd(latency, g.dialerToAnnotation[d].AddLatency)
	return selectorCandidate{
		dialer:         d,
		latency:        latency,
		sortingLatency: sortingLatency,
		priority:       g.dialerToAnnotation[d].PriorityAt(latency),
		degraded:       snapshot.Degraded,
	}
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
