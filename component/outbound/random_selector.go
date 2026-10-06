package outbound

import (
	"math"
	"slices"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

func (g *DialerGroup) preferredRandomCandidates(networkType *common.NetworkType) []selectorCandidate {
	candidates := g.candidates(networkType)
	candidates = slices.DeleteFunc(candidates, func(candidate selectorCandidate) bool {
		return !g.selectionUsable(candidate.dialer, networkType)
	})
	highestPriority := math.MinInt
	hasNormal := false
	for _, candidate := range candidates {
		hasNormal = hasNormal || !candidate.degraded
	}
	for _, candidate := range candidates {
		if hasNormal && candidate.degraded {
			continue
		}
		highestPriority = max(highestPriority, candidate.priority)
	}
	preferred := candidates[:0]
	for _, candidate := range candidates {
		if (!hasNormal || !candidate.degraded) && candidate.priority == highestPriority {
			preferred = append(preferred, candidate)
		}
	}
	return preferred
}

func (g *DialerGroup) selectRandom(networkType *common.NetworkType) *dialer.Dialer {
	candidates := g.preferredRandomCandidates(networkType)
	if len(candidates) == 0 {
		return nil
	}
	return candidates[fastrand.Intn(len(candidates))].dialer
}
