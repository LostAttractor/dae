package outbound

import (
	"math"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

type randomSelector struct {
	dialerGroup *DialerGroup
}

func (s *randomSelector) preferredCandidates(networkType *common.NetworkType) []selectorCandidate {
	candidates := s.dialerGroup.candidates(networkType)
	highestPriority := math.MinInt
	for _, candidate := range candidates {
		highestPriority = max(highestPriority, candidate.priority)
	}
	preferred := candidates[:0]
	for _, candidate := range candidates {
		if candidate.priority == highestPriority {
			preferred = append(preferred, candidate)
		}
	}
	return preferred
}

func (s *randomSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	candidates := s.preferredCandidates(networkType)
	if len(candidates) == 0 {
		return nil
	}
	return candidates[fastrand.Intn(len(candidates))].dialer
}

func (s *randomSelector) SelectedDialer(*common.NetworkType) *dialer.Dialer { return nil }

func (s *randomSelector) Refresh(*dialer.Dialer) {}

func (s *randomSelector) EnableTolerance() {}
