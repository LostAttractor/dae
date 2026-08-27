package outbound

import (
	"fmt"
	"math"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

type RandomSelector struct {
	dialerGroup *DialerGroup
}

func NewRandomSelector(dialerGroup *DialerGroup) Selector {
	return &RandomSelector{dialerGroup: dialerGroup}
}

func (s *RandomSelector) preferredCandidates(networkType *common.NetworkType) []selectorCandidate {
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

func (s *RandomSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	candidates := s.preferredCandidates(networkType)
	if len(candidates) == 0 {
		return nil
	}
	return candidates[fastrand.Intn(len(candidates))].dialer
}

func (s *RandomSelector) SelectedDialer(*common.NetworkType) *dialer.Dialer { return nil }

func (s *RandomSelector) Refresh(*dialer.Dialer) {}

func (s *RandomSelector) PrintLatencies(networkType *common.NetworkType, logfn func(args ...interface{})) {
	printLatencyHeader(s.dialerGroup, networkType, logfn)
	candidates := s.preferredCandidates(networkType)
	if len(candidates) == 0 {
		logfn("  <Empty>")
		return
	}
	for i, candidate := range candidates {
		tag := ""
		if candidate.dialer.SubscriptionTag != "" {
			tag = fmt.Sprintf(" [%v]", candidate.dialer.SubscriptionTag)
		}
		logfn(fmt.Sprintf("%4d.%v %v: %v", i+1, tag, candidate.dialer.Name, common.ShowDuration(candidate.latency)))
	}
}
