package outbound

import (
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

type RandomSelector struct {
	dialerGroup   *DialerGroup
	dialerToAlive map[*dialer.Dialer]bool

	networkIndexToDialers [4][]*dialer.Dialer
	mu                    sync.RWMutex
}

func NewRandomSelector(dialerGroup *DialerGroup) Selector {
	return &RandomSelector{
		dialerGroup:   dialerGroup,
		dialerToAlive: make(map[*dialer.Dialer]bool),
	}
}

func (s *RandomSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	index := common.NetworkTypeToIndex(networkType)
	dialers := s.networkIndexToDialers[index]
	if len(dialers) == 0 {
		return nil
	}
	return dialers[fastrand.Intn(len(dialers))]
}

func (s *RandomSelector) SelectedDialer(*common.NetworkType) *dialer.Dialer {
	return nil
}

func (s *RandomSelector) getSortedHighestPriorityAliveDialers(networkType *common.NetworkType) (aliveDialers []*dialer.Dialer) {
	preferred := preferredAliveDialers(s.dialerGroup.Dialers, networkType)
	highestPriority := s.getHighestPriority(preferred)
	for _, d := range preferred {
		if s.dialerGroup.dialerToAnnotation[d].Priority == highestPriority {
			aliveDialers = append(aliveDialers, d)
		}
	}
	return aliveDialers
}

func (s *RandomSelector) getHighestPriority(dialers []*dialer.Dialer) (highestPriority int) {
	highestPriority = math.MinInt
	for _, d := range dialers {
		priority := s.dialerGroup.dialerToAnnotation[d].Priority
		if priority > highestPriority {
			highestPriority = priority
		}
	}
	return
}

func (s *RandomSelector) NotifyStatusChange(dialer *dialer.Dialer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dialerToAlive[dialer] = logDialerAliveTransition(
		s.dialerGroup, dialer, s.dialerToAlive[dialer], dialer.Alive())

	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		s.networkIndexToDialers[i] = s.getSortedHighestPriorityAliveDialers(networkType)
	}
}

func (s *RandomSelector) PrintLatencies(networkType *common.NetworkType, logfn func(args ...interface{})) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var builder strings.Builder
	if networkType != nil {
		builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", s.dialerGroup.Name, networkType.String()))
	} else {
		builder.WriteString(fmt.Sprintf("Group '%v':\n", s.dialerGroup.Name))
	}

	aliveDialers := s.getSortedHighestPriorityAliveDialers(networkType)

	if len(aliveDialers) == 0 {
		builder.WriteString("\t<Empty>\n")
	} else {
		for i, dialer := range aliveDialers {
			tagStr := ""
			if dialer.SubscriptionTag != "" {
				tagStr = fmt.Sprintf(" [%v]", dialer.SubscriptionTag)
			}
			var latencyStr string
			if dialer.ChecksConnectivity() {
				latencyStr = common.ShowDuration(0)
			} else {
				latencyStr = "Always Alive"
			}
			builder.WriteString(fmt.Sprintf("%4d.%v %v: %v\n", i+1, tagStr, dialer.Name, latencyStr))
		}
	}
	logfn(strings.TrimSuffix(builder.String(), "\n"))
}
