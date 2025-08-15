package outbound

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	log "github.com/sirupsen/logrus"
)

type RandomSelector struct {
	BaseSelector
	dialerToAlive   map[*dialer.Dialer]bool
	dialerToLatency map[*dialer.Dialer]time.Duration

	networkIndexToDialers [4][]*dialer.Dialer
}

func NewRandomSelector(dialerGroup *DialerGroup, aliveChangeCallback func(alive bool, networkType *common.NetworkType)) Selector {
	return &RandomSelector{
		BaseSelector: BaseSelector{
			dialerGroup: dialerGroup,
		},
		dialerToAlive:   make(map[*dialer.Dialer]bool),
		dialerToLatency: make(map[*dialer.Dialer]time.Duration),
	}
}

func (s *RandomSelector) Select(networkType *common.NetworkType) (dialer *dialer.Dialer) {
	index := common.NetworkTypeToIndex(networkType)
	return s.networkIndexToDialers[index][fastrand.Intn(len(s.networkIndexToDialers[index]))]
}

func (s *RandomSelector) updateDialerAliveState(dialer *dialer.Dialer, alive bool) {
	if s.dialerToAlive[dialer] == alive {
		return
	}
	if alive {
		log.WithFields(log.Fields{
			"dialer": dialer.Name,
			"group":  s.dialerGroup.Name,
		}).Warnf("[NOT ALIVE --> ALIVE]")
	} else {
		log.WithFields(log.Fields{
			"dialer": dialer.Name,
			"group":  s.dialerGroup.Name,
		}).Infof("[ALIVE --> NOT ALIVE]")

	}
	s.dialerToAlive[dialer] = alive
}

func (s *RandomSelector) getLatencyData(dialer *dialer.Dialer) (latency time.Duration, hasLatency bool) {
	switch s.dialerGroup.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		latency, hasLatency = dialer.Latencies10.LastLatency()
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		latency, hasLatency = dialer.Latencies10.AvgLatency()
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		latency = dialer.MovingAverage
		hasLatency = latency > 0
	}
	return
}

func (s *RandomSelector) getSortedHighestPriorityAliveDialers(networkType *common.NetworkType) (aliveDialers []*dialer.Dialer) {
	highestPriority := s.getHighestPriority(networkType)
	for _, d := range s.dialerGroup.Dialers {
		if isDialerAlive(d, networkType) && s.dialerGroup.GetPriority(d) == highestPriority {
			aliveDialers = append(aliveDialers, d)
		}
	}
	return aliveDialers
}

func (s *RandomSelector) getHighestPriority(networkType *common.NetworkType) (highestPriority int) {
	highestPriority = math.MinInt
	for _, d := range s.dialerGroup.Dialers {
		if isDialerAlive(d, networkType) {
			priority := s.dialerGroup.GetPriority(d)
			if priority > highestPriority {
				highestPriority = priority
			}
		}
	}
	return
}

func (s *RandomSelector) NotifyStatusChange(dialer *dialer.Dialer) {
	s.updateDialerAliveState(dialer, dialer.Alive())

	latency, hasLatency := s.getLatencyData(dialer)
	if hasLatency {
		s.dialerToLatency[dialer] = latency
	}

	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		s.networkIndexToDialers[i] = s.getSortedHighestPriorityAliveDialers(networkType)
		s.handleAliveStateChange(len(s.networkIndexToDialers[i]) > 0, networkType)
	}
}

func (s *RandomSelector) PrintLatencies(networkType *common.NetworkType, level log.Level) {
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
			if dialer.NeedAliveState() {
				latencyStr = common.ShowDuration(s.dialerToLatency[dialer])
			} else {
				latencyStr = "Always Alive"
			}
			builder.WriteString(fmt.Sprintf("%4d.%v %v: %v\n", i+1, tagStr, dialer.Name, latencyStr))
		}
	}
	if level == log.InfoLevel {
		log.Infoln(strings.TrimSuffix(builder.String(), "\n"))
	} else {
		log.Warnln(strings.TrimSuffix(builder.String(), "\n"))
	}
}
