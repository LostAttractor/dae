package outbound

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

type LatencyBasedSelector struct {
	BaseSelector
	tolerance time.Duration

	dialerToAlive   map[*dialer.Dialer]bool
	dialerToLatency map[*dialer.Dialer]time.Duration

	networkIndexToDialer [4]*dialer.Dialer
}

func NewLatencyBasedSelector(dialerGroup *DialerGroup, tolerance time.Duration, aliveChangeCallback func(alive bool, networkType *common.NetworkType)) Selector {
	return &LatencyBasedSelector{
		BaseSelector: BaseSelector{
			dialerGroup:         dialerGroup,
			aliveChangeCallback: aliveChangeCallback,
		},
		tolerance:       tolerance,
		dialerToAlive:   make(map[*dialer.Dialer]bool),
		dialerToLatency: make(map[*dialer.Dialer]time.Duration),
	}
}

func (s *LatencyBasedSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	index := common.NetworkTypeToIndex(networkType)
	return s.networkIndexToDialer[index]
}

func (s *LatencyBasedSelector) getSortingLatency(d *dialer.Dialer) time.Duration {
	return s.dialerToLatency[d] + s.dialerGroup.dialerToLatencyOffset[d]
}

func (s *LatencyBasedSelector) getSortedAliveDialers(networkType *common.NetworkType) (aliveDialers []*dialer.Dialer) {
	var alive []*struct {
		dialer         *dialer.Dialer
		sortingLatency time.Duration
		priority       int
	}
	for _, d := range s.dialerGroup.Dialers {
		if isDialerAlive(d, networkType) {
			alive = append(alive, &struct {
				dialer         *dialer.Dialer
				sortingLatency time.Duration
				priority       int
			}{d, s.getSortingLatency(d), s.dialerGroup.GetPriority(d)})
		}
	}
	sort.SliceStable(alive, func(i, j int) bool {
		// First sort by priority (higher priority first)
		if alive[i].priority != alive[j].priority {
			return alive[i].priority > alive[j].priority
		}
		// Then sort by latency (lower latency first)
		return alive[i].sortingLatency < alive[j].sortingLatency
	})
	for _, d := range alive {
		aliveDialers = append(aliveDialers, d.dialer)
	}
	return aliveDialers
}

func isDialerAlive(dialer *dialer.Dialer, networkType *common.NetworkType) bool {
	if !dialer.Alive() {
		return false
	}
	if networkType != nil && !dialer.Supported(networkType) {
		return false
	}
	return true
}

func (s *LatencyBasedSelector) PrintLatencies(networkType *common.NetworkType, level log.Level) {
	var builder strings.Builder
	if networkType != nil {
		builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", s.dialerGroup.Name, networkType.String()))
	} else {
		builder.WriteString(fmt.Sprintf("Group '%v':\n", s.dialerGroup.Name))
	}

	aliveDialers := s.getSortedAliveDialers(networkType)

	if len(aliveDialers) == 0 {
		builder.WriteString("\t<Empty>\n")
	} else {
		for i, dialer := range aliveDialers {
			tagStr := ""
			if dialer.SubscriptionTag != "" {
				tagStr = fmt.Sprintf(" [%v]", dialer.SubscriptionTag)
			}
			latencyStr := common.LatencyString(s.dialerToLatency[dialer], s.dialerGroup.dialerToLatencyOffset[dialer])
			if !dialer.NeedAliveState() {
				latencyStr = fmt.Sprint("Always Alive (%v)", latencyStr)
			}
			builder.WriteString(fmt.Sprintf("%4d.%v %v: %v%s\n", i+1, tagStr, dialer.Name, latencyStr, fmt.Sprintf(" (priority: %d)", s.dialerGroup.GetPriority(dialer))))
		}
	}
	if level == log.InfoLevel {
		log.Infoln(strings.TrimSuffix(builder.String(), "\n"))
	} else {
		log.Warnln(strings.TrimSuffix(builder.String(), "\n"))
	}
}

func (s *LatencyBasedSelector) getLatencyData(dialer *dialer.Dialer) (latency time.Duration, hasLatency bool) {
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

func (s *LatencyBasedSelector) updateDialerAliveState(dialer *dialer.Dialer, alive bool) {
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

func (s *LatencyBasedSelector) logDialerSelection(oldBestDialer *dialer.Dialer, newBestDialer *dialer.Dialer, networkType *common.NetworkType) {
	var re string
	var oldDialerName, newDialerName string

	if oldBestDialer == nil {
		oldDialerName = "<nil>"
	} else {
		re = "re-"
		oldDialerName = oldBestDialer.Name
	}

	if newBestDialer == nil {
		newDialerName = "<nil>"
	} else {
		newDialerName = newBestDialer.Name
	}

	if oldBestDialer == nil {
		log.WithFields(log.Fields{
			string(s.dialerGroup.selectionPolicy.Policy): common.LatencyString(s.dialerToLatency[newBestDialer], s.dialerGroup.dialerToLatencyOffset[newBestDialer]),
			"_new_dialer": newDialerName,
			"_old_dialer": oldDialerName,
			"group":       s.dialerGroup.Name,
			"network":     networkType.String(),
		}).Warnf("Group %vselects dialer", re)
	} else {
		log.WithFields(log.Fields{
			string(s.dialerGroup.selectionPolicy.Policy): common.LatencyString(s.dialerToLatency[newBestDialer], s.dialerGroup.dialerToLatencyOffset[newBestDialer]),
			"_new_dialer": newDialerName,
			"_old_dialer": oldDialerName,
			"group":       s.dialerGroup.Name,
			"network":     networkType.String(),
		}).Infof("Group %vselects dialer", re)
	}
}

func (s *LatencyBasedSelector) NotifyStatusChange(dialer *dialer.Dialer) {
	s.updateDialerAliveState(dialer, dialer.Alive())

	latency, hasLatency := s.getLatencyData(dialer)
	if hasLatency {
		s.dialerToLatency[dialer] = latency
	}
	var oncePrintLatencies sync.Once

	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		oldDialer := s.networkIndexToDialer[i]
		newDialer := s.calcMinLatency(networkType)
		if oldDialer != newDialer {
			newLatency := s.getSortingLatency(newDialer)
			oldLatency := s.getSortingLatency(oldDialer)
			switch {
			case oldDialer == nil,
				!s.dialerToAlive[oldDialer],
				s.dialerGroup.GetPriority(newDialer) > s.dialerGroup.GetPriority(oldDialer),
				s.dialerGroup.GetPriority(newDialer) == s.dialerGroup.GetPriority(oldDialer) && hasLatency && newLatency < oldLatency-s.tolerance:
				s.networkIndexToDialer[i] = newDialer
				s.logDialerSelection(oldDialer, newDialer, networkType)
				oncePrintLatencies.Do(func() {
					s.PrintLatencies(networkType, log.WarnLevel)
				})
			}
		}
		oncePrintLatencies.Do(func() {
			s.PrintLatencies(networkType, log.InfoLevel)
		})
		s.handleAliveStateChange(newDialer != nil, networkType)
	}
}

func (s *LatencyBasedSelector) calcMinLatency(networkType *common.NetworkType) (dialer *dialer.Dialer) {
	minLatency := time.Hour
	highestPriority := math.MinInt

	for _, d := range s.dialerGroup.Dialers {
		if !isDialerAlive(d, networkType) {
			continue
		}

		priority := s.dialerGroup.GetPriority(d)
		sortingLatency := s.getSortingLatency(d)

		switch {
		case priority > highestPriority,
			priority == highestPriority && sortingLatency < minLatency:
			minLatency = sortingLatency
			highestPriority = priority
			dialer = d
		}
	}
	return
}
