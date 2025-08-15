package outbound

import (
	"fmt"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

type FixedSelector struct {
	BaseSelector
	alive   bool
	latency time.Duration
}

func NewFixedSelector(dialerGroup *DialerGroup, aliveChangeCallback func(alive bool, networkType *common.NetworkType)) Selector {
	return &FixedSelector{
		BaseSelector: BaseSelector{
			dialerGroup:         dialerGroup,
			aliveChangeCallback: aliveChangeCallback,
		},
	}
}

func (s *FixedSelector) Select(networkType *common.NetworkType) (dialer *dialer.Dialer) {
	if s.dialerGroup.selectionPolicy.FixedIndex >= len(s.dialerGroup.Dialers) {
		return nil
	}
	dialer = s.dialerGroup.Dialers[s.dialerGroup.selectionPolicy.FixedIndex]
	if !dialer.Alive() {
		return nil
	}
	return
}

func (s *FixedSelector) updateAliveState(dialer *dialer.Dialer, alive bool) {
	if s.alive == alive {
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
	s.alive = alive
}

func (s *FixedSelector) NotifyStatusChange(dialer *dialer.Dialer) {
	if s.dialerGroup.selectionPolicy.FixedIndex >= len(s.dialerGroup.Dialers) {
		return
	}
	if dialer == s.dialerGroup.Dialers[s.dialerGroup.selectionPolicy.FixedIndex] {
		s.updateAliveState(dialer, dialer.Alive())
		for i := 0; i < 4; i++ {
			networkType := common.IndexToNetworkType(i)
			s.handleAliveStateChange(dialer.Alive() && dialer.Supported(networkType), networkType)
		}
	}
}

func (s *FixedSelector) PrintLatencies(networkType *common.NetworkType, level log.Level) {
	var builder strings.Builder
	if networkType != nil {
		builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", s.dialerGroup.Name, networkType.String()))
	} else {
		builder.WriteString(fmt.Sprintf("Group '%v':\n", s.dialerGroup.Name))
	}

	if s.dialerGroup.selectionPolicy.FixedIndex >= len(s.dialerGroup.Dialers) {
		builder.WriteString("\t<Index Out Of Range>\n")
	} else {
		dialer := s.dialerGroup.Dialers[s.dialerGroup.selectionPolicy.FixedIndex]
		if dialer.Alive() {
			tagStr := ""
			if dialer.SubscriptionTag != "" {
				tagStr = fmt.Sprintf(" [%v]", dialer.SubscriptionTag)
			}
			var latencyStr string
			if dialer.NeedAliveState() {
				latencyStr = common.ShowDuration(s.latency)
			} else {
				latencyStr = "Always Alive"
			}
			builder.WriteString(fmt.Sprintf("%4d.%v %v: %v\n", 1, tagStr, dialer.Name, latencyStr))
		} else {
			builder.WriteString("\t<Not Alive>\n")
		}
	}
	if level == log.InfoLevel {
		log.Infoln(strings.TrimSuffix(builder.String(), "\n"))
	} else {
		log.Warnln(strings.TrimSuffix(builder.String(), "\n"))
	}
}
