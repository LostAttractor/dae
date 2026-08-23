package outbound

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

type FixedSelector struct {
	dialerGroup *DialerGroup
	alive       bool
}

func NewFixedSelector(dialerGroup *DialerGroup) Selector {
	return &FixedSelector{
		dialerGroup: dialerGroup,
	}
}

func (s *FixedSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	if s.dialerGroup.selectionPolicy.FixedIndex < 0 || s.dialerGroup.selectionPolicy.FixedIndex >= len(s.dialerGroup.Dialers) {
		return nil
	}
	d := s.dialerGroup.Dialers[s.dialerGroup.selectionPolicy.FixedIndex]
	if !isDialerAlive(d, networkType) {
		return nil
	}
	return d
}

func (s *FixedSelector) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
	return s.Select(networkType)
}

func (s *FixedSelector) NotifyStatusChange(d *dialer.Dialer) {
	index := s.dialerGroup.selectionPolicy.FixedIndex
	if index >= 0 && index < len(s.dialerGroup.Dialers) && d == s.dialerGroup.Dialers[index] {
		s.alive = logDialerAliveTransition(s.dialerGroup, d, s.alive, d.Alive())
	}
}

func (s *FixedSelector) PrintLatencies(networkType *common.NetworkType, logfn func(args ...interface{})) {
	var builder strings.Builder
	if networkType != nil {
		builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", s.dialerGroup.Name, networkType.String()))
	} else {
		builder.WriteString(fmt.Sprintf("Group '%v':\n", s.dialerGroup.Name))
	}

	if s.dialerGroup.selectionPolicy.FixedIndex < 0 || s.dialerGroup.selectionPolicy.FixedIndex >= len(s.dialerGroup.Dialers) {
		builder.WriteString("\t<Index Out Of Range>\n")
	} else {
		dialer := s.dialerGroup.Dialers[s.dialerGroup.selectionPolicy.FixedIndex]
		if dialer.Alive() {
			tagStr := ""
			if dialer.SubscriptionTag != "" {
				tagStr = fmt.Sprintf(" [%v]", dialer.SubscriptionTag)
			}
			var latencyStr string
			if dialer.ChecksConnectivity() {
				latencyStr = common.ShowDuration(0)
				if latency, ok := dialer.LatencyStats(s.dialerGroup); ok {
					latencyStr = common.ShowDuration(latency.Last)
				}
			} else {
				latencyStr = "Always Alive"
			}
			builder.WriteString(fmt.Sprintf("%4d.%v %v: %v\n", 1, tagStr, dialer.Name, latencyStr))
		} else {
			builder.WriteString("\t<Not Alive>\n")
		}
	}
	logfn(strings.TrimSuffix(builder.String(), "\n"))
}
