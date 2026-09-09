package outbound

import (
	"sort"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

type latencyBasedSelector struct {
	dialerGroup     *DialerGroup
	tolerance       time.Duration
	toleranceActive bool

	selected [common.NetworkTypeCount]*dialer.Dialer
}

func (s *latencyBasedSelector) sortedCandidates(networkType *common.NetworkType) []selectorCandidate {
	candidates := s.dialerGroup.candidates(networkType)
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority > candidates[j].priority
		}
		return candidates[i].sortingLatency < candidates[j].sortingLatency
	})
	return candidates
}

func findCandidate(candidates []selectorCandidate, d *dialer.Dialer) (selectorCandidate, bool) {
	for _, candidate := range candidates {
		if candidate.dialer == d {
			return candidate, true
		}
	}
	return selectorCandidate{}, false
}

func (s *latencyBasedSelector) refreshNetwork(index common.NetworkIndex, changed *dialer.Dialer, force bool) {
	networkType := index.NetworkType()
	candidates := s.sortedCandidates(networkType)
	oldDialer := s.selected[index]
	var best *dialer.Dialer
	if len(candidates) > 0 {
		best = candidates[0].dialer
	}
	newDialer := oldDialer
	if oldDialer != best {
		oldCandidate, oldUsable := findCandidate(candidates, oldDialer)
		switch {
		case !oldUsable:
			// Retain the last choice while unavailable. If a different node
			// later recovers, that is still a reselection of this group.
			if best != nil {
				newDialer = best
			}
		default:
			bestCandidate := candidates[0]
			tolerance := time.Duration(0)
			if s.toleranceActive && !force {
				tolerance = s.tolerance
			}
			if bestCandidate.priority > oldCandidate.priority ||
				bestCandidate.priority == oldCandidate.priority &&
					saturatingDurationAdd(bestCandidate.sortingLatency, tolerance) < oldCandidate.sortingLatency {
				newDialer = best
			}
		}
	}
	if newDialer != oldDialer {
		s.selected[index] = newDialer
		s.logSelection(oldDialer, newDialer, networkType)
	}
	if changed != nil {
		s.recordMetrics(candidates, changed, networkType)
	}
}

// The group's mutex protects all selection state and policy generations.
func (s *latencyBasedSelector) refresh(changed *dialer.Dialer, force dialer.SelectionForceMask) {
	for i := common.NetworkIndex(0); i < common.NetworkTypeCount; i++ {
		s.refreshNetwork(i, changed, force.Contains(i))
		network := i.NetworkType()
		if selected := s.selected[i]; selected != nil && selected.Usable(network) {
			s.dialerGroup.updateConnectionSelection(network, selected)
		}
	}
}

func (s *latencyBasedSelector) logSelection(oldDialer, newDialer *dialer.Dialer, networkType *common.NetworkType) {
	oldName := "<nil>"
	newName := "<nil>"
	if oldDialer != nil {
		oldName = oldDialer.Name
	}
	if newDialer != nil {
		newName = newDialer.Name
	}
	fields := log.Fields{
		"node":          newName,
		"previous_node": oldName,
		"group":         s.dialerGroup.Name,
		"network":       networkType.String(),
		"policy":        s.dialerGroup.selectionPolicy.Policy,
	}
	if newDialer != nil {
		if candidate, ok := s.dialerGroup.candidate(newDialer, networkType); ok {
			fields["latency"] = common.LatencyString(candidate.latency, s.dialerGroup.dialerToAnnotation[newDialer].AddLatency)
		}
	}
	if oldDialer == nil {
		delete(fields, "previous_node")
		log.WithFields(fields).Info("Group selected node")
	} else {
		log.WithFields(fields).Info("Group changed node")
	}
}

func (s *latencyBasedSelector) recordMetrics(candidates []selectorCandidate, d *dialer.Dialer, networkType *common.NetworkType) {
	snapshot := d.SelectionSnapshot(networkType)
	if snapshot.Support != dialer.NetworkSupportConfirmed || !snapshot.HasLatency {
		return
	}
	selectionLatency := candidateLatency(s.dialerGroup.selectionPolicy.Policy, snapshot)
	selectionLatency = saturatingDurationAdd(selectionLatency, s.dialerGroup.dialerToAnnotation[d].AddLatency)
	stats.DefaultStore.RecordCheckMetrics(
		d.StatsPath(s.dialerGroup.Name, networkType),
		snapshot.Latency.Last,
		snapshot.Latency.MovingAvg,
		selectionLatency,
	)
	for i, candidate := range candidates {
		stats.DefaultStore.RecordSelectionIndex(candidate.dialer.StatsPath(s.dialerGroup.Name, networkType), i)
	}
}
