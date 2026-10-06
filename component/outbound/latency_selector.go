package outbound

import (
	"cmp"
	"slices"
	"time"

	"github.com/daeuniverse/dae/api"
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
	slices.SortStableFunc(candidates, compareCandidates)
	return candidates
}

func compareCandidates(a, b selectorCandidate) int {
	if a.degraded != b.degraded {
		if a.degraded {
			return 1
		}
		return -1
	}
	return cmp.Or(cmp.Compare(b.priority, a.priority), cmp.Compare(a.sortingLatency, b.sortingLatency))
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
			fields["latency"] = candidate.latency.String()
			fields["selection_score"] = candidate.sortingLatency.String()
			fields["priority"] = candidate.priority
			fields["degraded"] = candidate.degraded
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
	if snapshot.Support != api.NetworkSupportConfirmed || !snapshot.HasLatency {
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
