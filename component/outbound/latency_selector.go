package outbound

import (
	"sort"
	"sync"
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
	mu       sync.RWMutex
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

func (s *latencyBasedSelector) refreshNetwork(index common.NetworkIndex, changed *dialer.Dialer) {
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
		case !oldUsable, best == nil:
			newDialer = best
		default:
			bestCandidate := candidates[0]
			tolerance := time.Duration(0)
			if s.toleranceActive {
				tolerance = s.tolerance
			}
			if bestCandidate.priority > oldCandidate.priority ||
				bestCandidate.priority == oldCandidate.priority && bestCandidate.sortingLatency < oldCandidate.sortingLatency-tolerance {
				newDialer = best
			}
		}
	}
	selectionChanged := newDialer != oldDialer
	if selectionChanged {
		s.selected[index] = newDialer
		s.logSelection(oldDialer, newDialer, networkType)
	}
	if changed != nil {
		s.recordMetrics(candidates, changed, networkType)
	}
}

func (s *latencyBasedSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := networkType.Index()
	s.refreshNetwork(index, nil)
	return s.selected[index]
}

func (s *latencyBasedSelector) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
	s.mu.RLock()
	d := s.selected[networkType.Index()]
	s.mu.RUnlock()
	if d == nil || !d.Usable(networkType) {
		return nil
	}
	return d
}

func (s *latencyBasedSelector) Refresh(changed *dialer.Dialer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := common.NetworkIndex(0); i < common.NetworkTypeCount; i++ {
		s.refreshNetwork(i, changed)
	}
}

func (s *latencyBasedSelector) EnableTolerance() {
	s.mu.Lock()
	s.toleranceActive = true
	s.mu.Unlock()
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
		"_new_dialer": newName,
		"_old_dialer": oldName,
		"group":       s.dialerGroup.Name,
		"network":     networkType.String(),
	}
	if newDialer != nil {
		if candidate, ok := s.dialerGroup.candidate(newDialer, networkType); ok {
			fields[string(s.dialerGroup.selectionPolicy.Policy)] = common.LatencyString(candidate.latency, s.dialerGroup.dialerToAnnotation[newDialer].AddLatency)
		}
	}
	if oldDialer == nil {
		log.WithFields(fields).Warn("Group selects dialer")
	} else {
		log.WithFields(fields).Info("Group re-selects dialer")
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
