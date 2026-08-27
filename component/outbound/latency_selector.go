package outbound

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

type LatencyBasedSelector struct {
	dialerGroup *DialerGroup
	tolerance   time.Duration

	selected [4]*dialer.Dialer
	mu       sync.RWMutex
}

func NewLatencyBasedSelector(dialerGroup *DialerGroup, tolerance time.Duration) Selector {
	return &LatencyBasedSelector{dialerGroup: dialerGroup, tolerance: tolerance}
}

func (s *LatencyBasedSelector) sortedCandidates(networkType *common.NetworkType) []selectorCandidate {
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

func (s *LatencyBasedSelector) refreshNetwork(index int, changed *dialer.Dialer) ([]selectorCandidate, bool) {
	networkType := common.IndexToNetworkType(index)
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
			if bestCandidate.priority > oldCandidate.priority ||
				bestCandidate.priority == oldCandidate.priority && bestCandidate.sortingLatency < oldCandidate.sortingLatency-s.tolerance {
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
	return candidates, selectionChanged
}

func (s *LatencyBasedSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := common.NetworkTypeToIndex(networkType)
	s.refreshNetwork(index, nil)
	return s.selected[index]
}

func (s *LatencyBasedSelector) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
	s.mu.RLock()
	d := s.selected[common.NetworkTypeToIndex(networkType)]
	s.mu.RUnlock()
	if d == nil || !d.Usable(networkType) {
		return nil
	}
	return d
}

func (s *LatencyBasedSelector) Refresh(changed *dialer.Dialer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var printOnce sync.Once
	for i := 0; i < 4; i++ {
		candidates, selectionChanged := s.refreshNetwork(i, changed)
		if selectionChanged && s.dialerGroup.latencyTableLogging.Load() {
			networkType := common.IndexToNetworkType(i)
			printOnce.Do(func() { s.printCandidates(candidates, networkType, log.Warnln) })
		}
	}
}

func (s *LatencyBasedSelector) PrintLatencies(networkType *common.NetworkType, logfn func(args ...interface{})) {
	s.printCandidates(s.sortedCandidates(networkType), networkType, logfn)
}

func (s *LatencyBasedSelector) printCandidates(candidates []selectorCandidate, networkType *common.NetworkType, logfn func(args ...interface{})) {
	printLatencyHeader(s.dialerGroup, networkType, logfn)
	if len(candidates) == 0 {
		logfn("  <Empty>")
		return
	}
	for i, candidate := range candidates {
		tag := ""
		if candidate.dialer.SubscriptionTag != "" {
			tag = fmt.Sprintf(" [%v]", candidate.dialer.SubscriptionTag)
		}
		latency := common.LatencyString(candidate.latency, s.dialerGroup.dialerToAnnotation[candidate.dialer].AddLatency)
		logfn(fmt.Sprintf("%4d.%v %v: %v (priority: %d)", i+1, tag, candidate.dialer.Name, latency, candidate.priority))
	}
}

func (s *LatencyBasedSelector) logSelection(oldDialer, newDialer *dialer.Dialer, networkType *common.NetworkType) {
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

func (s *LatencyBasedSelector) recordMetrics(candidates []selectorCandidate, d *dialer.Dialer, networkType *common.NetworkType) {
	snapshot := d.SelectionSnapshot(networkType)
	if snapshot.Support != dialer.NetworkSupportConfirmed || !snapshot.HasLatency {
		return
	}
	labels := prometheus.Labels{
		"id":       d.StatsID(),
		"outbound": s.dialerGroup.Name,
		"subtag":   d.Property.SubscriptionTag,
		"dialer":   d.Name,
		"network":  networkType.String(),
	}
	common.CheckLatency.With(labels).Set(float64(snapshot.Latency.Last.Milliseconds()))
	if snapshot.Latency.MovingAvg > 0 {
		common.CheckMovingLatency.With(labels).Set(float64(snapshot.Latency.MovingAvg.Milliseconds()))
	}
	selectionLatency := candidateLatency(s.dialerGroup.selectionPolicy.Policy, snapshot)
	selectionLatency = saturatingDurationAdd(selectionLatency, s.dialerGroup.dialerToAnnotation[d].AddLatency)
	if selectionLatency > 0 {
		common.CheckSelectLatency.With(labels).Set(float64(selectionLatency.Milliseconds()))
	}
	for i, candidate := range candidates {
		labels["id"] = candidate.dialer.StatsID()
		labels["subtag"] = candidate.dialer.Property.SubscriptionTag
		labels["dialer"] = candidate.dialer.Name
		common.DialerSelectIndex.With(labels).Set(float64(i))
	}
}
