package outbound

import (
	"fmt"
	"slices"
	"sort"
	"strings"
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

	dialerToAlive   map[*dialer.Dialer]bool
	dialerToLatency map[*dialer.Dialer]time.Duration

	networkIndexToDialer [4]*dialer.Dialer
	mu                   sync.RWMutex
}

func NewLatencyBasedSelector(dialerGroup *DialerGroup, tolerance time.Duration) Selector {
	return &LatencyBasedSelector{
		dialerGroup:     dialerGroup,
		tolerance:       tolerance,
		dialerToAlive:   make(map[*dialer.Dialer]bool),
		dialerToLatency: make(map[*dialer.Dialer]time.Duration),
	}
}

func (s *LatencyBasedSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	index := common.NetworkTypeToIndex(networkType)
	return s.networkIndexToDialer[index]
}

func (s *LatencyBasedSelector) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
	return s.Select(networkType)
}

func (s *LatencyBasedSelector) getSortingLatency(d *dialer.Dialer) time.Duration {
	return s.dialerToLatency[d] + s.dialerGroup.dialerToAnnotation[d].AddLatency
}

func (s *LatencyBasedSelector) getSortedAliveDialers(networkType *common.NetworkType) (aliveDialers []*dialer.Dialer) {
	var alive []*struct {
		dialer         *dialer.Dialer
		sortingLatency time.Duration
		priority       int
	}
	for _, d := range preferredAliveDialers(s.dialerGroup.Dialers, networkType) {
		sortingLatency := s.getSortingLatency(d)
		alive = append(alive, &struct {
			dialer         *dialer.Dialer
			sortingLatency time.Duration
			priority       int
		}{d, sortingLatency, s.dialerGroup.GetPriority(d, sortingLatency)})
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

func (s *LatencyBasedSelector) PrintLatencies(networkType *common.NetworkType, logfn func(args ...interface{})) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	aliveDialers := s.getSortedAliveDialers(networkType)
	s.printLatencies(aliveDialers, networkType, logfn)
}

// TODO: 由于tolerance 的存在, 第一个 aliveDialer 并不一定是当前选定的 dialer, 该方法需要修改
func (s *LatencyBasedSelector) printLatencies(aliveDialers []*dialer.Dialer, networkType *common.NetworkType, logfn func(args ...interface{})) {
	var builder strings.Builder
	if networkType != nil {
		builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", s.dialerGroup.Name, networkType.String()))
	} else {
		builder.WriteString(fmt.Sprintf("Group '%v':\n", s.dialerGroup.Name))
	}

	if len(aliveDialers) == 0 {
		builder.WriteString("\t<Empty>\n")
	} else {
		for i, dialer := range aliveDialers {
			tagStr := ""
			if dialer.SubscriptionTag != "" {
				tagStr = fmt.Sprintf(" [%v]", dialer.SubscriptionTag)
			}
			latencyStr := common.LatencyString(s.dialerToLatency[dialer], s.dialerGroup.dialerToAnnotation[dialer].AddLatency)
			if !dialer.ChecksConnectivity() {
				latencyStr = fmt.Sprintf("Always Alive (%v)", latencyStr)
			}
			builder.WriteString(fmt.Sprintf("%4d.%v %v: %v%s\n", i+1, tagStr, dialer.Name, latencyStr, fmt.Sprintf(" (priority: %d)", s.dialerGroup.GetPriority(dialer, s.getSortingLatency(dialer)))))
		}
	}
	logfn(strings.TrimSuffix(builder.String(), "\n"))
}

func (s *LatencyBasedSelector) selectionLatency(d *dialer.Dialer) (time.Duration, bool) {
	return d.SelectionLatency(s.dialerGroup, s.dialerGroup.selectionPolicy.Policy)
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

	logFields := log.Fields{
		"_new_dialer": newDialerName,
		"_old_dialer": oldDialerName,
		"group":       s.dialerGroup.Name,
		"network":     networkType.String(),
	}
	if newBestDialer != nil {
		logFields[string(s.dialerGroup.selectionPolicy.Policy)] = common.LatencyString(s.dialerToLatency[newBestDialer], s.dialerGroup.dialerToAnnotation[newBestDialer].AddLatency)
	}
	if oldBestDialer == nil {
		log.WithFields(logFields).Warnf("Group %vselects dialer", re)
	} else {
		log.WithFields(logFields).Infof("Group %vselects dialer", re)
	}
}

func (s *LatencyBasedSelector) logCheckLatency(aliveDialers []*dialer.Dialer, dialer *dialer.Dialer, networkType *common.NetworkType) {
	if !dialer.ConfirmedSupport(networkType) {
		return
	}
	labels := prometheus.Labels{
		"id":       dialer.StatsID(),
		"outbound": s.dialerGroup.Name,
		"subtag":   dialer.Property.SubscriptionTag,
		"dialer":   dialer.Name,
		"network":  networkType.String(),
	}

	lat, ok := dialer.LatencyStats(s.dialerGroup)
	if !ok {
		return
	}
	latencyMs := float64(lat.Last.Milliseconds())
	common.CheckLatency.With(labels).Set(latencyMs)

	if lat.MovingAvg > 0 {
		common.CheckMovingLatency.With(labels).Set(float64(lat.MovingAvg.Milliseconds()))
	}

	selectLatency := s.getSortingLatency(dialer)
	if selectLatency > 0 {
		common.CheckSelectLatency.With(labels).Set(float64(selectLatency.Milliseconds()))
	}

	for i, d := range aliveDialers {
		labels["id"] = d.StatsID()
		labels["subtag"] = d.Property.SubscriptionTag
		labels["dialer"] = d.Name
		common.DialerSelectIndex.With(labels).Set(float64(i))
	}
}

func (s *LatencyBasedSelector) NotifyStatusChange(d *dialer.Dialer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dialerToAlive[d] = logDialerAliveTransition(
		s.dialerGroup, d, s.dialerToAlive[d], d.Alive())

	latency, hasLatency := s.selectionLatency(d)
	if hasLatency {
		s.dialerToLatency[d] = latency
	}
	var oncePrintLatencies sync.Once

	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		aliveDialers := s.getSortedAliveDialers(networkType)
		oldDialer := s.networkIndexToDialer[i]
		var newDialer *dialer.Dialer
		if len(aliveDialers) > 0 {
			newDialer = aliveDialers[0]
		}
		s.logCheckLatency(aliveDialers, d, networkType)
		selectionChanged := false
		if oldDialer != newDialer {
			switch {
			case oldDialer == nil,
				newDialer == nil,
				!slices.Contains(aliveDialers, oldDialer):
				s.networkIndexToDialer[i] = newDialer
				s.logDialerSelection(oldDialer, newDialer, networkType)
				selectionChanged = true
			default:
				oldLatency := s.getSortingLatency(oldDialer)
				newLatency := s.getSortingLatency(newDialer)
				oldPriority := s.dialerGroup.GetPriority(oldDialer, oldLatency)
				newPriority := s.dialerGroup.GetPriority(newDialer, newLatency)
				switch {
				case newPriority > oldPriority,
					newPriority == oldPriority && hasLatency && newLatency < oldLatency-s.tolerance:
					s.networkIndexToDialer[i] = newDialer
					s.logDialerSelection(oldDialer, newDialer, networkType)
					selectionChanged = true
				}
			}
		}
		if selectionChanged && s.dialerGroup.latencyTableLogging.Load() {
			oncePrintLatencies.Do(func() {
				s.printLatencies(aliveDialers, networkType, log.Warnln)
			})
		}
	}
}
