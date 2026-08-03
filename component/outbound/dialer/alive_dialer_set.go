/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
)

type AliveDialerSet struct {
	dialerGroupName string
	tolerance       time.Duration

	aliveChangeCallback func(alive bool, networkType *NetworkType)

	selectionPolicy DialerSelectionPolicy
	fixedDialer     *Dialer

	aliveDialers []*Dialer

	mu                    sync.Mutex
	dialerToAlive         map[*Dialer]bool
	dialerToPriority      map[*Dialer]int
	dialerToLatency       map[*Dialer]time.Duration
	dialerToLatencyOffset map[*Dialer]time.Duration

	alive  [4]*bool
	dialer [4]*Dialer
}

func NewAliveDialerSet(
	dialerGroupName string,
	tolerance time.Duration,
	selectionPolicy DialerSelectionPolicy,
	dialers []*Dialer,
	dialersAnnotations []*Annotation,
	aliveChangeCallback func(alive bool, networkType *NetworkType),
) *AliveDialerSet {
	if len(dialers) != len(dialersAnnotations) {
		panic(fmt.Sprintf("unmatched annotations length: %v dialers and %v annotations", len(dialers), len(dialersAnnotations)))
	}
	a := &AliveDialerSet{
		dialerGroupName:       dialerGroupName,
		tolerance:             tolerance,
		aliveChangeCallback:   aliveChangeCallback,
		dialerToAlive:         make(map[*Dialer]bool),
		dialerToPriority:      make(map[*Dialer]int),
		dialerToLatency:       make(map[*Dialer]time.Duration),
		dialerToLatencyOffset: make(map[*Dialer]time.Duration),
		aliveDialers:          make([]*Dialer, 0, len(dialers)),
		selectionPolicy:       selectionPolicy,
	}
	if len(dialers) != 0 && selectionPolicy.Policy == consts.DialerSelectionPolicy_Fixed {
		// Allow empty dialer group.
		if selectionPolicy.FixedIndex < 0 || selectionPolicy.FixedIndex >= len(dialers) {
			panic(fmt.Sprintf("selected dialer index is out of range, group: %v, index: %v", dialerGroupName, selectionPolicy.FixedIndex))
		}
		a.fixedDialer = dialers[selectionPolicy.FixedIndex]
	}
	for i, d := range dialers {
		a.dialerToAlive[d] = false
		a.dialerToPriority[d] = dialersAnnotations[i].Priority
		a.dialerToLatencyOffset[d] = dialersAnnotations[i].AddLatency
	}
	return a
}

// func (a *AliveDialerSet) GetRand(networkType *NetworkType) *Dialer {
// 	a.mu.Lock()
// 	defer a.mu.Unlock()

// 	highPriorityDialers := a.getHighestPriorityDialers(networkType)
// 	if len(highPriorityDialers) == 0 {
// 		return nil
// 	}
// 	return highPriorityDialers[fastrand.Intn(len(highPriorityDialers))]
// }

func (a *AliveDialerSet) GetDialer(networkType *NetworkType) *Dialer {
	return a.dialer[NetworkTypeToIndex(networkType)]
}

func (a *AliveDialerSet) GetSortingLatency(d *Dialer) time.Duration {
	return a.dialerToLatency[d] + a.dialerToLatencyOffset[d]
}

func (a *AliveDialerSet) GetPriority(d *Dialer) int {
	return a.dialerToPriority[d]
}

func (a *AliveDialerSet) PrintLatencies(networkType *NetworkType, level log.Level) {
	var builder strings.Builder
	if networkType != nil {
		builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", a.dialerGroupName, networkType.String()))
	} else {
		builder.WriteString(fmt.Sprintf("Group '%v':\n", a.dialerGroupName))
	}
	samePriority := true

	var alive []*struct {
		dialer         *Dialer
		latency        time.Duration
		offset         time.Duration
		sortingLatency time.Duration
		priority       int
	}
	for _, dialer := range a.aliveDialers {
		if networkType != nil && !dialer.Supported(networkType) {
			continue
		}
		latency, ok := a.dialerToLatency[dialer]
		if !ok {
			continue
		}
		offset := a.dialerToLatencyOffset[dialer]
		priority := a.GetPriority(dialer)
		if len(alive) > 0 {
			samePriority = samePriority && priority == alive[len(alive)-1].priority
		}
		alive = append(alive, &struct {
			dialer         *Dialer
			latency        time.Duration
			offset         time.Duration
			sortingLatency time.Duration
			priority       int
		}{dialer, latency, offset, latency + offset, priority})
	}
	sort.SliceStable(alive, func(i, j int) bool {
		// First sort by priority (higher priority first)
		if alive[i].priority != alive[j].priority {
			return alive[i].priority > alive[j].priority
		}
		// Then sort by latency (lower latency first)
		return alive[i].sortingLatency < alive[j].sortingLatency
	})
	if len(alive) == 0 {
		builder.WriteString("\t<Empty>\n")
	} else {
		for i, dialer := range alive {
			priorityStr := ""
			if !samePriority {
				priorityStr = fmt.Sprintf(" (priority: %d)", dialer.priority)
			}
			tagStr := ""
			if dialer.dialer.SubscriptionTag != "" {
				tagStr = fmt.Sprintf(" [%v]", dialer.dialer.SubscriptionTag)
			}
			builder.WriteString(fmt.Sprintf("%4d.%v %v: %v%s\n", i+1, tagStr, dialer.dialer.Name, latencyString(dialer.latency, dialer.offset), priorityStr))
		}
	}
	if level == log.InfoLevel {
		log.Infoln(strings.TrimSuffix(builder.String(), "\n"))
	} else {
		log.Warnln(strings.TrimSuffix(builder.String(), "\n"))
	}
}

func (a *AliveDialerSet) getLatencyData(dialer *Dialer) (latency time.Duration, hasLatency bool) {
	switch a.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		latency, hasLatency = dialer.collection.Latencies10.LastLatency()
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		latency, hasLatency = dialer.collection.Latencies10.AvgLatency()
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		latency = dialer.collection.MovingAverage
		hasLatency = latency > 0
	}
	return
}

func (a *AliveDialerSet) updateDialerAliveState(dialer *Dialer, alive bool) {
	if alive {
		a.addAliveDialer(dialer)
	} else {
		a.removeAliveDialer(dialer)
	}
}

func (a *AliveDialerSet) addAliveDialer(dialer *Dialer) {
	if a.dialerToAlive[dialer] {
		return
	}

	log.WithFields(log.Fields{
		"dialer": dialer.Name,
		"group":  a.dialerGroupName,
	}).Warnf("[NOT ALIVE --> ALIVE]")

	a.dialerToAlive[dialer] = true
	a.aliveDialers = append(a.aliveDialers, dialer)
}

func (a *AliveDialerSet) removeAliveDialer(dialer *Dialer) {
	if !a.dialerToAlive[dialer] {
		return
	}

	log.WithFields(log.Fields{
		"dialer": dialer.Name,
		"group":  a.dialerGroupName,
	}).Infof("[ALIVE --> NOT ALIVE]")

	a.dialerToAlive[dialer] = false
	index := slices.Index(a.aliveDialers, dialer)
	if index == -1 {
		panic(fmt.Sprintf("dialer %p not found in aliveDialers", dialer))
	}

	if index < len(a.aliveDialers)-1 {
		// 将该元素与最后一个元素交换
		a.aliveDialers[index], a.aliveDialers[len(a.aliveDialers)-1] =
			a.aliveDialers[len(a.aliveDialers)-1], a.aliveDialers[index]
	}

	// 弹出最后一个元素
	a.aliveDialers = a.aliveDialers[:len(a.aliveDialers)-1]
}

func (a *AliveDialerSet) handleAliveStateChange(alive bool, networkType *NetworkType) {
	index := NetworkTypeToIndex(networkType)
	if a.alive[index] != nil && *a.alive[index] == alive {
		return
	}

	if alive {
		log.WithFields(log.Fields{
			"group":   a.dialerGroupName,
			"network": networkType.String(),
		}).Infof("Group is alive")
	} else {
		log.WithFields(log.Fields{
			"group":   a.dialerGroupName,
			"network": networkType.String(),
		}).Infof("Group has no dialer alive")
	}
	a.alive[index] = &alive
	a.aliveChangeCallback(alive, networkType)
}

func (a *AliveDialerSet) logDialerSelection(oldBestDialer *Dialer, newBestDialer *Dialer, networkType *NetworkType) {
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
			string(a.selectionPolicy.Policy): latencyString(a.dialerToLatency[newBestDialer], a.dialerToLatencyOffset[newBestDialer]),
			"_new_dialer":                    newDialerName,
			"_old_dialer":                    oldDialerName,
			"group":                          a.dialerGroupName,
			"network":                        networkType.String(),
		}).Warnf("Group %vselects dialer", re)
	} else {
		log.WithFields(log.Fields{
			string(a.selectionPolicy.Policy): latencyString(a.dialerToLatency[newBestDialer], a.dialerToLatencyOffset[newBestDialer]),
			"_new_dialer":                    newDialerName,
			"_old_dialer":                    oldDialerName,
			"group":                          a.dialerGroupName,
			"network":                        networkType.String(),
		}).Infof("Group %vselects dialer", re)
	}
}

// 修改初始化时 dialer 更新的逻辑?
// NotifyLatencyChange should be invoked when dialer every time latency and alive state changes.
func (a *AliveDialerSet) NotifyLatencyChange(dialer *Dialer, alive bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.updateDialerAliveState(dialer, alive)

	fmt.Printf("[DEBUG] NotifyLatencyChange: %v %v\n", dialer.Name, alive)

	latency, hasLatency := a.getLatencyData(dialer)
	if hasLatency {
		a.dialerToLatency[dialer] = latency
	}

	for i := 0; i < 4; i++ {
		networkType := IndexToNetworkType(i)
		switch a.selectionPolicy.Policy {
		case consts.DialerSelectionPolicy_MinLastLatency,
			consts.DialerSelectionPolicy_MinAverage10Latencies,
			consts.DialerSelectionPolicy_MinMovingAverageLatencies:
			oldDialer := a.dialer[i]
			newDialer := a.calcMinLatency(networkType)
			if newDialer != nil {
				fmt.Printf("[DEBUG] newDialer: %v, hasLatency: %v, network: %v\n", newDialer.Name, hasLatency, networkType.String())
			}
			if oldDialer != newDialer {
				newLatency := a.GetSortingLatency(newDialer)
				oldLatency := a.GetSortingLatency(oldDialer)
				if oldDialer != nil &&
					a.dialerToAlive[oldDialer] &&
					a.GetPriority(oldDialer) == a.GetPriority(newDialer) &&
					hasLatency {
					if newLatency >= oldLatency {
						continue
					}
					if newLatency >= oldLatency-a.tolerance {
						fmt.Printf("[DEBUG] Skip new dialer because of tolerance: %v\n", a.tolerance)
						continue
					}
				}
				a.dialer[i] = newDialer
				a.logDialerSelection(oldDialer, newDialer, networkType)
				a.PrintLatencies(networkType, log.WarnLevel)
			}
			a.handleAliveStateChange(newDialer != nil, networkType)
		case consts.DialerSelectionPolicy_Fixed:
			if dialer == a.fixedDialer {
				if alive {
					alive = dialer.Supported(networkType)
				}
				a.handleAliveStateChange(alive, networkType)
			}
		}
	}
}

func (a *AliveDialerSet) calcMinLatency(networkType *NetworkType) (dialer *Dialer) {
	minLatency := time.Hour
	highestPriority := math.MinInt

	for _, d := range a.aliveDialers {
		if !d.Supported(networkType) {
			continue
		}

		priority := a.GetPriority(d)
		sortingLatency := a.GetSortingLatency(d)

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
