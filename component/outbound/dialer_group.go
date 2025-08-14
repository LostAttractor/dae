/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	log "github.com/sirupsen/logrus"
)

var ErrNoDialer = fmt.Errorf("no dialer")
var ErrNoAliveDialer = fmt.Errorf("no alive dialer")
var ErrFixedDialerNotAlive = fmt.Errorf("fixed dialer is not alive")

type DialerGroup struct {
	netproxy.Dialer

	Name string

	Dialers         []*dialer.Dialer
	selectionPolicy *dialer.DialerSelectionPolicy

	needAliveState bool
	tolerance      time.Duration

	aliveChangeCallback func(alive bool, networkType *common.NetworkType)

	mu                    sync.Mutex
	dialerToAlive         map[*dialer.Dialer]bool
	dialerToPriority      map[*dialer.Dialer]int
	dialerToLatency       map[*dialer.Dialer]time.Duration
	dialerToLatencyOffset map[*dialer.Dialer]time.Duration

	networkIndexToAlive   [4]*bool
	networkIndexToDialer  [4]*dialer.Dialer
	networkIndexToDialers [4][]*dialer.Dialer
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	selectionPolicy dialer.DialerSelectionPolicy,
	needAliveState bool,
	aliveChangeCallback func(alive bool, networkType *common.NetworkType),
) *DialerGroup {
	if len(dialers) != len(dialersAnnotations) {
		panic(fmt.Sprintf("unmatched annotations length: %v dialers and %v annotations", len(dialers), len(dialersAnnotations)))
	}

	g := &DialerGroup{
		Name:                  name,
		Dialers:               dialers,
		selectionPolicy:       &selectionPolicy,
		needAliveState:        needAliveState,
		tolerance:             option.CheckTolerance,
		aliveChangeCallback:   aliveChangeCallback,
		dialerToAlive:         make(map[*dialer.Dialer]bool),
		dialerToPriority:      make(map[*dialer.Dialer]int),
		dialerToLatency:       make(map[*dialer.Dialer]time.Duration),
		dialerToLatencyOffset: make(map[*dialer.Dialer]time.Duration),
	}

	if needAliveState {
		for _, d := range dialers {
			d.RegisterAliveDialerSet(g)
		}
	}

	for i, d := range dialers {
		g.dialerToPriority[d] = dialersAnnotations[i].Priority
		g.dialerToLatencyOffset[d] = dialersAnnotations[i].AddLatency
	}
	return g
}

func (g *DialerGroup) Close() error {
	for _, d := range g.Dialers {
		d.UnregisterAliveDialerSet(g)
	}
	return nil
}

func (g *DialerGroup) NeedAliveState() bool {
	return g.needAliveState
}

func (g *DialerGroup) GetSelectionPolicy() (policy consts.DialerSelectionPolicy) {
	return g.selectionPolicy.Policy
}

// SelectFallbackIpVersion selects a dialer from group according to selectionPolicy. If 'strictIpVersion' is false and no alive dialer, it will fallback to another ipversion.
func (g *DialerGroup) SelectFallbackIpVersion(networkType *common.NetworkType, strictIpVersion bool) (dialer *dialer.Dialer, fallback bool, err error) {
	dialer, err = g.Select(networkType)
	if !strictIpVersion && errors.Is(err, ErrNoAliveDialer) {
		networkType.IpVersion = (consts.IpVersion_X - networkType.IpVersion.ToIpVersionType()).ToIpVersionStr()
		dialer, err = g.Select(networkType)
		fallback = true
	}
	return
}

func (g *DialerGroup) Select(networkType *common.NetworkType) (dialer *dialer.Dialer, err error) {
	if len(g.Dialers) == 0 {
		return nil, ErrNoDialer
	}
select_dialer:
	switch g.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_Fixed:
		dialer = g.Dialers[g.selectionPolicy.FixedIndex]
	case consts.DialerSelectionPolicy_Random:
		dialers := g.networkIndexToDialers[common.NetworkTypeToIndex(networkType)]
		if len(dialers) > 0 {
			dialer = dialers[fastrand.Intn(len(dialers))]
		}
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		dialer = g.networkIndexToDialer[common.NetworkTypeToIndex(networkType)]
	default:
		panic(fmt.Sprintf("unsupported DialerSelectionPolicy: %v", g.selectionPolicy))
	}

	if !g.needAliveState {
		return dialer, nil
	}

	if dialer == nil {
		// TODO: 这种情况下应该尝试测试网络连接性, 若从无连接变为有连接则重新测速所有节点?
		return nil, ErrNoAliveDialer
	}

	if !dialer.Alive() {
		dialer.ReportUnavailable()
		goto select_dialer
	}

	return dialer, nil
}

func (g *DialerGroup) PrintLatency() {
	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		g.printLatencies(networkType, log.InfoLevel)
	}
}

func (g *DialerGroup) getSortingLatency(d *dialer.Dialer) time.Duration {
	return g.dialerToLatency[d] + g.dialerToLatencyOffset[d]
}

func (g *DialerGroup) getPriority(d *dialer.Dialer) int {
	return g.dialerToPriority[d]
}

func (g *DialerGroup) getSortedAliveDialers(networkType *common.NetworkType) (aliveDialers []*dialer.Dialer) {
	var alive []*struct {
		dialer         *dialer.Dialer
		sortingLatency time.Duration
		priority       int
	}
	for _, d := range g.Dialers {
		if isDialerAlive(d, networkType) {
			alive = append(alive, &struct {
				dialer         *dialer.Dialer
				sortingLatency time.Duration
				priority       int
			}{d, g.getSortingLatency(d), g.getPriority(d)})
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

func (g *DialerGroup) getSortedHighestPriorityAliveDialers(networkType *common.NetworkType) (aliveDialers []*dialer.Dialer) {
	highestPriority := g.getHighestPriority(networkType)
	var alive []*struct {
		dialer         *dialer.Dialer
		sortingLatency time.Duration
	}
	for _, d := range g.Dialers {
		if isDialerAlive(d, networkType) && g.getPriority(d) == highestPriority {
			alive = append(alive, &struct {
				dialer         *dialer.Dialer
				sortingLatency time.Duration
			}{d, g.getSortingLatency(d)})
		}
	}
	sort.SliceStable(alive, func(i, j int) bool {
		return alive[i].sortingLatency < alive[j].sortingLatency
	})
	for _, d := range alive {
		aliveDialers = append(aliveDialers, d.dialer)
	}
	return aliveDialers
}

func (g *DialerGroup) getHighestPriority(networkType *common.NetworkType) (highestPriority int) {
	highestPriority = math.MinInt
	for _, d := range g.Dialers {
		if isDialerAlive(d, networkType) {
			priority := g.getPriority(d)
			if priority > highestPriority {
				highestPriority = priority
			}
		}
	}
	return
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

func (g *DialerGroup) printLatencies(networkType *common.NetworkType, level log.Level) {
	var builder strings.Builder
	if networkType != nil {
		builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", g.Name, networkType.String()))
	} else {
		builder.WriteString(fmt.Sprintf("Group '%v':\n", g.Name))
	}
	samePriority := true

	aliveDialers := g.getSortedAliveDialers(networkType)

	if len(aliveDialers) == 0 {
		builder.WriteString("\t<Empty>\n")
	} else {
		for i, dialer := range aliveDialers {
			priorityStr := ""
			if !samePriority {
				priorityStr = fmt.Sprintf(" (priority: %d)", g.getPriority(dialer))
			}
			tagStr := ""
			if dialer.SubscriptionTag != "" {
				tagStr = fmt.Sprintf(" [%v]", dialer.SubscriptionTag)
			}
			builder.WriteString(fmt.Sprintf("%4d.%v %v: %v%s\n", i+1, tagStr, dialer.Name, common.LatencyString(g.dialerToLatency[dialer], g.dialerToLatencyOffset[dialer]), priorityStr))
		}
	}
	if level == log.InfoLevel {
		log.Infoln(strings.TrimSuffix(builder.String(), "\n"))
	} else {
		log.Warnln(strings.TrimSuffix(builder.String(), "\n"))
	}
}

func (g *DialerGroup) getLatencyData(dialer *dialer.Dialer) (latency time.Duration, hasLatency bool) {
	switch g.selectionPolicy.Policy {
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

func (g *DialerGroup) updateDialerAliveState(dialer *dialer.Dialer, alive bool) {
	if g.dialerToAlive[dialer] == alive {
		return
	}
	if alive {
		log.WithFields(log.Fields{
			"dialer": dialer.Name,
			"group":  g.Name,
		}).Warnf("[NOT ALIVE --> ALIVE]")
	} else {
		log.WithFields(log.Fields{
			"dialer": dialer.Name,
			"group":  g.Name,
		}).Infof("[ALIVE --> NOT ALIVE]")

	}
	g.dialerToAlive[dialer] = alive
}

func (g *DialerGroup) handleAliveStateChange(alive bool, networkType *common.NetworkType) {
	index := common.NetworkTypeToIndex(networkType)
	if g.networkIndexToAlive[index] != nil && *g.networkIndexToAlive[index] == alive {
		return
	}

	if alive {
		log.WithFields(log.Fields{
			"group":   g.Name,
			"network": networkType.String(),
		}).Infof("Group is alive")
	} else {
		log.WithFields(log.Fields{
			"group":   g.Name,
			"network": networkType.String(),
		}).Infof("Group has no dialer alive")
	}
	g.networkIndexToAlive[index] = &alive
	g.aliveChangeCallback(alive, networkType)
}

func (g *DialerGroup) logDialerSelection(oldBestDialer *dialer.Dialer, newBestDialer *dialer.Dialer, networkType *common.NetworkType) {
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
			string(g.selectionPolicy.Policy): common.LatencyString(g.dialerToLatency[newBestDialer], g.dialerToLatencyOffset[newBestDialer]),
			"_new_dialer":                    newDialerName,
			"_old_dialer":                    oldDialerName,
			"group":                          g.Name,
			"network":                        networkType.String(),
		}).Warnf("Group %vselects dialer", re)
	} else {
		log.WithFields(log.Fields{
			string(g.selectionPolicy.Policy): common.LatencyString(g.dialerToLatency[newBestDialer], g.dialerToLatencyOffset[newBestDialer]),
			"_new_dialer":                    newDialerName,
			"_old_dialer":                    oldDialerName,
			"group":                          g.Name,
			"network":                        networkType.String(),
		}).Infof("Group %vselects dialer", re)
	}
}

func (g *DialerGroup) NotifyStatusChange(dialer *dialer.Dialer) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.updateDialerAliveState(dialer, dialer.Alive())

	latency, hasLatency := g.getLatencyData(dialer)
	if hasLatency {
		g.dialerToLatency[dialer] = latency
	}

	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		switch g.selectionPolicy.Policy {
		case consts.DialerSelectionPolicy_MinLastLatency,
			consts.DialerSelectionPolicy_MinAverage10Latencies,
			consts.DialerSelectionPolicy_MinMovingAverageLatencies:
			oldDialer := g.networkIndexToDialer[i]
			newDialer := g.calcMinLatency(networkType)
			if oldDialer != newDialer {
				newLatency := g.getSortingLatency(newDialer)
				oldLatency := g.getSortingLatency(oldDialer)
				if oldDialer != nil &&
					g.dialerToAlive[oldDialer] &&
					g.getPriority(oldDialer) == g.getPriority(newDialer) &&
					hasLatency {
					if newLatency >= oldLatency || newLatency >= oldLatency-g.tolerance {
						continue
					}
				}
				g.networkIndexToDialer[i] = newDialer
				g.logDialerSelection(oldDialer, newDialer, networkType)
				g.printLatencies(networkType, log.WarnLevel)
			}
			g.handleAliveStateChange(newDialer != nil, networkType)
		case consts.DialerSelectionPolicy_Random:
			g.networkIndexToDialers[i] = g.getSortedHighestPriorityAliveDialers(networkType)
			g.handleAliveStateChange(len(g.networkIndexToDialers[i]) > 0, networkType)
		case consts.DialerSelectionPolicy_Fixed:
			if dialer == g.Dialers[g.selectionPolicy.FixedIndex] {
				g.handleAliveStateChange(isDialerAlive(dialer, networkType), networkType)
			}
		}
	}
}

func (g *DialerGroup) calcMinLatency(networkType *common.NetworkType) (dialer *dialer.Dialer) {
	minLatency := time.Hour
	highestPriority := math.MinInt

	for _, d := range g.Dialers {
		if !isDialerAlive(d, networkType) {
			continue
		}

		priority := g.getPriority(d)
		sortingLatency := g.getSortingLatency(d)

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
