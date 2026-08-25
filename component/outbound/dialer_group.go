/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

var ErrNoDialer = fmt.Errorf("no dialer")
var ErrNoAliveDialer = fmt.Errorf("no alive dialer")

// GroupKind describes how an outbound target selects and checks its dialers.
type GroupKind int

const (
	// GroupKindSelector applies a policy to checked paths. An empty policy means fixed(0).
	GroupKindSelector GroupKind = iota
	// GroupKindSingleAlwaysAlive is a singleton that needs no connectivity check.
	GroupKindSingleAlwaysAlive
	// GroupKindInvisible is a hidden singleton such as the built-in block target.
	GroupKindInvisible
)

type DialerGroup struct {
	Name            string
	Kind            GroupKind
	TargetKind      TargetKind
	Dialers         []*dialer.Dialer
	selectionPolicy dialer.DialerSelectionPolicy
	selector        Selector

	dialerToAnnotation  map[*dialer.Dialer]*dialer.Annotation
	notifyMu            sync.Mutex
	networkAvailable    [4]bool
	networkStateSet     [4]bool
	availabilitySet     bool
	availableCallback   func(available bool, networkType *common.NetworkType) error
	available           atomic.Bool
	closed              atomic.Bool
	closeOnce           sync.Once
	latencyTableLogging atomic.Bool
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	kind GroupKind,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	selectionPolicy dialer.DialerSelectionPolicy,
	availableCallback func(available bool, networkType *common.NetworkType) error,
) *DialerGroup {
	if len(dialers) != len(dialersAnnotations) {
		panic(fmt.Sprintf("unmatched annotations length: %v dialers and %v annotations", len(dialers), len(dialersAnnotations)))
	}
	if kind != GroupKindSelector && len(dialers) != 1 {
		panic(fmt.Sprintf("group kind %d requires exactly one dialer, got %d", kind, len(dialers)))
	}
	switch kind {
	case GroupKindSelector:
		for _, d := range dialers {
			if !d.ChecksConnectivity() {
				panic(fmt.Sprintf("selector group %q requires checked dialers", name))
			}
		}
	case GroupKindSingleAlwaysAlive, GroupKindInvisible:
		if dialers[0].ChecksConnectivity() {
			panic(fmt.Sprintf("unchecked singleton %q cannot use a checked dialer", name))
		}
	default:
		panic(fmt.Sprintf("unsupported group kind %d", kind))
	}

	g := &DialerGroup{
		Name:               name,
		Kind:               kind,
		TargetKind:         TargetKindGroup,
		Dialers:            dialers,
		selectionPolicy:    selectionPolicy,
		dialerToAnnotation: make(map[*dialer.Dialer]*dialer.Annotation),
		availableCallback:  availableCallback,
	}

	for i, d := range dialers {
		g.dialerToAnnotation[d] = dialersAnnotations[i]
	}

	if kind == GroupKindSelector {
		switch selectionPolicy.Policy {
		case "":
			g.selector = NewFixedSelector(g)
		case consts.DialerSelectionPolicy_MinAverage10Latencies,
			consts.DialerSelectionPolicy_MinMovingAverageLatencies,
			consts.DialerSelectionPolicy_MinLastLatency:
			g.selector = NewLatencyBasedSelector(g, option.CheckTolerance)
		case consts.DialerSelectionPolicy_Fixed:
			g.selector = NewFixedSelector(g)
		case consts.DialerSelectionPolicy_Random:
			g.selector = NewRandomSelector(g)
		default:
			panic(fmt.Sprintf("unsupported selection policy %q", selectionPolicy.Policy))
		}
	}

	if g.ChecksConnectivity() {
		for _, d := range dialers {
			d.RegisterDialerGroup(g, selectionPolicy.EmaAlpha, selectionPolicy.TimeoutPenalty)
		}
	}
	if kind == GroupKindSingleAlwaysAlive || kind == GroupKindInvisible {
		g.available.Store(true)
		g.availabilitySet = true
		for i := range g.networkAvailable {
			g.networkAvailable[i] = true
			g.networkStateSet[i] = true
		}
	}

	return g
}

func (g *DialerGroup) SetTargetMetadata(kind TargetKind) *DialerGroup {
	g.TargetKind = kind
	return g
}

func (g *DialerGroup) DisplayPolicy() string {
	if g.TargetKind == TargetKindGroup {
		return string(g.selectionPolicy.Policy)
	}
	return ""
}

// DialerAnnotation returns the immutable selection annotation for a dialer.
func (g *DialerGroup) DialerAnnotation(d *dialer.Dialer) (dialer.Annotation, bool) {
	annotation, ok := g.dialerToAnnotation[d]
	if !ok || annotation == nil {
		return dialer.Annotation{}, false
	}
	return *annotation, true
}

func (g *DialerGroup) ChecksConnectivity() bool {
	return g.Kind == GroupKindSelector
}

// Close stops the connectivity checks of all dialers in the group. It is
// called when the owning control plane is retired; the dialers themselves
// must not be reused afterwards.
func (g *DialerGroup) Close() error {
	g.closeOnce.Do(func() {
		g.closed.Store(true)
		g.notifyMu.Lock()
		g.notifyMu.Unlock()
		for _, d := range g.Dialers {
			_ = d.Close()
			d.UnregisterDialerGroup(g)
		}
	})
	return nil
}

func (g *DialerGroup) InitializeConnectivity() error {
	g.notifyMu.Lock()
	defer g.notifyMu.Unlock()
	if g.closed.Load() {
		return net.ErrClosed
	}
	if !g.ChecksConnectivity() {
		return nil
	}
	var err error
	for i := range g.networkAvailable {
		err = errors.Join(err, g.publishNetworkAvailable(common.IndexToNetworkType(i), false))
	}
	return err
}

func (g *DialerGroup) Available() bool { return g.available.Load() }

func (g *DialerGroup) publishAvailable(available bool) error {
	if g.availabilitySet && g.available.Load() == available {
		return nil
	}
	if g.availabilitySet || available {
		if available {
			log.WithField("group", g.Name).Infoln("Group is available")
		} else {
			log.WithField("group", g.Name).Infoln("Group is unavailable")
		}
	}
	g.available.Store(available)
	g.availabilitySet = true
	stats.RecordGroup(g.Name, available)
	return nil
}

func (g *DialerGroup) publishNetworkAvailable(networkType *common.NetworkType, available bool) error {
	index := common.NetworkTypeToIndex(networkType)
	if g.networkStateSet[index] && g.networkAvailable[index] == available {
		return nil
	}
	if g.availableCallback != nil {
		if err := g.availableCallback(available, networkType); err != nil {
			return err
		}
	}
	g.networkAvailable[index] = available
	g.networkStateSet[index] = true
	aggregate := false
	for i, state := range g.networkAvailable {
		aggregate = aggregate || g.networkStateSet[i] && state
	}
	return g.publishAvailable(aggregate)
}

func (g *DialerGroup) networkUsable(networkType *common.NetworkType) bool {
	if g.selectionPolicy.Policy == consts.DialerSelectionPolicy_Fixed {
		index := g.selectionPolicy.FixedIndex
		return index >= 0 && index < len(g.Dialers) && isDialerAlive(g.Dialers[index], networkType)
	}
	return len(preferredAliveDialers(g.Dialers, networkType)) > 0
}

// Returns the priority given an observed latency.
// If a "ConditionalPriority" is present, it is applied;
// Otherwise the default fixed Priority is returned.
func (g *DialerGroup) GetPriority(d *dialer.Dialer, latency time.Duration) int {
	return g.dialerToAnnotation[d].PriorityAt(latency)
}

func (g *DialerGroup) GetSelectionPolicy() consts.DialerSelectionPolicy {
	return g.selectionPolicy.Policy
}

// SelectedDialer returns the dialer currently selected for the given network
// type. It returns nil for policies without a stable selection (e.g. random)
// or when no dialer is alive.
func (g *DialerGroup) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
	if g.closed.Load() {
		return nil
	}
	if g.Kind != GroupKindSelector {
		d := g.Dialers[0]
		if isDialerAlive(d, networkType) {
			return d
		}
		return nil
	}
	return g.selector.SelectedDialer(networkType)
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

func (g *DialerGroup) Select(networkType *common.NetworkType) (*dialer.Dialer, error) {
	if g.closed.Load() {
		return nil, net.ErrClosed
	}
	if len(g.Dialers) == 0 {
		return nil, ErrNoDialer
	}
	if g.Kind != GroupKindSelector {
		d := g.Dialers[0]
		if !isDialerAlive(d, networkType) {
			return nil, ErrNoAliveDialer
		}
		return d, nil
	}
	for {
		if g.closed.Load() {
			return nil, net.ErrClosed
		}
		selected := g.selector.Select(networkType)
		if selected == nil {
			return nil, ErrNoAliveDialer
		}
		if isDialerAlive(selected, networkType) {
			return selected, nil
		}
		if selected.Alive() {
			selected.NotifyStatusChange()
		}
		selected.ReportUnavailable()
	}
}

func (g *DialerGroup) PrintLatency() {
	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		if g.Kind == GroupKindSelector {
			g.selector.PrintLatencies(networkType, log.Infoln)
		} else {
			printDialerLatency(g, g.Dialers[0], networkType, log.Infoln)
		}
	}
	// Initial checks update selectors incrementally. Enable detailed tables
	// only after this complete startup snapshot has been printed.
	g.latencyTableLogging.Store(true)
}

func (g *DialerGroup) NotifyStatusChange(dialer *dialer.Dialer) {
	g.notifyMu.Lock()
	defer g.notifyMu.Unlock()
	if g.closed.Load() {
		return
	}
	if g.Kind != GroupKindSelector {
		return
	}
	g.selector.NotifyStatusChange(dialer)
	var err error
	for i := range g.networkAvailable {
		networkType := common.IndexToNetworkType(i)
		err = errors.Join(err, g.publishNetworkAvailable(networkType, g.networkUsable(networkType)))
	}
	if err != nil {
		log.WithField("group", g.Name).Warnf("Failed to publish group availability: %v", err)
	}
}
