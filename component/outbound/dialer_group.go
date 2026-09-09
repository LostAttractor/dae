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
	Name       string
	Kind       GroupKind
	TargetKind TargetKind
	Dialers    []*dialer.Dialer
	// CheckAsync skips the startup barrier for every dialer in this group.
	// Set it before starting connectivity checks.
	CheckAsync      bool
	selectionPolicy dialer.DialerSelectionPolicy
	selector        *latencyBasedSelector
	selectionIndex  int
	connections     connectionPolicy

	dialerToAnnotation map[*dialer.Dialer]*dialer.Annotation
	// mu serializes selection, connection generations and availability publication.
	mu                sync.Mutex
	networkAvailable  [common.NetworkTypeCount]bool
	availabilityKnown bool
	statsDeferred     bool
	startupReady      chan struct{}
	startupReadyOnce  sync.Once
	publishNetwork    func(available bool, networkType *common.NetworkType) error
	closed            atomic.Bool
	closeOnce         sync.Once
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	kind GroupKind,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	selectionPolicy dialer.DialerSelectionPolicy,
	publishNetwork func(available bool, networkType *common.NetworkType) error,
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
		publishNetwork:     publishNetwork,
	}
	g.selectionIndex = selectionPolicy.FixedIndex

	for i, d := range dialers {
		g.dialerToAnnotation[d] = dialersAnnotations[i]
	}

	if kind == GroupKindSelector {
		switch selectionPolicy.Policy {
		case "", consts.DialerSelectionPolicy_Fixed, consts.DialerSelectionPolicy_Selector, consts.DialerSelectionPolicy_Random:
		case consts.DialerSelectionPolicy_MinAverage10Latencies,
			consts.DialerSelectionPolicy_MinMovingAverageLatencies,
			consts.DialerSelectionPolicy_MinLastLatency:
			g.selector = &latencyBasedSelector{dialerGroup: g, tolerance: option.CheckTolerance}
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
		g.availabilityKnown = true
		for i := range g.networkAvailable {
			g.networkAvailable[i] = true
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

func (g *DialerGroup) releaseStartupReady(available bool) {
	if g.startupReady == nil {
		return
	}
	g.startupReadyOnce.Do(func() {
		if !available {
			log.WithField("group", g.Name).Warn("Initial checks found no usable node; startup continues with no_connectivity_behavior")
		}
		close(g.startupReady)
	})
}

// Close retires all dialers owned by the group.
func (g *DialerGroup) Close() error {
	g.closeOnce.Do(func() {
		g.closed.Store(true)
		// Drain notifications that passed the closed check before shutdown.
		g.mu.Lock()
		g.releaseStartupReady(true)
		g.mu.Unlock()
		for _, d := range g.Dialers {
			_ = d.Close()
		}
	})
	return nil
}

func (g *DialerGroup) initializeConnectivity() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed.Load() {
		return net.ErrClosed
	}
	if !g.ChecksConnectivity() {
		return nil
	}
	if !g.CheckAsync && len(g.policyDialers()) != 0 && g.startupReady == nil {
		g.startupReady = make(chan struct{})
	}
	var err error
	for i := range g.networkAvailable {
		networkType := common.NetworkIndex(i).NetworkType()
		if g.publishNetwork != nil {
			if callbackErr := g.publishNetwork(false, networkType); callbackErr != nil {
				err = errors.Join(err, callbackErr)
			}
		}
	}
	if err != nil {
		return err
	}
	g.networkAvailable = [common.NetworkTypeCount]bool{}
	if len(g.policyDialers()) == 0 {
		g.recordAvailability(false, false)
	}
	return nil
}

// StartConnectivityChecks registers the group's checkers with the shared start
// gate. The returned channel is nil when the group does not block startup.
func (g *DialerGroup) StartConnectivityChecks(start <-chan struct{}) (<-chan struct{}, error) {
	if err := g.initializeConnectivity(); err != nil {
		return nil, err
	}
	for _, d := range g.Dialers {
		d.ActivateCheck(start)
	}
	return g.startupReady, nil
}

// DeferStats isolates a candidate group before its connectivity checks start.
func (g *DialerGroup) DeferStats() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.statsDeferred = true
	for _, d := range g.Dialers {
		d.DeferStats()
	}
}

// PublishStats follows process-store reconciliation after the old plane retires.
func (g *DialerGroup) PublishStats() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.statsDeferred {
		return
	}
	for _, d := range g.Dialers {
		d.PublishStats()
	}
	if g.availabilityKnown {
		stats.DefaultStore.RecordGroup(g.Name, g.anyNetworkAvailable())
	}
	g.statsDeferred = false
}

func (g *DialerGroup) Connectivity() (stats.GroupState, stats.GroupAvailability) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.aggregateConnectivity().state(g.anyNetworkAvailable()), stats.DefaultStore.GetGroup(g.Name)
}

func (g *DialerGroup) anyNetworkAvailable() bool {
	for _, available := range g.networkAvailable {
		if available {
			return true
		}
	}
	return false
}

func (g *DialerGroup) recordAvailability(previous, available bool) {
	if g.availabilityKnown && previous == available {
		return
	}
	if g.availabilityKnown || available {
		if available {
			log.WithField("group", g.Name).Info("Group is available")
		} else {
			log.WithField("group", g.Name).Warn("Group has no usable node; using no_connectivity_behavior")
		}
	}
	g.availabilityKnown = true
	if !g.statsDeferred {
		stats.DefaultStore.RecordGroup(g.Name, available)
	}
}

func (g *DialerGroup) publishNetworkAvailable(networkType *common.NetworkType, available bool) error {
	index := networkType.Index()
	if g.networkAvailable[index] == available {
		return nil
	}
	if g.publishNetwork != nil {
		if err := g.publishNetwork(available, networkType); err != nil {
			return err
		}
	}
	g.networkAvailable[index] = available
	return nil
}

type groupConnectivity struct {
	networks    [common.NetworkTypeCount]bool
	stable      bool
	pending     bool
	initialDone bool
}

func (c groupConnectivity) state(published bool) stats.GroupState {
	if c.stable && published {
		return stats.GroupStateAvailable
	}
	if c.pending {
		return stats.GroupStateChecking
	}
	return stats.GroupStateUnavailable
}

func (g *DialerGroup) aggregateConnectivity() groupConnectivity {
	aggregate := groupConnectivity{initialDone: true}
	for _, d := range g.policyDialers() {
		snapshot := d.ConnectivitySnapshot()
		usable := false
		for i, available := range snapshot.Usable {
			aggregate.networks[i] = aggregate.networks[i] || available
			usable = usable || available
		}
		aggregate.stable = aggregate.stable || (usable && !snapshot.ConfirmingFailure)
		if !snapshot.InitialCheckDone {
			aggregate.pending = true
			aggregate.initialDone = false
		}
		aggregate.pending = aggregate.pending || (usable && snapshot.ConfirmingFailure)
	}
	return aggregate
}

func (g *DialerGroup) DialerChanged(dialer *dialer.Dialer, forceSelection dialer.SelectionForceMask) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed.Load() {
		return
	}
	if g.Kind != GroupKindSelector {
		return
	}
	if g.selector != nil {
		g.selector.refresh(dialer, forceSelection)
	}
	if err := g.updateConnectivity(); err != nil {
		log.WithField("group", g.Name).WithError(err).Error("Failed to update group routing availability")
		return
	}
	g.closeRecoveredConnections()
}

// updateConnectivity runs with mu held for both checker notifications
// and manual selection changes.
func (g *DialerGroup) updateConnectivity() error {
	connectivity := g.aggregateConnectivity()
	previouslyAvailable := g.anyNetworkAvailable()
	var err error
	for i := range g.networkAvailable {
		networkType := common.NetworkIndex(i).NetworkType()
		err = errors.Join(err, g.publishNetworkAvailable(networkType, connectivity.networks[i]))
	}
	if err != nil {
		return err
	}
	available := g.anyNetworkAvailable()
	if g.availabilityKnown || available || !connectivity.pending {
		g.recordAvailability(previouslyAvailable, available)
	}
	if available || connectivity.initialDone {
		g.releaseStartupReady(available)
	}
	return nil
}
