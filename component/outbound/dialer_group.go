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
	Name            string
	Kind            GroupKind
	TargetKind      TargetKind
	Dialers         []*dialer.Dialer
	selectionPolicy dialer.DialerSelectionPolicy
	selector        *latencyBasedSelector

	dialerToAnnotation map[*dialer.Dialer]*dialer.Annotation
	notifyMu           sync.Mutex
	networkAvailable   [common.NetworkTypeCount]bool
	availabilityKnown  bool
	startupReady       chan struct{}
	startupReadyOnce   sync.Once
	publishNetwork     func(available bool, networkType *common.NetworkType) error
	closed             atomic.Bool
	closeOnce          sync.Once
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

	for i, d := range dialers {
		g.dialerToAnnotation[d] = dialersAnnotations[i]
	}

	if kind == GroupKindSelector {
		switch selectionPolicy.Policy {
		case "", consts.DialerSelectionPolicy_Fixed, consts.DialerSelectionPolicy_Random:
		case consts.DialerSelectionPolicy_MinAverage10Latencies,
			consts.DialerSelectionPolicy_MinMovingAverageLatencies,
			consts.DialerSelectionPolicy_MinLastLatency:
			g.selector = &latencyBasedSelector{dialerGroup: g, tolerance: option.CheckTolerance}
		default:
			panic(fmt.Sprintf("unsupported selection policy %q", selectionPolicy.Policy))
		}
		g.startupReady = startupBarrier(g.policyDialers())
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

func startupBarrier(dialers []*dialer.Dialer) chan struct{} {
	for _, d := range dialers {
		if d.InitialCheckMode() == dialer.InitialCheckBlocking {
			return make(chan struct{})
		}
	}
	return nil
}

func (g *DialerGroup) releaseStartupReady(available bool) {
	if g.startupReady == nil {
		return
	}
	g.startupReadyOnce.Do(func() {
		if !available {
			log.WithField("group", g.Name).Info("Blocking connectivity checks completed without a usable candidate; startup continues")
		}
		close(g.startupReady)
	})
}

// Close retires all dialers owned by the group.
func (g *DialerGroup) Close() error {
	g.closeOnce.Do(func() {
		g.closed.Store(true)
		g.releaseStartupReady(true)
		// Drain notifications that passed the closed check before shutdown.
		g.notifyMu.Lock()
		g.notifyMu.Unlock()
		for _, d := range g.Dialers {
			_ = d.Close()
		}
	})
	return nil
}

func (g *DialerGroup) initializeConnectivity() error {
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

func (g *DialerGroup) Connectivity() (stats.GroupState, stats.GroupAvailability) {
	g.notifyMu.Lock()
	defer g.notifyMu.Unlock()
	return g.aggregateConnectivity().state(g.anyNetworkAvailable()), stats.DefaultStore.GetGroup(g.Name)
}

// EnableSelectionTolerance switches latency selection from startup best-so-far
// behavior to the configured steady-state hysteresis.
func (g *DialerGroup) EnableSelectionTolerance() {
	if g.selector != nil {
		g.selector.EnableTolerance()
	}
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
			log.WithField("group", g.Name).Infoln("Group is available")
		} else {
			log.WithField("group", g.Name).Infoln("Group is unavailable")
		}
	}
	g.availabilityKnown = true
	stats.DefaultStore.RecordGroup(g.Name, available)
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

func (g *DialerGroup) policyDialers() []*dialer.Dialer {
	if g.selectionPolicy.Policy == "" || g.selectionPolicy.Policy == consts.DialerSelectionPolicy_Fixed {
		index := g.selectionPolicy.FixedIndex
		if index < 0 || index >= len(g.Dialers) {
			return nil
		}
		return g.Dialers[index : index+1]
	}
	return g.Dialers
}

func (g *DialerGroup) fixedDialer() *dialer.Dialer {
	index := g.selectionPolicy.FixedIndex
	if index < 0 || index >= len(g.Dialers) {
		return nil
	}
	return g.Dialers[index]
}

type groupConnectivity struct {
	networks     [common.NetworkTypeCount]bool
	stable       bool
	pending      bool
	blockingDone bool
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
	hasBlocking := g.startupReady != nil
	aggregate := groupConnectivity{blockingDone: hasBlocking}
	for _, d := range g.policyDialers() {
		snapshot := d.ConnectivitySnapshot()
		usable := false
		for i, available := range snapshot.Usable {
			aggregate.networks[i] = aggregate.networks[i] || available
			usable = usable || available
		}
		aggregate.stable = aggregate.stable || (usable && !snapshot.ConfirmingFailure)
		if !snapshot.InitialCheckDone && (!hasBlocking || d.InitialCheckMode() == dialer.InitialCheckBlocking) {
			aggregate.pending = true
		}
		if d.InitialCheckMode() == dialer.InitialCheckBlocking && !snapshot.InitialCheckDone {
			aggregate.blockingDone = false
		}
		aggregate.pending = aggregate.pending || (usable && snapshot.ConfirmingFailure)
	}
	return aggregate
}

// SelectedDialer returns the dialer currently selected for the given network
// type. It returns nil for policies without a stable selection (e.g. random)
// or when no dialer is alive.
func (g *DialerGroup) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
	if g.closed.Load() {
		return nil
	}
	var selected *dialer.Dialer
	if g.Kind != GroupKindSelector {
		selected = g.Dialers[0]
	} else {
		switch g.selectionPolicy.Policy {
		case "", consts.DialerSelectionPolicy_Fixed:
			selected = g.fixedDialer()
		case consts.DialerSelectionPolicy_Random:
			return nil
		default:
			selected = g.selector.SelectedDialer(networkType)
		}
	}
	if selected == nil || !selected.Usable(networkType) {
		return nil
	}
	return selected
}

// SelectFallbackIpVersion selects a dialer and optionally tries the other IP family.
func (g *DialerGroup) SelectFallbackIpVersion(networkType common.NetworkType, strictIpVersion bool) (*dialer.Dialer, common.NetworkType, bool, error) {
	selected, err := g.Select(&networkType)
	if !strictIpVersion && errors.Is(err, ErrNoAliveDialer) {
		networkType.IpVersion = (consts.IpVersion_X - networkType.IpVersion.ToIpVersionType()).ToIpVersionStr()
		selected, err = g.Select(&networkType)
		return selected, networkType, true, err
	}
	return selected, networkType, false, err
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
		if !d.Usable(networkType) {
			return nil, ErrNoAliveDialer
		}
		return d, nil
	}
	var selected *dialer.Dialer
	switch g.selectionPolicy.Policy {
	case "", consts.DialerSelectionPolicy_Fixed:
		selected = g.fixedDialer()
	case consts.DialerSelectionPolicy_Random:
		selected = g.selectRandom(networkType)
	default:
		selected = g.selector.Select(networkType)
	}
	if selected == nil || !selected.Usable(networkType) {
		return nil, ErrNoAliveDialer
	}
	return selected, nil
}

func (g *DialerGroup) DialerChanged(dialer *dialer.Dialer, forceSelection dialer.SelectionForceMask) {
	g.notifyMu.Lock()
	defer g.notifyMu.Unlock()
	if g.closed.Load() {
		return
	}
	if g.Kind != GroupKindSelector {
		return
	}
	if g.selector != nil {
		g.selector.Refresh(dialer, forceSelection)
	}
	connectivity := g.aggregateConnectivity()
	previouslyAvailable := g.anyNetworkAvailable()
	var err error
	for i := range g.networkAvailable {
		networkType := common.NetworkIndex(i).NetworkType()
		err = errors.Join(err, g.publishNetworkAvailable(networkType, connectivity.networks[i]))
	}
	available := g.anyNetworkAvailable()
	if g.availabilityKnown || available || (err == nil && !connectivity.pending) {
		g.recordAvailability(previouslyAvailable, available)
	}
	if err != nil {
		log.WithField("group", g.Name).Warnf("Failed to publish group availability: %v", err)
	}
	if available || connectivity.blockingDone {
		g.releaseStartupReady(available)
	}
}
