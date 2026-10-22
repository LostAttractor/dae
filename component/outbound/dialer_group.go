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

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
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
	automatic       *automaticSelection
	selectionIndex  int
	connections     connectionPolicy

	dialerToAnnotation map[*dialer.Dialer]*dialer.Annotation
	// mu serializes selection, connection generations and availability publication.
	mu                sync.Mutex
	networkAvailable  [common.NetworkTypeCount]bool
	networkElecting   [common.NetworkTypeCount]bool
	availabilityKnown bool
	statsDeferred     bool
	startupReady      chan struct{}
	startupReadyOnce  sync.Once
	observers         map[*connectivityObserver]struct{}
	checksStarted     bool
	closed            atomic.Bool
	closeOnce         sync.Once
}

// Connectivity is one network's routing projection. While the network is
// unavailable, Electing reports that an automatic group elects a path and no
// election has failed since the group last served the network, as at startup:
// a request waits for that election instead of degrading. Fallback is the
// generation of the group's no-connectivity fallback connections if a
// connection policy can end it, and nil otherwise.
type Connectivity struct {
	Network   *common.NetworkType
	Available bool
	Electing  bool
	Fallback  *netproxy.Lease
}

type connectivityObserver struct {
	publish func(Connectivity) error
}

// ObserveConnectivity immediately initializes one routing projection and keeps
// it current until detached. A group is independent of any particular BPF map.
func (g *DialerGroup) ObserveConnectivity(publish func(Connectivity) error) (func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, available := range g.networkAvailable {
		if err := publish(g.connectivity(common.NetworkIndex(i), available, g.networkElecting[i])); err != nil {
			return nil, err
		}
	}
	observer := &connectivityObserver{publish}
	if g.observers == nil {
		g.observers = make(map[*connectivityObserver]struct{})
	}
	g.observers[observer] = struct{}{}
	return sync.OnceFunc(func() { g.mu.Lock(); delete(g.observers, observer); g.mu.Unlock() }), nil
}

// Caller holds mu.
func (g *DialerGroup) connectivity(network common.NetworkIndex, available, electing bool) Connectivity {
	update := Connectivity{Network: network.NetworkType(), Available: available}
	if !available {
		update.Electing = electing
		update.Fallback = g.interruptibleFallback(update.Network)
	}
	return update
}

func (g *DialerGroup) publishConnectivity(network common.NetworkIndex, available, electing bool) (err error) {
	if len(g.observers) == 0 {
		return nil
	}
	update := g.connectivity(network, available, electing)
	for observer := range g.observers {
		err = errors.Join(err, observer.publish(update))
	}
	return err
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	kind GroupKind,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	selectionPolicy dialer.DialerSelectionPolicy,
) *DialerGroup {
	selectionPolicy = selectionPolicy.WithDefaults()
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
	}
	g.selectionIndex = selectionPolicy.FixedIndex

	for i, d := range dialers {
		g.dialerToAnnotation[d] = dialersAnnotations[i]
	}

	if kind == GroupKindSelector {
		switch selectionPolicy.Policy {
		case "", consts.DialerSelectionPolicy_Fixed, consts.DialerSelectionPolicy_Selector:
		case consts.DialerSelectionPolicy_MinAverage10Latencies,
			consts.DialerSelectionPolicy_Random,
			consts.DialerSelectionPolicy_Failover,
			consts.DialerSelectionPolicy_MinMovingAverageLatencies,
			consts.DialerSelectionPolicy_MinLastLatency:
			g.automatic = newAutomaticSelection(g, option.CheckTolerance)
		default:
			panic(fmt.Sprintf("unsupported selection policy %q", selectionPolicy.Policy))
		}
	}

	if g.ChecksConnectivity() {
		for _, d := range dialers {
			d.RegisterDialerGroup(g, selectionPolicy)
		}
		g.updateCheckTracking()
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

// Close releases the group's members of their shared path runtimes.
func (g *DialerGroup) Close() error {
	g.closeOnce.Do(func() {
		g.closed.Store(true)
		// Drain notifications that passed the closed check before shutdown.
		g.mu.Lock()
		g.releaseStartupReady(true)
		g.closeRemovedFallbacks()
		g.mu.Unlock()
		if g.automatic != nil {
			g.automatic.close()
		}
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
	if len(g.policyDialers()) != 0 && g.startupReady == nil {
		g.startupReady = make(chan struct{})
	}
	// An automatic group elects its first path; requests wait for it.
	electing := g.automatic != nil
	var err error
	for i := range g.networkAvailable {
		err = errors.Join(err, g.publishConnectivity(common.NetworkIndex(i), false, electing))
	}
	if err != nil {
		return err
	}
	g.networkAvailable = [common.NetworkTypeCount]bool{}
	for i := range g.networkElecting {
		g.networkElecting[i] = electing
	}
	if len(g.policyDialers()) == 0 {
		g.recordAvailability(false, false)
	}
	return nil
}

// StartConnectivityChecks registers the group's checkers with the shared start
// gate. The returned channel describes readiness, including when the workers
// already exist. Each preparing control plane decides whether to wait on it.
func (g *DialerGroup) StartConnectivityChecks(start <-chan struct{}) (<-chan struct{}, error) {
	g.mu.Lock()
	if g.checksStarted {
		g.mu.Unlock()
		return g.StartupReady()
	}
	g.checksStarted = true
	g.mu.Unlock()
	if err := g.initializeConnectivity(); err != nil {
		return nil, err
	}
	for _, d := range g.Dialers {
		d.ActivateCheck(start)
		// Another group may already have checked this shared runtime.
		g.DialerChanged(d, dialer.SelectionForceNone)
	}
	if g.automatic != nil {
		g.automatic.start(start)
	}
	return g.startupReady, nil
}

// StartupReady exposes the shared workers' current readiness. Waiting policy is
// owned by the candidate plane, so preparing it cannot change an active plane.
func (g *DialerGroup) StartupReady() (<-chan struct{}, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed.Load() {
		return nil, net.ErrClosed
	}
	if !g.ChecksConnectivity() || len(g.policyDialers()) == 0 {
		return nil, nil
	}
	if g.startupReady == nil {
		g.startupReady = make(chan struct{})
	}
	if err := g.updateConnectivity(); err != nil {
		return nil, err
	}
	return g.startupReady, nil
}

// DeferStats isolates a candidate group before its connectivity checks start.
func (g *DialerGroup) DeferStats() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.checksStarted {
		return
	}
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

func (g *DialerGroup) Connectivity() (api.GroupState, api.GroupAvailability) {
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

// Available reports the connectivity the group last published for the network.
func (g *DialerGroup) Available(network common.NetworkType) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.networkAvailable[network.Index()]
}

// Electing reports whether the group published the network as unavailable
// while it elects a path.
func (g *DialerGroup) Electing(network common.NetworkType) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.networkElecting[network.Index()]
}

func (g *DialerGroup) publishNetwork(network common.NetworkIndex, available, electing bool) error {
	if g.networkAvailable[network] == available && g.networkElecting[network] == electing {
		return nil
	}
	if err := g.publishConnectivity(network, available, electing); err != nil {
		return err
	}
	g.networkAvailable[network], g.networkElecting[network] = available, electing
	return nil
}

type groupConnectivity struct {
	retain      [common.NetworkTypeCount]bool
	networks    [common.NetworkTypeCount]bool
	electing    [common.NetworkTypeCount]bool
	stable      bool
	pending     bool
	initialDone bool
}

func (c groupConnectivity) state(published bool) api.GroupState {
	if c.stable && published {
		return api.GroupStateAvailable
	}
	if c.pending {
		return api.GroupStateChecking
	}
	return api.GroupStateUnavailable
}

func (g *DialerGroup) aggregateConnectivity() groupConnectivity {
	if g.automatic != nil {
		if snapshot, started := g.automatic.connectivity(); started {
			return snapshot
		}
	}
	aggregate := groupConnectivity{initialDone: true}
	for _, d := range g.policyDialers() {
		snapshot := d.ConnectivitySnapshot()
		usable := false
		for i, available := range snapshot.Usable {
			aggregate.networks[i] = aggregate.networks[i] || available
			usable = usable || available
		}
		aggregate.stable = aggregate.stable || usable && !snapshot.ConfirmingFailure
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
	if g.automatic != nil {
		if changed, ready := g.automatic.observe(dialer, forceSelection); ready {
			g.publishAutomaticLocked(changed)
		}
		return
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
		// Keep already admitted proxy routes while their bounded replacement
		// election runs. Only a completed unsuccessful election publishes down.
		if connectivity.retain[i] && !connectivity.networks[i] {
			continue
		}
		err = errors.Join(err, g.publishNetwork(common.NetworkIndex(i), connectivity.networks[i], connectivity.electing[i]))
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

// automaticChanged publishes changes the selection made outside the group lock.
func (g *DialerGroup) automaticChanged(changed commits) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed.Load() {
		return
	}
	g.publishAutomaticLocked(changed)
}

// publishAutomaticLocked reads each committed choice again under mu, so a
// delayed publication cannot restore an older one. Only a commit changes
// connection generations: a scheduler wake must not replace the path chosen by
// a random-policy request.
func (g *DialerGroup) publishAutomaticLocked(changed commits) {
	for network, committed := range changed {
		if !committed {
			continue
		}
		g.updateConnectionSelection(common.NetworkIndex(network).NetworkType(), g.automatic.selectedDialer(common.NetworkIndex(network)))
	}
	if err := g.updateConnectivity(); err != nil {
		log.WithField("group", g.Name).WithError(err).Error("Failed to update group routing availability")
		return
	}
	g.closeRecoveredConnections()
}
