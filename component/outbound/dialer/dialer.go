/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type DialerGroup interface {
	DialerChanged(d *Dialer, forceSelection SelectionForceMask)
}

// SelectionForceMask identifies networks whose selector refresh ignores tolerance.
type SelectionForceMask uint8

const (
	SelectionForceNone SelectionForceMask = 0
)

// SelectionForceFor returns a mask containing one valid network.
func SelectionForceFor(index common.NetworkIndex) SelectionForceMask {
	if !index.Valid() {
		return SelectionForceNone
	}
	return 1 << index
}

// Contains reports whether tolerance should be ignored for a network.
func (m SelectionForceMask) Contains(index common.NetworkIndex) bool {
	return m&SelectionForceFor(index) != 0
}

type groupBinding struct {
	observer DialerGroup
	// The fixed ten-check history is owned by Dialer.mu.
	latencies      [10]time.Duration
	failed         [10]bool
	next, count    int
	movingAverage  time.Duration
	emaAlpha       float64
	timeoutPenalty time.Duration
}

func (g *groupBinding) recordLatency(latency time.Duration, success bool) {
	sample := latency
	if !success {
		sample = g.timeoutPenalty
	}
	if g.movingAverage == 0 {
		g.movingAverage = sample
	} else {
		g.movingAverage = time.Duration(float64(g.movingAverage)*(1-g.emaAlpha) + float64(sample)*g.emaAlpha)
	}
	g.latencies[g.next], g.failed[g.next] = sample, !success
	g.next = (g.next + 1) % len(g.latencies)
	g.count = min(g.count+1, len(g.latencies))
}

type networkState uint8

// networkState records irreversible mode capability. Reachability is shared
// by all supported modes through Dialer.health.
const (
	networkUntested networkState = iota
	networkUnknown
	networkSupported
	networkUnsupported
)

type healthPhase uint8

const (
	healthUnhealthy healthPhase = iota
	healthHealthy
	healthConfirming
)

func (p healthPhase) usable() bool {
	return p == healthHealthy || p == healthConfirming
}

type checkRequestReason uint8

const (
	checkRequestDataPlane checkRequestReason = 1 << iota
	checkRequestEnvironment
	checkRequestManual
)

type Dialer struct {
	*pathRuntime
	*Property
	statsKey string
	statsID  string
	stats    dialerStats
	// Member state is protected by the shared runtime's mu.
	group        *groupBinding
	checkEnabled bool
	active       bool
	closed       bool
	closeOnce    sync.Once
}

// pathRuntime owns a complete physical path and its connectivity worker.
// Dialers are group-local members; the last member stops this runtime.
type pathRuntime struct {
	*GlobalOption
	netproxy.Dialer
	name        string
	runtime     *netproxy.Runtime
	session     netproxy.Session
	members     map[*Dialer]struct{}
	lastLatency *latencySample

	checksConnectivity bool
	health             healthPhase
	healthSeq          uint64
	observedSessionSeq uint64
	statusRevision     uint64
	recovery           recoveryProgress
	lastFailure        *FailureSnapshot
	resourceFailures   map[uint64]resourceFailureProgress
	activeProbes       int
	failureReportedAt  time.Time
	failureGeneration  uint64
	pendingCheck       checkRequestReason
	networks           [common.NetworkTypeCount]networkState
	pendingForce       SelectionForceMask

	mu sync.RWMutex

	checkCh chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc

	checkActivated bool
	checkPaused    bool
	checkRunning   bool
	checkProbing   bool // The running operation includes a connectivity probe.
	checkedAt      time.Time
	checkWG        sync.WaitGroup
	retireOnce     sync.Once
	// Protected by mu. Retains keep an existing intercepted client connection
	// able to open further upstream requests after its control plane closes.
	retains       int
	checksStopped bool
}

type SelectionSnapshot struct {
	Usable     bool
	Support    api.NetworkSupportState
	HasLatency bool
	Latency    api.LatencyStats
}

// ConnectivitySnapshot is the state needed to aggregate a dialer into its
// group. It deliberately excludes process-lifetime statistics.
type ConnectivitySnapshot struct {
	Usable            [common.NetworkTypeCount]bool
	InitialCheckDone  bool
	ConfirmingFailure bool
}

func supportState(state networkState) api.NetworkSupportState {
	switch state {
	case networkSupported:
		return api.NetworkSupportConfirmed
	case networkUnsupported:
		return api.NetworkSupportUnsupported
	default:
		return api.NetworkSupportUnknown
	}
}

// RuntimeSnapshot is a coherent view of a dialer's current connectivity state.
// Process-lifetime availability statistics are sampled after releasing its lock.
type RuntimeSnapshot struct {
	Revision           uint64
	ObservedSessionSeq uint64
	Recovery           RecoverySnapshot
	Failure            *FailureSnapshot
	Healthy            bool
	InitialCheckDone   bool
	CheckEnabled       bool
	Checking           bool
	CheckedAt          time.Time
	ConfirmingFailure  bool
	SupportState       [common.NetworkTypeCount]api.NetworkSupportState
	Session            netproxy.StateEvent
	HasSession         bool
	HasLatency         bool
	Latency            api.LatencyStats
	Availability       api.Availability
}

type GlobalOption struct {
	D.ExtraOption
	SoMarkFromDae     uint32
	Mptcp             bool
	DNSResolver       string
	CheckDnsOptionRaw CheckDnsOptionRaw
	CheckInterval     time.Duration
	CheckIntervalMax  time.Duration
	CheckTolerance    time.Duration
}

type Property struct {
	D.Property
	SubscriptionTag string
	Hops            []Hop
	Egress          *api.NodeEgress
}

type Hop struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Subtag   string `json:"subtag"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}

func NewGlobalOption(global *config.Global) *GlobalOption {
	return &GlobalOption{
		SoMarkFromDae:       common.EffectiveSoMarkFromDae(global.SoMarkFromDae),
		Mptcp:               global.Mptcp,
		DNSResolver:         global.DNSResolver,
		AllowInsecure:       global.AllowInsecure,
		TlsImplementation:   global.TlsImplementation,
		UtlsImitate:         global.UtlsImitate,
		BandwidthMaxTx:      global.BandwidthMaxTx,
		BandwidthMaxRx:      global.BandwidthMaxRx,
		TlsFragment:         global.TlsFragment,
		TlsFragmentLength:   global.TlsFragmentLength,
		TlsFragmentInterval: global.TlsFragmentInterval,
		UDPHopInterval:      global.UDPHopInterval,
		CheckDnsOptionRaw:   CheckDnsOptionRaw{Raw: global.UdpCheckDns},
		CheckInterval:       global.CheckInterval,
		CheckIntervalMax:    global.CheckIntervalMax,
		CheckTolerance:      global.CheckTolerance,
	}
}

func NewDialer(runtime *netproxy.Runtime, option *GlobalOption, property *Property, checksConnectivity bool, statsScope string) *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	session := runtime.Session()
	d := &Dialer{
		pathRuntime: &pathRuntime{
			GlobalOption:       option,
			Dialer:             runtime.Dialer(),
			name:               property.Name,
			runtime:            runtime,
			session:            session,
			checksConnectivity: checksConnectivity,
			checkCh:            make(chan struct{}, 1),
			statusRevision:     1,
			recovery:           recoveryProgress{Phase: RecoveryQueued},
			ctx:                ctx,
			cancel:             cancel,
		},
		Property:     property,
		checkEnabled: true,
		active:       true,
	}
	if !checksConnectivity {
		if session == nil {
			d.recovery.Phase = RecoveryReady
		}
		d.health = healthHealthy
		for i := range d.networks {
			d.networks[i] = networkSupported
		}
	}
	if session != nil {
		snapshot := session.Snapshot()
		if !checksConnectivity {
			if snapshot.Accepting {
				d.healthSeq = snapshot.ReadinessVersion
			} else {
				d.health = healthUnhealthy
			}
		}
	}
	d.statsKey = makeStatsKey(property, statsScope)
	d.statsID = stats.NodeID(d.statsKey)
	d.members = map[*Dialer]struct{}{d: {}}
	return d
}

func composeStatsIdentity(parts ...string) string {
	var builder strings.Builder
	for _, part := range parts {
		builder.WriteString(strconv.Itoa(len(part)))
		builder.WriteByte(':')
		builder.WriteString(part)
	}
	return builder.String()
}

func makeStatsKey(property *Property, scope string) string {
	id := property.Link
	if id == "" {
		id = property.Protocol + "://" + property.Address
	}
	return composeStatsIdentity(property.SubscriptionTag, id, scope)
}

func (d *Dialer) StatsKey() string { return d.statsKey }

func (d *Dialer) StatsID() string { return d.statsID }

func (d *Dialer) StatsPath(outbound string, networkType *common.NetworkType) stats.Path {
	return stats.Path{
		NodeID:   d.StatsID(),
		Outbound: outbound,
		Subtag:   d.Property.SubscriptionTag,
		Dialer:   d.Name,
		Network:  networkType.Index(),
	}
}

func (d *pathRuntime) ChecksConnectivity() bool {
	return d.checksConnectivity
}

func (d *pathRuntime) sessionSnapshot() netproxy.StateEvent {
	if d.session == nil {
		return netproxy.StateEvent{}
	}
	return d.session.Snapshot()
}

func (d *pathRuntime) healthyLocked(session netproxy.StateEvent) bool {
	return d.ctx.Err() == nil && d.health.usable() && (d.session == nil || session.Accepting && d.healthSeq == session.ReadinessVersion)
}

func (d *Dialer) Usable(networkType *common.NetworkType) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return !d.closed && d.healthyLocked(d.sessionSnapshot()) && d.networks[networkType.Index()] == networkSupported
}

func (d *Dialer) SelectionSnapshot(networkType *common.NetworkType) SelectionSnapshot {
	d.mu.RLock()
	session := d.sessionSnapshot()
	state := d.networks[networkType.Index()]
	snapshot := SelectionSnapshot{
		Usable:  !d.closed && d.healthyLocked(session) && state == networkSupported,
		Support: supportState(state),
	}
	snapshot.Latency, snapshot.HasLatency = d.latencyStatsLocked()
	d.mu.RUnlock()
	return snapshot
}

func (d *Dialer) ConnectivitySnapshot() ConnectivitySnapshot {
	d.mu.RLock()
	session := d.sessionSnapshot()
	healthy := !d.closed && d.healthyLocked(session)
	snapshot := ConnectivitySnapshot{
		InitialCheckDone:  d.initialCheckCompletedLocked(),
		ConfirmingFailure: healthy && d.health == healthConfirming,
	}
	for i, state := range d.networks {
		snapshot.Usable[i] = healthy && state == networkSupported
	}
	d.mu.RUnlock()
	return snapshot
}

func (d *pathRuntime) initialCheckCompleted() bool {
	d.mu.RLock()
	done := d.initialCheckCompletedLocked()
	d.mu.RUnlock()
	return done
}

func (d *pathRuntime) initialCheckCompletedLocked() bool {
	for _, state := range d.networks {
		if state == networkUntested {
			return false
		}
	}
	return true
}

func (d *Dialer) RegisterDialerGroup(group DialerGroup, emaAlpha float64, timeoutPenalty time.Duration) {
	d.mu.Lock()
	d.group = &groupBinding{
		observer:       group,
		emaAlpha:       emaAlpha,
		timeoutPenalty: timeoutPenalty,
	}
	d.mu.Unlock()
}

func (d *Dialer) latencyStats() (lat api.LatencyStats, ok bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.latencyStatsLocked()
}

func (d *Dialer) latencyStatsLocked() (lat api.LatencyStats, ok bool) {
	g := d.group
	if g == nil || g.count == 0 {
		return api.LatencyStats{}, false
	}
	lat.Last = g.latencies[(g.next+len(g.latencies)-1)%len(g.latencies)]
	for i, sample := range g.latencies[:g.count] {
		lat.Avg10 += sample
		lat.Avg10HasFailure = lat.Avg10HasFailure || g.failed[i]
	}
	lat.Avg10 /= time.Duration(g.count)
	lat.MovingAvg = g.movingAverage
	return lat, true
}

func (d *Dialer) RuntimeStatus() RuntimeSnapshot {
	d.mu.RLock()
	snapshot := d.runtimeStatusLocked()
	snapshot.Healthy = snapshot.Healthy && !d.closed
	snapshot.CheckEnabled = d.checkEnabled && !d.closed
	snapshot.Latency, snapshot.HasLatency = d.latencyStatsLocked()
	d.mu.RUnlock()
	snapshot.Availability = stats.DefaultStore.GetNode(d.StatsKey())
	return snapshot
}

func (d *pathRuntime) runtimeStatus() RuntimeSnapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.runtimeStatusLocked()
}

func (d *pathRuntime) runtimeStatusLocked() RuntimeSnapshot {
	session := d.sessionSnapshot()
	healthy := d.healthyLocked(session)
	snapshot := RuntimeSnapshot{
		Revision:           d.statusRevision,
		ObservedSessionSeq: d.observedSessionSeq,
		Recovery:           d.recoverySnapshotLocked(session, healthy),
		Failure:            d.lastFailure,
		Healthy:            healthy,
		InitialCheckDone:   d.initialCheckCompletedLocked(),
		CheckEnabled:       !d.checkPaused,
		Checking:           d.checkRunning || d.pendingCheck != 0 || (!d.checkPaused && d.checkedAt.IsZero()),
		CheckedAt:          d.checkedAt,
		ConfirmingFailure:  healthy && d.health == healthConfirming,
		Session:            session,
		HasSession:         d.session != nil,
	}
	for i, state := range d.networks {
		snapshot.SupportState[i] = supportState(state)
	}
	return snapshot
}

// Retain keeps the shared runtime accepting operations for an existing caller,
// even after its member closes. The final member stops checks; the final retain
// then retires the transport. Closed members reject new retains. Release is
// idempotent.
func (d *Dialer) Retain() (release func(), err error) {
	d.mu.Lock()
	if d.closed || d.ctx.Err() != nil {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	d.retains++
	d.mu.Unlock()
	d.signalConnectivityCheck()
	return sync.OnceFunc(func() {
		d.mu.Lock()
		d.retains--
		retire := d.checksStopped && d.retains == 0
		d.mu.Unlock()
		d.signalConnectivityCheck()
		if retire {
			d.retireRuntime()
		}
	}), nil
}

// Close releases this member. The final member stops health checks; retained
// callers and established connection leases keep the transport alive to drain.
func (d *Dialer) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		delete(d.members, d)
		if len(d.members) != 0 {
			d.updateCheckDemandLocked()
			d.mu.Unlock()
			d.signalConnectivityCheck()
			return
		}
		d.cancel()
		d.recovery.Phase = RecoveryStopped
		d.recovery.RetryAt = time.Time{}
		d.statusRevision++
		d.mu.Unlock()
		d.checkWG.Wait()
		d.mu.Lock()
		d.checksStopped = true
		retire := d.retains == 0
		d.mu.Unlock()
		if retire {
			d.retireRuntime()
		}
	})
	return nil
}

func (d *pathRuntime) retireRuntime() {
	d.retireOnce.Do(func() {
		d.runtime.Retire()
		go func() {
			if err := d.runtime.Wait(context.Background()); err != nil {
				log.WithField("node", d.name).WithError(err).Debug("Outbound cleanup completed with an error")
			}
		}()
	})
}
