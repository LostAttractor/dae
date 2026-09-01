/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

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
	DialerChanged(d *Dialer)
}

type groupBinding struct {
	observer       DialerGroup
	latencies      *LatenciesN
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
	g.latencies.AppendSample(sample, !success)
}

// InitialCheckMode controls whether a dialer is checked and whether its group
// may wait for a usable candidate during startup.
type InitialCheckMode uint8

const (
	InitialCheckDisabled InitialCheckMode = iota
	InitialCheckBlocking
	InitialCheckAsync
)

type networkState uint8

const (
	networkUnknown networkState = iota
	networkUsable
	networkUnavailable
	networkUnsupported
)

type Dialer struct {
	*GlobalOption
	netproxy.Dialer
	*Property
	statsKey string
	statsID  string
	runtime  *netproxy.Runtime
	session  netproxy.Session

	initialCheck      InitialCheckMode
	initialCheckDone  bool
	healthy           bool
	healthSeq         uint64
	failureReportedAt time.Time
	networks          [common.NetworkTypeCount]networkState
	group             *groupBinding

	mu sync.RWMutex

	checkCh chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc

	checkActivated bool
	checkRequested bool
	checkWG        sync.WaitGroup
	closeOnce      sync.Once
}

// LatencyStats is a coherent view of the latency samples of a dialer.
type LatencyStats struct {
	Last            time.Duration `json:"last"`
	Avg10           time.Duration `json:"average_10"`
	MovingAvg       time.Duration `json:"moving_average"`
	Avg10HasFailure bool          `json:"average_10_failed"`
}

type SelectionSnapshot struct {
	Usable     bool
	Support    NetworkSupportState
	HasLatency bool
	Latency    LatencyStats
}

// ConnectivitySnapshot is the state needed to aggregate a dialer into its
// group. It deliberately excludes process-lifetime statistics.
type ConnectivitySnapshot struct {
	Usable            [common.NetworkTypeCount]bool
	InitialCheckDone  bool
	ConfirmingFailure bool
}

// NetworkSupportState describes protocol/remote capability, not current
// reachability. Confirmed modes can be either usable or temporarily down.
type NetworkSupportState string

const (
	NetworkSupportUnknown     NetworkSupportState = "unknown"
	NetworkSupportConfirmed   NetworkSupportState = "confirmed"
	NetworkSupportUnsupported NetworkSupportState = "unsupported"
)

func supportState(state networkState) NetworkSupportState {
	switch state {
	case networkUsable, networkUnavailable:
		return NetworkSupportConfirmed
	case networkUnsupported:
		return NetworkSupportUnsupported
	default:
		return NetworkSupportUnknown
	}
}

// RuntimeSnapshot is a coherent view of a dialer's current connectivity state.
// Process-lifetime availability statistics are sampled after releasing its lock.
type RuntimeSnapshot struct {
	Healthy           bool
	ConfirmingFailure bool
	SupportState      [common.NetworkTypeCount]NetworkSupportState
	Session           netproxy.StateEvent
	HasSession        bool
	HasLatency        bool
	Latency           LatencyStats
	Availability      stats.Availability
}

type GlobalOption struct {
	D.ExtraOption
	CheckDnsOptionRaw CheckDnsOptionRaw
	CheckInterval     time.Duration
	CheckIntervalMax  time.Duration
	CheckTolerance    time.Duration
}

type Property struct {
	D.Property
	SubscriptionTag string
	Hops            []Hop
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

func NewDialer(runtime *netproxy.Runtime, option *GlobalOption, property *Property, initialCheck InitialCheckMode, statsScope string) *Dialer {
	if initialCheck > InitialCheckAsync {
		panic(fmt.Sprintf("invalid initial check mode %d", initialCheck))
	}
	ctx, cancel := context.WithCancel(context.Background())
	session, _ := runtime.Session()
	d := &Dialer{
		GlobalOption:     option,
		Dialer:           runtime.Dialer(),
		Property:         property,
		runtime:          runtime,
		session:          session,
		initialCheck:     initialCheck,
		initialCheckDone: initialCheck == InitialCheckDisabled,
		healthy:          initialCheck == InitialCheckDisabled,
		checkCh:          make(chan struct{}, 1),
		ctx:              ctx,
		cancel:           cancel,
	}
	if initialCheck == InitialCheckDisabled {
		for i := range d.networks {
			d.networks[i] = networkUsable
		}
	}
	d.statsKey = makeStatsKey(property, statsScope)
	d.statsID = stats.NodeID(d.statsKey)
	log.WithField("dialer", d.Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
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

func (d *Dialer) ChecksConnectivity() bool {
	return d.initialCheck != InitialCheckDisabled
}

func (d *Dialer) sessionSnapshot() (netproxy.StateEvent, bool) {
	if d.session == nil {
		return netproxy.StateEvent{State: netproxy.SessionConnected}, false
	}
	return d.session.Snapshot(), true
}

func (d *Dialer) healthyLocked(session netproxy.StateEvent, hasSession bool) bool {
	return d.ctx.Err() == nil && d.healthy && (!hasSession || session.State == netproxy.SessionConnected && d.healthSeq == session.Seq)
}

func (d *Dialer) Healthy() bool {
	d.mu.RLock()
	session, hasSession := d.sessionSnapshot()
	healthy := d.healthyLocked(session, hasSession)
	d.mu.RUnlock()
	return healthy
}

func (d *Dialer) Usable(networkType *common.NetworkType) bool {
	return d.SelectionSnapshot(networkType).Usable
}

func (d *Dialer) SelectionSnapshot(networkType *common.NetworkType) SelectionSnapshot {
	d.mu.RLock()
	session, hasSession := d.sessionSnapshot()
	state := d.networks[networkType.Index()]
	snapshot := SelectionSnapshot{
		Usable:  d.healthyLocked(session, hasSession) && state == networkUsable,
		Support: supportState(state),
	}
	snapshot.Latency, snapshot.HasLatency = d.latencyStatsLocked()
	d.mu.RUnlock()
	return snapshot
}

func (d *Dialer) ConnectivitySnapshot() ConnectivitySnapshot {
	d.mu.RLock()
	session, hasSession := d.sessionSnapshot()
	healthy := d.healthyLocked(session, hasSession)
	snapshot := ConnectivitySnapshot{
		InitialCheckDone:  d.initialCheckDone,
		ConfirmingFailure: healthy && !d.failureReportedAt.IsZero(),
	}
	for i, state := range d.networks {
		snapshot.Usable[i] = healthy && state == networkUsable
	}
	d.mu.RUnlock()
	return snapshot
}

func (d *Dialer) initialCheckCompleted() bool {
	d.mu.RLock()
	done := d.initialCheckDone
	d.mu.RUnlock()
	return done
}

func (d *Dialer) notifyGroup(group *groupBinding) {
	if group != nil {
		group.observer.DialerChanged(d)
	}
}

func (d *Dialer) RegisterDialerGroup(group DialerGroup, emaAlpha float64, timeoutPenalty time.Duration) {
	d.mu.Lock()
	d.group = &groupBinding{
		observer:       group,
		latencies:      NewLatenciesN(10),
		emaAlpha:       emaAlpha,
		timeoutPenalty: timeoutPenalty,
	}
	d.mu.Unlock()
}

func (d *Dialer) latencyStats() (lat LatencyStats, ok bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.latencyStatsLocked()
}

func (d *Dialer) latencyStatsLocked() (lat LatencyStats, ok bool) {
	if d.group == nil {
		return LatencyStats{}, false
	}
	lat.Last, ok = d.group.latencies.LastLatency()
	if !ok {
		return LatencyStats{}, false
	}
	lat.Avg10, _ = d.group.latencies.AvgLatency()
	lat.MovingAvg = d.group.movingAverage
	lat.Avg10HasFailure = d.group.latencies.HasFailure()
	return lat, true
}

func (d *Dialer) RuntimeStatus() RuntimeSnapshot {
	d.mu.RLock()
	session, hasSession := d.sessionSnapshot()
	snapshot := RuntimeSnapshot{
		Healthy:           d.healthyLocked(session, hasSession),
		ConfirmingFailure: !d.failureReportedAt.IsZero(),
		Session:           session,
		HasSession:        hasSession,
	}
	for i, state := range d.networks {
		snapshot.SupportState[i] = supportState(state)
	}
	snapshot.Latency, snapshot.HasLatency = d.latencyStatsLocked()
	d.mu.RUnlock()
	snapshot.ConfirmingFailure = snapshot.Healthy && snapshot.ConfirmingFailure
	snapshot.Availability = stats.DefaultStore.GetNode(d.StatsKey())
	return snapshot
}

func (d *Dialer) InitialCheckMode() InitialCheckMode { return d.initialCheck }

// Close stops health checking and retires the owned outbound runtime. Runtime
// leases keep established connections alive until their callers close them.
func (d *Dialer) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.cancel()
		d.mu.Unlock()
		d.checkWG.Wait()
		d.runtime.Retire()
		go func() {
			if err := d.runtime.Wait(context.Background()); err != nil {
				log.Warnf("Failed to release outbound runtime: %v", err)
			}
		}()
	})
	return nil
}
