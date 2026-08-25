/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common/consts"
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
	NotifyStatusChange(*Dialer)
	GetEmaAlpha() float64
	GetTimeoutPenalty() time.Duration
}

type Dialer struct {
	*GlobalOption
	netproxy.Dialer
	*Property
	statsKey string
	statsID  string

	needAliveState bool
	alive          bool
	lastLatency    time.Duration
	// support is monotonic protocol capability. modeAlive records the latest
	// health verdict for each confirmed mode independently of aggregate health.
	support       [4]NetworkSupportState
	modeAlive     [4]bool
	Latencies10   map[DialerGroup]*LatenciesN
	MovingAverage map[DialerGroup]time.Duration

	mu                     sync.RWMutex
	registeredDialerGroups map[DialerGroup]struct{}
	connectMu              *sync.Mutex

	checkCh chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc

	checkActivated bool
	checkAsync     bool
	checkWG        sync.WaitGroup
}

// LatencyStats is a coherent view of the latency samples of a dialer in one
// dialer group.
type LatencyStats struct {
	Last            time.Duration
	Avg10           time.Duration
	MovingAvg       time.Duration
	Avg10HasFailure bool
}

// NetworkSupportState describes protocol/remote capability, not node health.
// Unknown becomes Confirmed only after a successful mode probe, or Unsupported
// only after an explicit UnsupportedTunnelTypeError. Timeouts, local network
// failures, and ordinary remote failures never imply Unsupported. Confirmed
// and Unsupported are terminal; runtime health is tracked separately.
type NetworkSupportState uint8

const (
	NetworkSupportUnknown     NetworkSupportState = iota
	NetworkSupportConfirmed                       // The mode has completed a successful probe.
	NetworkSupportUnsupported                     // The protocol or remote explicitly rejected this mode.
)

func (s NetworkSupportState) String() string {
	switch s {
	case NetworkSupportUnknown:
		return "unknown"
	case NetworkSupportConfirmed:
		return "confirmed"
	case NetworkSupportUnsupported:
		return "unsupported"
	default:
		return "invalid"
	}
}

// RuntimeSnapshot is a coherent view of the mutable status fields of a
// dialer. Callers should prefer this over reading the fields one by one.
// Availability is sampled from the stats registry outside the dialer lock and
// is not coherent with the other fields.
type RuntimeSnapshot struct {
	Alive        bool
	SupportState [4]NetworkSupportState
	HasLatency   bool
	Latency      LatencyStats
	Availability stats.Availability
}
type GlobalOption struct {
	D.ExtraOption
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckIntervalMax  time.Duration
	CheckTolerance    time.Duration
}

type Property struct {
	D.Property
	SubscriptionTag string
}

func NewGlobalOption(global *config.Global) *GlobalOption {
	return &GlobalOption{
		ExtraOption: D.ExtraOption{
			AllowInsecure:       global.AllowInsecure,
			TlsImplementation:   global.TlsImplementation,
			UtlsImitate:         global.UtlsImitate,
			BandwidthMaxTx:      global.BandwidthMaxTx,
			BandwidthMaxRx:      global.BandwidthMaxRx,
			TlsFragment:         global.TlsFragment,
			TlsFragmentLength:   global.TlsFragmentLength,
			TlsFragmentInterval: global.TlsFragmentInterval,
			UDPHopInterval:      global.UDPHopInterval,
		},
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: global.UdpCheckDns},
		CheckInterval:     global.CheckInterval,
		CheckIntervalMax:  global.CheckIntervalMax,
		CheckTolerance:    global.CheckTolerance,
	}
}

// NewDialer is for register in general.
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, property *Property, needAliveState bool) *Dialer {
	return newDialer(dialer, option, property, needAliveState, "")
}

func newDialer(dialer netproxy.Dialer, option *GlobalOption, property *Property, needAliveState bool, statsScope string) *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:           option,
		Dialer:                 dialer,
		Property:               property,
		needAliveState:         needAliveState,
		alive:                  !needAliveState,
		Latencies10:            make(map[DialerGroup]*LatenciesN),
		MovingAverage:          make(map[DialerGroup]time.Duration),
		registeredDialerGroups: make(map[DialerGroup]struct{}),
		connectMu:              new(sync.Mutex),
		checkCh:                make(chan struct{}, 1),
		ctx:                    ctx,
		cancel:                 cancel,
	}
	if !needAliveState {
		for i := range d.support {
			d.support[i] = NetworkSupportConfirmed
			d.modeAlive[i] = true
		}
	}
	d.setStatsScope(statsScope)
	log.WithField("dialer", d.Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	if !needAliveState {
		stats.RecordNode(d.StatsKey(), d.Property.SubscriptionTag, d.Name, true, false)
	}
	return d
}

func makeStatsKey(property *Property, scope string) string {
	id := property.Link
	if id == "" {
		id = property.Protocol + "://" + property.Address
	}
	key := property.SubscriptionTag + "\x1f" + id
	if scope != "" {
		key += "\x1f" + scope
	}
	return key
}

func (d *Dialer) setStatsScope(scope string) {
	d.statsKey = makeStatsKey(d.Property, scope)
	d.statsID = stats.NodeID(d.statsKey)
}

// StatsKey returns the process-lifetime identity of the node backing this
// dialer. It is stable across control-plane reloads.
func (d *Dialer) StatsKey() string { return d.statsKey }

func (d *Dialer) StatsID() string { return d.statsID }

func (d *Dialer) NeedAliveState() bool {
	return d.needAliveState
}

// LatencyStats returns the latency samples of this dialer in the given
// group. ok is false if no check sample has been recorded yet.
func (d *Dialer) LatencyStats(g DialerGroup) (lat LatencyStats, ok bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.latencyStatsLocked(g)
}

func (d *Dialer) latencyStatsLocked(g DialerGroup) (lat LatencyStats, ok bool) {
	latencies, ok := d.Latencies10[g]
	if !ok {
		return LatencyStats{}, false
	}
	lat.Last, ok = latencies.LastLatency()
	if !ok {
		return LatencyStats{}, false
	}
	lat.Avg10, _ = latencies.AvgLatency()
	lat.MovingAvg = d.MovingAverage[g]
	lat.Avg10HasFailure = latencies.HasFailure()
	return lat, true
}

// SelectionLatency returns the latency of this dialer in the group according
// to the given selection policy. ok is false when no sample qualifies.
func (d *Dialer) SelectionLatency(g DialerGroup, policy consts.DialerSelectionPolicy) (time.Duration, bool) {
	lat, ok := d.LatencyStats(g)
	if !ok {
		return 0, false
	}
	switch policy {
	case consts.DialerSelectionPolicy_MinLastLatency:
		return lat.Last, true
	case consts.DialerSelectionPolicy_MinAverage10Latencies:
		return lat.Avg10, true
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return lat.MovingAvg, lat.MovingAvg > 0
	}
	return 0, false
}

// RuntimeStatus returns a snapshot whose state and latency-map selection
// cannot be interleaved with a connectivity update.
func (d *Dialer) RuntimeStatus(g DialerGroup) RuntimeSnapshot {
	d.mu.RLock()
	snapshot := RuntimeSnapshot{
		Alive:        d.Dialer.Alive() && d.alive,
		SupportState: d.support,
	}
	snapshot.Latency, snapshot.HasLatency = d.latencyStatsLocked(g)
	d.mu.RUnlock()
	snapshot.Availability = stats.GetNode(d.StatsKey())
	return snapshot
}

// SetCheckAsync marks the dialer's initial connectivity check to run in
// background without blocking startup. The dialer stays unavailable until
// the first successful check.
func (d *Dialer) SetCheckAsync(checkAsync bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.checkAsync = checkAsync
}

// CheckAsync reports whether the dialer's connectivity check was marked to
// run asynchronously (via the "check_async" filter annotation).
func (d *Dialer) CheckAsync() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.checkAsync
}

func (d *Dialer) Clone() *Dialer {
	clone := NewDialer(d.Dialer, d.GlobalOption, d.Property, d.needAliveState)
	clone.connectMu = d.connectMu
	return clone
}

// CloneForStatsScope gives group-specific health state a distinct identity
// while sharing both the data-plane transport and its connection lock.
func (d *Dialer) CloneForStatsScope(scope string) *Dialer {
	clone := newDialer(d.Dialer, d.GlobalOption, d.Property, d.needAliveState, scope)
	clone.connectMu = d.connectMu
	return clone
}

// Close cancels the connectivity check and waits for its goroutine to exit.
// The dialer must not be reused afterwards.
func (d *Dialer) Close() error {
	d.cancel()
	d.checkWG.Wait()
	return nil
}
