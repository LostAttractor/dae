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

	needAliveState bool
	alive          bool
	supported      [4]bool
	Latencies10    map[DialerGroup]*LatenciesN
	MovingAverage  map[DialerGroup]time.Duration

	mu                     sync.Mutex
	registeredDialerGroups map[DialerGroup]int

	checkCh chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc

	checkActivated bool
	checkAsync     bool
}
type GlobalOption struct {
	D.ExtraOption
	// TcpCheckOptionRaw TcpCheckOptionRaw // Lazy parse
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckTolerance    time.Duration
	CheckDnsTcp       bool
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
		// TcpCheckOptionRaw: TcpCheckOptionRaw{Raw: global.TcpCheckUrl, Method: global.TcpCheckHttpMethod},
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: global.UdpCheckDns},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
	}
}

// NewDialer is for register in general.
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, property *Property, needAliveState bool) *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:           option,
		Dialer:                 dialer,
		Property:               property,
		needAliveState:         needAliveState,
		alive:                  !needAliveState,
		Latencies10:            make(map[DialerGroup]*LatenciesN),
		MovingAverage:          make(map[DialerGroup]time.Duration),
		registeredDialerGroups: make(map[DialerGroup]int),
		checkCh:                make(chan struct{}, 1),
		ctx:                    ctx,
		cancel:                 cancel,
	}
	log.WithField("dialer", d.Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	if !needAliveState {
		stats.RecordNode(d.StatsKey(), d.Property.SubscriptionTag, d.Name, true, false)
	}
	return d
}

// StatsKey returns the process-lifetime identity of the node backing this
// dialer. It is stable across control-plane reloads.
func (d *Dialer) StatsKey() string {
	id := d.Property.Link
	if id == "" {
		id = d.Property.Protocol + "://" + d.Property.Address
	}
	return d.Property.SubscriptionTag + "\x1f" + id
}

func (d *Dialer) NeedAliveState() bool {
	return d.needAliveState
}

// LatencySnapshot returns the last, avg10 and moving-average latencies of
// this dialer in the given group. hasLatency is false if no check sample has
// been recorded yet.
func (d *Dialer) LatencySnapshot(g DialerGroup) (last, avg10, movingAvg time.Duration, hasLatency bool) {
	d.mu.Lock()
	latencies, ok := d.Latencies10[g]
	movingAvg = d.MovingAverage[g]
	d.mu.Unlock()
	if !ok {
		return 0, 0, 0, false
	}
	last, ok = latencies.LastLatency()
	if !ok {
		return 0, 0, 0, false
	}
	avg10, _ = latencies.AvgLatency()
	return last, avg10, movingAvg, true
}

// SetCheckAsync marks the dialer's initial connectivity check to run in
// background without blocking startup. The dialer stays unavailable until
// the first successful check.
func (d *Dialer) SetCheckAsync(checkAsync bool) {
	d.checkAsync = checkAsync
}

// CheckAsync reports whether the dialer's connectivity check was marked to
// run asynchronously (via the "check_async" filter annotation).
func (d *Dialer) CheckAsync() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.checkAsync
}

func (d *Dialer) Clone() *Dialer {
	return NewDialer(d.Dialer, d.GlobalOption, d.Property, d.needAliveState)
}

func (d *Dialer) Close() error {
	d.cancel()
	return nil
}
