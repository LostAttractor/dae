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

	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type DialerGroup interface {
	NotifyStatusChange(*Dialer)
}

type Dialer struct {
	*GlobalOption
	InstanceOption
	netproxy.Dialer
	*Property

	alive         bool
	supported     [4]bool
	Latencies10   *LatenciesN
	MovingAverage time.Duration

	mu                     sync.Mutex
	registeredDialerGroups map[DialerGroup]int

	tickerMu sync.Mutex
	ticker   *time.Ticker
	checkCh  chan time.Time
	ctx      context.Context
	cancel   context.CancelFunc

	checkActivated bool

	DialerPrometheus
}

type DialerPrometheus struct {
	registry                                                      prometheus.Registerer
	TotalConnections                                              prometheus.Counter
	ActiveConnections, ActiveConnectionsTCP, ActiveConnectionsUDP prometheus.Gauge
	DialLatency                                                   prometheus.Histogram
}

func (d *DialerPrometheus) InitPrometheus(name string) {
	d.ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("dae_active_connections_%s", name),
			Help: fmt.Sprintf("Number of active connections in %s", name),
		},
	)
	d.ActiveConnectionsTCP = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("dae_active_connections_%s_tcp", name),
			Help: fmt.Sprintf("Number of active TCP connections in %s", name),
		},
	)
	d.ActiveConnectionsUDP = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("dae_active_connections_%s_udp", name),
			Help: fmt.Sprintf("Number of active UDP connections in %s", name),
		},
	)
	d.TotalConnections = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("dae_total_connections_%s", name),
			Help: fmt.Sprintf("Total number of connections handled in %s", name),
		},
	)
	d.DialLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("dae_dial_latency_seconds_%s", name),
			Help:    fmt.Sprintf("Dial latency in seconds in %s", name),
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms ~ ~16s
		},
	)
	d.registry.MustRegister(d.TotalConnections)
	d.registry.MustRegister(d.ActiveConnections)
	d.registry.MustRegister(d.ActiveConnectionsTCP)
	d.registry.MustRegister(d.ActiveConnectionsUDP)
	d.registry.MustRegister(d.DialLatency)
}

type GlobalOption struct {
	D.ExtraOption
	// TcpCheckOptionRaw TcpCheckOptionRaw // Lazy parse
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckTolerance    time.Duration
	CheckDnsTcp       bool
}

type InstanceOption struct {
	DisableCheck bool
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
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, iOption InstanceOption, property *Property, registry prometheus.Registerer) *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:           option,
		InstanceOption:         iOption,
		Dialer:                 dialer,
		Property:               property,
		Latencies10:            NewLatenciesN(10),
		registeredDialerGroups: make(map[DialerGroup]int),
		tickerMu:               sync.Mutex{},
		ticker:                 nil,
		checkCh:                make(chan time.Time, 1),
		ctx:                    ctx,
		cancel:                 cancel,
		DialerPrometheus:       DialerPrometheus{registry: registry},
	}
	log.WithField("dialer", d.Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	return d
}

func (d *Dialer) Clone() *Dialer {
	return NewDialer(d.Dialer, d.GlobalOption, d.InstanceOption, d.Property, d.registry)
}

func (d *Dialer) Close() error {
	d.cancel()
	d.tickerMu.Lock()
	if d.ticker != nil {
		d.ticker.Stop()
	}
	d.tickerMu.Unlock()
	return nil
}
