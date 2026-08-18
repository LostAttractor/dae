/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

var ErrNoDialer = fmt.Errorf("no dialer")
var ErrNoAliveDialer = fmt.Errorf("no alive dialer")
var ErrFixedDialerNotAlive = fmt.Errorf("fixed dialer is not alive")

// GroupKind describes the availability semantics of a group and how it is
// presented in status output.
type GroupKind int

const (
	// GroupKindNormal is a regular group whose dialers are subject to
	// connectivity checks.
	GroupKindNormal GroupKind = iota
	// GroupKindAlwaysAlive groups dialers that need no connectivity checks
	// (e.g. the built-in direct group); only its connection counts are
	// meaningful.
	GroupKindAlwaysAlive
	// GroupKindInvisible groups dialers that never carry real traffic (e.g.
	// the built-in block group); it is hidden from status output.
	GroupKindInvisible
)

type DialerGroup struct {
	Name            string
	Kind            GroupKind
	Dialers         []*dialer.Dialer
	selectionPolicy *dialer.DialerSelectionPolicy
	selector        Selector

	dialerToAnnotation  map[*dialer.Dialer]*dialer.Annotation
	latencyTableLogging atomic.Bool
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	kind GroupKind,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	selectionPolicy dialer.DialerSelectionPolicy,
	aliveChangeCallback func(alive bool, networkType *common.NetworkType),
) *DialerGroup {
	if len(dialers) != len(dialersAnnotations) {
		panic(fmt.Sprintf("unmatched annotations length: %v dialers and %v annotations", len(dialers), len(dialersAnnotations)))
	}

	g := &DialerGroup{
		Name:               name,
		Kind:               kind,
		Dialers:            dialers,
		selectionPolicy:    &selectionPolicy,
		dialerToAnnotation: make(map[*dialer.Dialer]*dialer.Annotation),
	}

	for i, d := range dialers {
		g.dialerToAnnotation[d] = dialersAnnotations[i]
		if dialersAnnotations[i].CheckAsync {
			d.SetCheckAsync(true)
		}
	}

	switch selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies,
		consts.DialerSelectionPolicy_MinLastLatency:
		g.selector = NewLatencyBasedSelector(g, option.CheckTolerance, aliveChangeCallback)
	case consts.DialerSelectionPolicy_Fixed:
		g.selector = NewFixedSelector(g, aliveChangeCallback)
	case consts.DialerSelectionPolicy_Random:
		g.selector = NewRandomSelector(g, aliveChangeCallback)
	}

	for _, d := range dialers {
		d.RegisterDialerGroup(g)
	}

	return g
}

// Close stops the connectivity checks of all dialers in the group. It is
// called when the owning control plane is retired; the dialers themselves
// must not be reused afterwards.
func (g *DialerGroup) Close() error {
	for _, d := range g.Dialers {
		_ = d.Close()
		d.UnregisterDialerGroup(g)
	}
	return nil
}

func (g *DialerGroup) InitializeConnectivity() {
	g.selector.InitializeConnectivity()
}

// Returns the priority given an observed latency.
// If a "ConditionalPriority" is present, it is applied;
// Otherwise the default fixed Priority is returned.
func (g *DialerGroup) GetPriority(d *dialer.Dialer, latency time.Duration) int {
	for _, p := range g.dialerToAnnotation[d].ConditionalPriority {
		if latency >= p.Low && latency <= p.High {
			return p.Pri
		}
	}
	return g.dialerToAnnotation[d].Priority
}

func (g *DialerGroup) GetSelectionPolicy() (policy consts.DialerSelectionPolicy) {
	return g.selectionPolicy.Policy
}

// SelectedDialer returns the dialer currently selected for the given network
// type. It returns nil for policies without a stable selection (e.g. random)
// or when no dialer is alive.
func (g *DialerGroup) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
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

func (g *DialerGroup) Select(networkType *common.NetworkType) (dialer *dialer.Dialer, err error) {
	if len(g.Dialers) == 0 {
		return nil, ErrNoDialer
	}
select_dialer:
	dialer = g.selector.Select(networkType)
	if err != nil {
		return nil, err
	}

	if dialer == nil {
		// TODO: 这种情况下应该尝试测试网络连接性, 若从无连接变为有连接则重新测速所有节点?
		return nil, ErrNoAliveDialer
	}

	if !isDialerAlive(dialer, networkType) {
		if dialer.Alive() {
			dialer.NotifyStatusChange()
		}
		dialer.ReportUnavailable()
		goto select_dialer
	}

	return dialer, nil
}

func (g *DialerGroup) PrintLatency() {
	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		g.selector.PrintLatencies(networkType, log.Infoln)
	}
	// Initial checks update selectors incrementally. Enable detailed tables
	// only after this complete startup snapshot has been printed.
	g.latencyTableLogging.Store(true)
}

func (g *DialerGroup) NotifyStatusChange(dialer *dialer.Dialer) {
	g.selector.NotifyStatusChange(dialer)
}

func (g *DialerGroup) GetEmaAlpha() float64 {
	return g.selectionPolicy.EmaAlpha
}

func (g *DialerGroup) GetTimeoutPenalty() time.Duration {
	return g.selectionPolicy.TimeoutPenalty
}
