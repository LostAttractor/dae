/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"errors"
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

var ErrNoDialer = fmt.Errorf("no dialer")
var ErrNoAliveDialer = fmt.Errorf("no alive dialer")
var ErrFixedDialerNotAlive = fmt.Errorf("fixed dialer is not alive")

type DialerGroup struct {
	netproxy.Dialer

	Name string

	Dialers         []*dialer.Dialer
	aliveDialerSet  *dialer.AliveDialerSet
	selectionPolicy *dialer.DialerSelectionPolicy
}

func NewDialerGroup(
	option *dialer.GlobalOption,
	name string,
	dialers []*dialer.Dialer,
	dialersAnnotations []*dialer.Annotation,
	selectionPolicy dialer.DialerSelectionPolicy,
	needAliveState bool,
	aliveChangeCallback func(alive bool, networkType *dialer.NetworkType),
) *DialerGroup {
	var aliveDialerSet *dialer.AliveDialerSet

	if needAliveState {
		aliveDialerSet = dialer.NewAliveDialerSet(name, option.CheckTolerance, selectionPolicy, dialers, dialersAnnotations, aliveChangeCallback)

		for _, d := range dialers {
			d.RegisterAliveDialerSet(aliveDialerSet)
		}
	}

	return &DialerGroup{
		Name:            name,
		Dialers:         dialers,
		aliveDialerSet:  aliveDialerSet,
		selectionPolicy: &selectionPolicy,
	}
}

func (g *DialerGroup) NeedAliveState() bool {
	return g.aliveDialerSet != nil
}

func (g *DialerGroup) Close() error {
	for _, d := range g.Dialers {
		d.UnregisterAliveDialerSet(g.aliveDialerSet)
	}
	return nil
}

func (g *DialerGroup) SetSelectionPolicy(policy dialer.DialerSelectionPolicy) {
	// TODO:
	g.selectionPolicy = &policy
}

func (g *DialerGroup) GetSelectionPolicy() (policy consts.DialerSelectionPolicy) {
	return g.selectionPolicy.Policy
}

// SelectFallbackIpVersion selects a dialer from group according to selectionPolicy. If 'strictIpVersion' is false and no alive dialer, it will fallback to another ipversion.
func (g *DialerGroup) SelectFallbackIpVersion(networkType *dialer.NetworkType, strictIpVersion bool) (dialer *dialer.Dialer, fallback bool, err error) {
	dialer, err = g.Select(networkType)
	if !strictIpVersion && errors.Is(err, ErrNoAliveDialer) {
		networkType.IpVersion = (consts.IpVersion_X - networkType.IpVersion.ToIpVersionType()).ToIpVersionStr()
		dialer, err = g.Select(networkType)
		fallback = true
	}
	return
}

func (g *DialerGroup) Select(networkType *dialer.NetworkType) (dialer *dialer.Dialer, err error) {
	if len(g.Dialers) == 0 {
		// panic(fmt.Sprintf("no dialer in this group: %s", g.Name))
		return nil, ErrNoDialer
	}
	switch g.selectionPolicy.Policy {
	case consts.DialerSelectionPolicy_Fixed:
		dialer = g.Dialers[g.selectionPolicy.FixedIndex]
	// case consts.DialerSelectionPolicy_Random:
	// 	dialer = aliveDialerSet.GetRand()
	// 	latency = 0
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		dialer = g.aliveDialerSet.GetDialer(networkType)
	default:
		panic(fmt.Sprintf("unsupported DialerSelectionPolicy: %v", g.selectionPolicy))
	}

	if dialer == nil {
		// No alive dialer.
		return nil, ErrNoAliveDialer
	}
	if g.NeedAliveState() && !dialer.GetAlive() {
		return nil, ErrFixedDialerNotAlive
	}

	return dialer, nil
}

func (g *DialerGroup) PrintLatency() {
	if g.aliveDialerSet == nil {
		return
	}
	for i := 0; i < 4; i++ {
		networkType := dialer.IndexToNetworkType(i)
		g.aliveDialerSet.PrintLatencies(networkType, log.InfoLevel)
	}
}
