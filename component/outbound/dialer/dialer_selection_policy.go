/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
)

type DialerSelectionPolicy struct {
	Policy             consts.DialerSelectionPolicy
	FixedIndex         int
	FixedIndexSet      bool
	TrackAll           bool
	EmaAlpha           float64
	FailureRecovery    time.Duration
	ProbeTimeout       time.Duration
	SelectionTimeout   time.Duration
	UpgradeInterval    time.Duration
	UpgradeIntervalMax time.Duration
}

const (
	DefaultEmaAlpha           = 0.18
	DefaultFailureRecovery    = 30 * time.Second
	DefaultProbeTimeout       = 3 * time.Second
	DefaultSelectionTimeout   = 15 * time.Second
	DefaultUpgradeInterval    = 3 * time.Minute
	DefaultUpgradeIntervalMax = time.Hour
)

func (p DialerSelectionPolicy) Automatic() bool {
	switch p.Policy {
	case consts.DialerSelectionPolicy_Random, consts.DialerSelectionPolicy_Failover,
		consts.DialerSelectionPolicy_MinLastLatency, consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return true
	}
	return false
}

func (p DialerSelectionPolicy) WithDefaults() DialerSelectionPolicy {
	if p.EmaAlpha == 0 {
		p.EmaAlpha = DefaultEmaAlpha
	}
	if p.FailureRecovery == 0 {
		p.FailureRecovery = DefaultFailureRecovery
	}
	if p.ProbeTimeout == 0 {
		p.ProbeTimeout = DefaultProbeTimeout
	}
	if p.SelectionTimeout == 0 {
		p.SelectionTimeout = DefaultSelectionTimeout
	}
	if p.UpgradeInterval == 0 {
		p.UpgradeInterval = DefaultUpgradeInterval
	}
	if p.UpgradeIntervalMax == 0 {
		p.UpgradeIntervalMax = DefaultUpgradeIntervalMax
	}
	return p
}

func NewDialerSelectionPolicyFromGroupParam(param *config.Group) (policy *DialerSelectionPolicy, err error) {
	fs, err := config.ParseFunctionListOrString(param.Policy)
	if err != nil {
		return nil, fmt.Errorf("invalid group policy: %w", err)
	}
	if len(fs) != 1 {
		return nil, fmt.Errorf("policy should be exact 1 function: got %v", len(fs))
	}
	f := fs[0]
	if (param.TrackAll || param.Present["track_all"]) && f.Name != string(consts.DialerSelectionPolicy_Selector) {
		return nil, fmt.Errorf("track_all requires selector policy")
	}
	if f.Not {
		return nil, fmt.Errorf("policy param does not support not operator: !%v()", f.Name)
	}
	policy = &DialerSelectionPolicy{
		Policy:          consts.DialerSelectionPolicy(f.Name),
		TrackAll:        param.TrackAll,
		FailureRecovery: param.FailureRecovery,
		ProbeTimeout:    param.ProbeTimeout, SelectionTimeout: param.SelectionTimeout,
		UpgradeInterval: param.UpgradeInterval, UpgradeIntervalMax: param.UpgradeIntervalMax,
	}
	for name, value := range map[string]int64{
		"failure_recovery": int64(param.FailureRecovery),
		"probe_timeout":    int64(param.ProbeTimeout), "selection_timeout": int64(param.SelectionTimeout),
		"upgrade_interval": int64(param.UpgradeInterval), "upgrade_interval_max": int64(param.UpgradeIntervalMax),
	} {
		if value < 0 || param.Present[name] && value == 0 {
			return nil, fmt.Errorf("%s must be positive", name)
		}
		if (value != 0 || param.Present[name]) && !policy.Automatic() {
			return nil, fmt.Errorf("%s requires an automatic selection policy", name)
		}
	}
	*policy = policy.WithDefaults()
	if policy.UpgradeIntervalMax < policy.UpgradeInterval {
		return nil, fmt.Errorf("upgrade_interval_max must not be less than upgrade_interval")
	}
	switch fName := consts.DialerSelectionPolicy(f.Name); fName {
	case consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_Failover,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinLastLatency:
		if len(f.Params) != 0 {
			return nil, fmt.Errorf("%s does not accept parameters", fName)
		}
		return policy, nil
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		if len(f.Params) > 1 || len(f.Params) == 1 && f.Params[0].Key != "alpha" {
			return nil, fmt.Errorf("min_moving_avg accepts only alpha: value")
		}
		if len(f.Params) == 1 {
			alpha, err := strconv.ParseFloat(f.Params[0].Val, 64)
			if err != nil {
				return nil, fmt.Errorf(`invalid "%v" param format: %w`, fName, err)
			}
			if math.IsNaN(alpha) || alpha <= 0 || alpha >= 1 {
				return nil, fmt.Errorf(`invalid "%v" param format: alpha should be between 0 and 1`, fName)
			}
			policy.EmaAlpha = alpha
		}
		return policy, nil
	case consts.DialerSelectionPolicy_Fixed, consts.DialerSelectionPolicy_Selector:
		if fName == consts.DialerSelectionPolicy_Selector && len(f.Params) == 0 {
			return policy, nil
		}
		if len(f.Params) != 1 || f.Params[0].Key != "" {
			return nil, fmt.Errorf(`invalid "%v" param format`, fName)
		}
		strIndex := f.Params[0].Val
		index, err := strconv.Atoi(strIndex)
		if err != nil {
			return nil, fmt.Errorf(`invalid "%v" param format: %w`, fName, err)
		}
		if index < 0 {
			return nil, fmt.Errorf(`invalid "%v" param format: index must not be negative`, fName)
		}
		policy.FixedIndex, policy.FixedIndexSet = index, true
		return policy, nil

	default:
		return nil, fmt.Errorf("unexpected policy: %v", fName)
	}
}
