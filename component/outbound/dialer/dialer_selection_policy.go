/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
)

type DialerSelectionPolicy struct {
	Policy     consts.DialerSelectionPolicy
	FixedIndex int
	// For moving average
	EmaAlpha       float64
	TimeoutPenalty time.Duration
}

const (
	DefaultTimeoutPenalty = 10 * time.Minute
	DefaultEmaAlpha       = 0.18
)

func NewDialerSelectionPolicyFromGroupParam(param *config.Group) (policy *DialerSelectionPolicy, err error) {
	fs := config.FunctionListOrStringToFunctionList(param.Policy)
	if len(fs) != 1 {
		return nil, fmt.Errorf("policy should be exact 1 function: got %v", len(fs))
	}
	f := fs[0]
	if f.Not {
		return nil, fmt.Errorf("policy param does not support not operator: !%v()", f.Name)
	}
	switch fName := consts.DialerSelectionPolicy(f.Name); fName {
	case consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinLastLatency:
		penalty := DefaultTimeoutPenalty
		if len(f.Params) == 1 {
			penalty, err = time.ParseDuration(f.Params[0].Val)
			if err != nil {
				return nil, fmt.Errorf(`invalid "%v" param format: %w`, fName, err)
			}
			if penalty <= 0 {
				return nil, fmt.Errorf(`invalid "%v" param format: penalty should be positive`, fName)
			}
		}
		return &DialerSelectionPolicy{
			Policy:         fName,
			TimeoutPenalty: penalty,
		}, nil
	case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		alpha := DefaultEmaAlpha
		penalty := DefaultTimeoutPenalty
		if len(f.Params) == 2 {
			penalty, err = time.ParseDuration(f.Params[0].Val)
			if err != nil {
				return nil, fmt.Errorf(`invalid "%v" param format: %w`, fName, err)
			}
			if penalty <= 0 {
				return nil, fmt.Errorf(`invalid "%v" param format: penalty should be positive`, fName)
			}
			alpha, err = strconv.ParseFloat(f.Params[1].Val, 64)
			if err != nil {
				return nil, fmt.Errorf(`invalid "%v" param format: %w`, fName, err)
			}
			if alpha <= 0 || alpha >= 1 {
				return nil, fmt.Errorf(`invalid "%v" param format: alpha should be between 0 and 1`, fName)
			}
		}
		return &DialerSelectionPolicy{
			Policy:         fName,
			TimeoutPenalty: penalty,
			EmaAlpha:       alpha,
		}, nil
	case consts.DialerSelectionPolicy_Fixed:
		if len(f.Params) != 1 || f.Params[0].Key != "" {
			return nil, fmt.Errorf(`invalid "%v" param format`, fName)
		}
		strIndex := f.Params[0].Val
		index, err := strconv.Atoi(strIndex)
		if err != nil {
			return nil, fmt.Errorf(`invalid "%v" param format: %w`, fName, err)
		}
		return &DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy(fName),
			FixedIndex: index,
		}, nil

	default:
		return nil, fmt.Errorf("unexpected policy: %v", fName)
	}
}
