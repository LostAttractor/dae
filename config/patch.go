/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type patch func(params *Config) error

var patches = []patch{
	// patchTcpCheckHttpMethod,
	validateCheckIntervals,
	patchEmptyDns,
	patchMustOutbound,
}

// func patchTcpCheckHttpMethod(params *Config) error {
// 	if !common.IsValidHttpMethod(params.Global.TcpCheckHttpMethod) {
// 		log.Warnf("Unknown HTTP Method '%v'. Fallback to 'CONNECT'.", params.Global.TcpCheckHttpMethod)
// 		params.Global.TcpCheckHttpMethod = "CONNECT"
// 	}
// 	return nil
// }

func validateCheckIntervals(params *Config) error {
	if params.Global.CheckInterval <= 0 {
		return fmt.Errorf("check_interval must be positive")
	}
	if params.Global.CheckIntervalMax < time.Second {
		return fmt.Errorf("check_interval_max must be at least 1s")
	}
	if params.Global.CheckIntervalMax > time.Duration(math.MaxInt64/2) {
		return fmt.Errorf("check_interval_max is too large")
	}
	for _, group := range params.Group {
		if group.CheckInterval < 0 {
			return fmt.Errorf("group %q: check_interval must be positive", group.Name)
		}
		if group.CheckIntervalMax != 0 && group.CheckIntervalMax < time.Second {
			return fmt.Errorf("group %q: check_interval_max must be at least 1s", group.Name)
		}
		if group.CheckIntervalMax > time.Duration(math.MaxInt64/2) {
			return fmt.Errorf("group %q: check_interval_max is too large", group.Name)
		}
	}
	return nil
}

func patchEmptyDns(params *Config) error {
	if params.Dns.Routing.Request.Fallback == nil {
		params.Dns.Routing.Request.Fallback = consts.DnsRequestOutboundIndex_AsIs.String()
	}
	if params.Dns.Routing.Response.Fallback == nil {
		params.Dns.Routing.Response.Fallback = consts.DnsResponseOutboundIndex_Accept.String()
	}
	return nil
}

func patchMustOutbound(params *Config) error {
	for i := range params.Routing.Rules {
		if strings.HasPrefix(params.Routing.Rules[i].Outbound.Name, "must_") {
			if params.Routing.Rules[i].Outbound.Name == "must_rules" {
				// Reserve must_rules.
				continue
			}
			params.Routing.Rules[i].Outbound.Name = strings.TrimPrefix(params.Routing.Rules[i].Outbound.Name, "must_")
			params.Routing.Rules[i].Outbound.Params = append(params.Routing.Rules[i].Outbound.Params, &config_parser.Param{
				Val: "must",
			})
		}
	}
	if f := FunctionOrStringToFunction(params.Routing.Fallback); strings.HasPrefix(f.Name, "must_") {
		f.Name = strings.TrimPrefix(f.Name, "must_")
		f.Params = append(f.Params, &config_parser.Param{
			Val: "must",
		})
		params.Routing.Fallback = f
	}
	return nil
}
