/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type patch func(params *Config) error

var patches = []patch{
	validateSoMarkFromDae,
	validateControlModes,
	validateCheckIntervals,
	validateCheckDNS,
	patchEmptyDns,
	validateFallbacks,
	validateRoutingActions,
}

func validateSoMarkFromDae(params *Config) error {
	return common.ValidateSoMarkFromDae(params.Global.SoMarkFromDae)
}

func validateControlModes(params *Config) error {
	if err := consts.VerifyRerouteMode(string(params.Global.RerouteMode)); err != nil {
		return err
	}
	return consts.VerifySniffVerifyMode(string(params.Global.SniffVerifyMode))
}

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
		if group.CheckInterval < 0 || group.Present["check_interval"] && group.CheckInterval == 0 {
			return fmt.Errorf("group %q: check_interval must be positive", group.Name)
		}
		if (group.Present["check_interval_max"] || group.CheckIntervalMax != 0) && group.CheckIntervalMax < time.Second {
			return fmt.Errorf("group %q: check_interval_max must be at least 1s", group.Name)
		}
		if group.CheckIntervalMax > time.Duration(math.MaxInt64/2) {
			return fmt.Errorf("group %q: check_interval_max is too large", group.Name)
		}
	}
	return nil
}

func validateCheckDNS(params *Config) error {
	if err := validateCheckDNSEndpoint(params.Global.UdpCheckDns); err != nil {
		return fmt.Errorf("udp_check_dns: %w", err)
	}
	for _, group := range params.Group {
		if group.UdpCheckDns == nil {
			continue
		}
		if err := validateCheckDNSEndpoint(group.UdpCheckDns); err != nil {
			return fmt.Errorf("group %q: udp_check_dns: %w", group.Name, err)
		}
	}
	return nil
}

func validateCheckDNSEndpoint(raw []string) error {
	if len(raw) == 0 {
		return fmt.Errorf("must not be empty")
	}
	host, port, err := net.SplitHostPort(raw[0])
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", raw[0], err)
	}
	if host == "" {
		return fmt.Errorf("host must not be empty")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return fmt.Errorf("invalid port %q", port)
	}
	for _, value := range raw[1:] {
		if _, err := netip.ParseAddr(value); err != nil {
			return fmt.Errorf("invalid IP address %q", value)
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

func validateFallbacks(params *Config) error {
	fallbacks := []struct {
		name  string
		value FunctionOrString
	}{
		{name: "routing.fallback", value: params.Routing.Fallback},
		{name: "dns.routing.request.fallback", value: params.Dns.Routing.Request.Fallback},
		{name: "dns.routing.response.fallback", value: params.Dns.Routing.Response.Fallback},
	}
	for _, fallback := range fallbacks {
		if _, err := ParseFunctionOrString(fallback.value); err != nil {
			return fmt.Errorf("invalid %s: %w", fallback.name, err)
		}
	}
	return nil
}

func validateRoutingActions(params *Config) error {
	for i, rule := range params.Routing.Rules {
		if err := validateRoutingAction(&rule.Outbound); err != nil {
			return fmt.Errorf("routing rule %d: %w", i+1, err)
		}
	}
	f, err := ParseFunctionOrString(params.Routing.Fallback)
	if err != nil {
		return fmt.Errorf("invalid routing fallback: %w", err)
	}
	if err := validateRoutingAction(f); err != nil {
		return fmt.Errorf("routing fallback: %w", err)
	}
	return nil
}

func validateRoutingAction(f *config_parser.Function) error {
	if !f.Quoted && (f.Name == "must" || strings.HasPrefix(f.Name, "must_")) {
		return fmt.Errorf("must control moved to rules { <filter> -> must }; select the outbound separately in routing")
	}
	if f.Name == consts.OutboundControlPlaneRouting.String() {
		return fmt.Errorf("control-plane routing moved to rules { <filter> -> bump }; select the outbound separately in routing")
	}
	for _, p := range f.Params {
		if p != nil && p.Key == "" && p.Val == "must" {
			return fmt.Errorf("the must outbound parameter moved to rules { <filter> -> must }; remove must from the routing outbound")
		}
	}
	return nil
}
