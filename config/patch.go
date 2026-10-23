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
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type patch func(params *Config) error

var patches = []patch{
	validateSoMarkFromDae,
	validateControlModes,
	validateGroupNames,
	validateCheckIntervals,
	validateCheckDNS,
	validateFallbacks,
}

func validateGroupNames(params *Config) error {
	for _, group := range params.Group {
		switch group.Name {
		case consts.OutboundDirect.String(),
			consts.OutboundBlock.String(),
			consts.OutboundControlPlaneRouting.String(),
			consts.OutboundLogicalOr.String(),
			consts.OutboundLogicalAnd.String():
			return fmt.Errorf("group name %q is reserved for an internal outbound", group.Name)
		}
	}
	return nil
}

// dae always marks its own sockets.
func validateSoMarkFromDae(params *Config) error {
	if params.Global.SoMarkFromDae == 0 {
		return fmt.Errorf("so_mark_from_dae must be nonzero")
	}
	return common.ValidateSoMarkFromDae(params.Global.SoMarkFromDae)
}

func validateControlModes(params *Config) error {
	if interval := params.Global.ResourceUpdateInterval; interval < 0 || interval > 0 && interval < time.Second {
		return fmt.Errorf("resource_update_interval must be zero or at least 1s")
	}
	if _, err := netutils.ParseDNSServer(params.Global.DNSResolver); err != nil {
		return err
	}
	if params.Global.DNSRetentionWindow <= 0 {
		return fmt.Errorf("dns_retention_window must be positive")
	}
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

func validateFallbacks(params *Config) error {
	return params.Routing.Validate()
}

func validateRoutingAction(f *config_parser.Function) error {
	if f.Name == consts.OutboundControlPlaneRouting.String() || !f.Quoted && (f.Name == "must" || f.Name == "dnat") {
		return fmt.Errorf("routing target %q is a flow control; flow controls belong in rules {}", f.Name)
	}
	_, err := routing.ParseOutbound(f)
	return err
}
