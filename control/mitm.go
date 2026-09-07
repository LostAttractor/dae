// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"slices"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	log "github.com/sirupsen/logrus"
)

func (c *ControlPlane) MITMStatus() []plugin.InstanceStatus {
	if c.mitmHost == nil {
		return nil
	}
	return c.mitmHost.Status()
}

// Pure inspection can use an existing route. Request transformations are
// admitted separately, before any terminal route for the old target.
func (c *ControlPlane) mitmMode(domain string, src, dst netip.AddrPort, result *bpfRoutingResult) mitm.HTTPMode {
	if c.mitmHost == nil {
		return mitm.HTTPBypass
	}
	mode := c.mitmHost.Match(domain, dst.Port())
	if mode == mitm.HTTPBypass {
		return mode
	}
	src = common.ConvergeAddrPort(src)
	enabled, _ := c.mitmSelection(src.Addr(), result.Mac)
	if !enabled && log.IsLevelEnabled(log.InfoLevel) {
		mac := "unknown"
		if result.Mac != [6]byte{} {
			mac = net.HardwareAddr(result.Mac[:]).String()
		}
		log.WithFields(log.Fields{
			"event": "mitm_bypass", "host": domain, "port": dst.Port(),
			"source": src.String(), "mac": mac, "reason": "client_not_allowed",
		}).Info("mitm")
	}
	if !enabled {
		return mitm.HTTPBypass
	}
	return mode
}

func (c *ControlPlane) mitmAuthority() *mitmca.Authority {
	if c.mitmHost != nil {
		return c.mitmHost.Authority()
	}
	return nil
}

func (p *preparedRules) enableMITMPlan(plan plugin.Plan) {
	p.routing = slices.Concat(plan.EarlyRoutes, p.routing, plan.Routes)
	if len(plan.Scopes) != 0 {
		if p.capture == nil {
			p.capture = &routingCapture{}
		}
		for _, scope := range plan.Scopes {
			if scope.PreserveRoute {
				p.capture.http = append(p.capture.http, scope.Scope)
			} else {
				p.capture.requestRouting = append(p.capture.requestRouting, scope.Scope)
			}
		}
	}
}

// mitmSelection is shared by the traffic gate and the device API. An explicit
// device setting takes precedence over the configured IP/MAC allowlist.
func (c *ControlPlane) mitmSelection(ip netip.Addr, mac [6]byte) (enabled bool, override *bool) {
	if enabled, exists := c.settings.MITM(mac); exists {
		return enabled, &enabled
	}
	return c.mitmClients.Match(ip, mac), nil
}

// Request-transforming scopes are admitted before choosing any upstream route
// or dialer. A candidate miss/client exclusion follows ordinary connection
// routing, including destination rules; pure inspection retains its route.
func (c *ControlPlane) prepareHTTPRoute(ctx context.Context, p *RouteParam) (*DialOption, mitm.UpstreamPlanner, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	mode := c.mitmMode(p.Domain, p.Src, p.Dest, p.routingResult)
	if mode == mitm.HTTPRequest {
		return nil, c.mitmUpstreamPlanner(string(p.networkType.L4Proto), p.Domain, p.Src, p.Dest, *p.routingResult, nil), nil, nil
	}
	option, err := c.RouteDialOption(ctx, p)
	if err != nil {
		return nil, nil, nil, err
	}
	if mode != mitm.HTTPInspect || option.Outbound.Name == consts.OutboundBlock.String() {
		return option, nil, nil, nil
	}
	release, err := option.Dialer.Retain()
	if err != nil {
		return nil, nil, nil, err
	}
	c.logDial(p.Src, p.Dest, p.Domain, option, option.NetworkType.String(), p.routingResult)
	return option, c.mitmUpstreamPlanner(string(p.networkType.L4Proto), p.Domain, p.Src, p.Dest, *p.routingResult, option), release, nil
}
