// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/mitm"
	log "github.com/sirupsen/logrus"
)

func (c *planeHTTP) MITMStatus() api.PluginStatus {
	host := c.MITMHost()
	if host == nil {
		return api.PluginStatus{BufferMemory: mitm.BodyBufferStatus()}
	}
	return host.Status()
}

// Pure inspection can use an existing route. Request transformations are
// admitted separately, before any terminal route for the old target.
func (c *ControlPlane) mitmMode(domain string, src, dst netip.AddrPort, result *routingResult) mitm.HTTPMode {
	host := c.MITMHost()
	if host == nil {
		return mitm.HTTPBypass
	}
	mode := host.Match(domain, dst.Port())
	if mode == mitm.HTTPBypass {
		return mode
	}
	src = common.ConvergeAddrPort(src)
	enabled, _ := c.mitmSelection(src.Addr(), result.Mac)
	if !enabled && log.IsLevelEnabled(log.DebugLevel) {
		mac := "unknown"
		if result.Mac != [6]byte{} {
			mac = net.HardwareAddr(result.Mac[:]).String()
		}
		log.WithFields(log.Fields{
			"event": "mitm_bypass", "host": domain, "port": dst.Port(),
			"source": src.String(), "mac": mac, "reason": "client_not_allowed",
		}).Debug("MITM bypassed for client")
	}
	if !enabled {
		return mitm.HTTPBypass
	}
	return mode
}

func (c *ControlPlane) mitmAuthority() *localca.Authority {
	if host := c.MITMHost(); host != nil {
		return host.Authority()
	}
	return nil
}

// mitmSelection is shared by the traffic gate and the device API. An explicit
// device setting takes precedence over the configured IP/MAC allowlist.
func (c *ControlPlane) mitmSelection(ip netip.Addr, mac [6]byte) (enabled bool, override *bool) {
	c.httpClients.mu.RLock()
	defer c.httpClients.mu.RUnlock()
	return c.httpClients.policy.Match(ip, mac)
}

// mitmState reports the effective selection together with the configured
// default from one policy generation.
func (c *ControlPlane) mitmState(ip netip.Addr, mac [6]byte) (enabled bool, override *bool, configured bool) {
	c.httpClients.mu.RLock()
	defer c.httpClients.mu.RUnlock()
	enabled, override = c.httpClients.policy.Match(ip, mac)
	return enabled, override, c.httpClients.policy.Default(ip, mac)
}

// Request-transforming scopes are admitted before choosing any upstream route
// or dialer. A candidate miss/client exclusion follows ordinary connection
// routing, including destination rules; pure inspection retains its route.
// host is the HTTP authority candidate. It may be the destination IP for TLS
// without SNI; p.Domain keeps the original sniffed name for ordinary routing.
func (c *ControlPlane) prepareHTTPRoute(ctx context.Context, host string, p *RouteParam) (*DialOption, mitm.UpstreamPlanner, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	mode := c.mitmMode(host, p.Src, p.Dest, p.routingResult)
	if mode == mitm.HTTPRequest {
		return nil, c.mitmUpstreamPlanner(string(p.networkType.L4Proto), host, p.Src, p.Dest, *p.routingResult, nil), nil, nil
	}
	option, err := c.RouteDialOption(ctx, p)
	if err != nil {
		return nil, nil, nil, err
	}
	if mode != mitm.HTTPInspect || option.Outbound.IsBlock() {
		return option, nil, nil, nil
	}
	release, err := option.Dialer.Retain()
	if err != nil {
		return nil, nil, nil, err
	}
	c.logDial(p.Src, p.Dest, p.Domain, option, option.NetworkType.String(), p.routingResult)
	return option, c.mitmUpstreamPlanner(string(p.networkType.L4Proto), host, p.Src, p.Dest, *p.routingResult, option), release, nil
}
