// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"slices"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
)

func (c *planeHTTP) SetPluginConfiguration(plugins config.Plugins, compiled []string) {
	c.mitmMu.Lock()
	defer c.mitmMu.Unlock()
	c.pluginStatus.CompiledPlugins = append([]string{}, compiled...)
	c.pluginStatus.Plugins = pluginConfigurationStatus(plugins)
}

func pluginConfigurationStatus(plugins config.Plugins) []api.PluginInstanceStatus {
	instances := make([]api.PluginInstanceStatus, 0, len(plugins))
	for _, p := range plugins {
		instances = append(instances, api.PluginInstanceStatus{ID: p.Name, Type: p.Type, Enabled: p.Enabled})
	}
	return instances
}

// MITMStatus queries plugins without holding mitmMu, so a status poll never
// queues reloads, and the flows behind them, behind plugin reports. Updates
// replace the configured slices instead of modifying them.
func (c *planeHTTP) MITMStatus() api.PluginStatus {
	c.mitmMu.RLock()
	host, configured := c.mitmHost, c.pluginStatus
	c.mitmMu.RUnlock()
	snapshot := api.PluginStatus{BufferMemory: mitm.BodyBufferStatus()}
	if host != nil {
		snapshot = host.Status()
	}
	snapshot.CompiledPlugins = append([]string{}, configured.CompiledPlugins...)
	live := snapshot.Plugins
	snapshot.Plugins = make([]api.PluginInstanceStatus, 0, len(live)+len(configured.Plugins))
	for _, p := range configured.Plugins {
		if !p.Enabled {
			p.State, p.HTTPReason = "disabled", "disabled"
		} else if i := slices.IndexFunc(live, func(status api.PluginInstanceStatus) bool { return status.ID == p.ID }); i >= 0 {
			p = live[i]
		} else {
			p.State, p.HTTPReason = "unavailable", "unavailable"
		}
		snapshot.Plugins = append(snapshot.Plugins, p)
	}
	for _, p := range live {
		if !slices.ContainsFunc(configured.Plugins, func(status api.PluginInstanceStatus) bool { return status.ID == p.ID }) {
			snapshot.Plugins = append(snapshot.Plugins, p)
		}
	}
	return snapshot
}

// Pure inspection can use an existing route. Request transformations are
// admitted separately, before any terminal route for the old target.
func (c *ControlPlane) mitmMode(host *mitm.Host, domain string, src, dst netip.AddrPort, result *routingResult) mitm.HTTPMode {
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

// mitmRoute owns admission and any retained dialer until setup fails or the
// protocol connection ends. TCP and QUIC transfer this owner as a unit.
type mitmRoute struct {
	admission     *mitm.Admission
	planner       mitm.UpstreamPlanner
	releaseDialer func()
}

func (r *mitmRoute) Release() {
	if r == nil {
		return
	}
	if r.releaseDialer != nil {
		r.releaseDialer()
	}
	r.admission.Release()
}

// Request-transforming scopes are admitted before choosing any upstream route
// or dialer. A candidate miss/client exclusion follows ordinary connection
// routing, including destination rules; pure inspection retains its route.
// A non-nil intercepted result transfers all MITM ownership to the caller.
// host is the HTTP authority candidate. It may be the destination IP for TLS
// without SNI; p.Domain keeps the original sniffed name for ordinary routing.
func (c *ControlPlane) prepareHTTPRoute(ctx context.Context, host string, p *RouteParam) (option *DialOption, intercepted *mitmRoute, err error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	c.mitmMu.RLock()
	bypass := c.mitmHost == nil && c.mitmHandoff == nil
	c.mitmMu.RUnlock()
	if bypass {
		option, err := c.routeDialOption(ctx, p, func(string) bool { return false })
		return option, nil, err
	}
	admission, err := c.admitMITM(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if intercepted == nil {
			admission.Release()
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(admission.Context(), cancel)
	defer stop()
	mode := c.mitmMode(admission.Host(), host, p.Src, p.Dest, p.routingResult)
	if mode == mitm.HTTPRequest {
		return nil, &mitmRoute{
			admission: admission,
			planner:   c.mitmUpstreamPlanner(string(p.networkType.L4Proto), host, p.Src, p.Dest, *p.routingResult, nil),
		}, nil
	}
	option, err = c.routeDialOption(ctx, p, admission.UseDNSAddress)
	if err != nil {
		return nil, nil, err
	}
	if mode != mitm.HTTPInspect {
		return option, nil, nil
	}
	release, err := option.Dialer.Retain()
	if err != nil {
		return nil, nil, err
	}
	c.logDial(p.Src, p.Dest, p.Domain, option, option.NetworkType.String(), p.routingResult)
	return option, &mitmRoute{
		admission:     admission,
		planner:       c.mitmUpstreamPlanner(string(p.networkType.L4Proto), host, p.Src, p.Dest, *p.routingResult, option),
		releaseDialer: release,
	}, nil
}
