// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
)

// Validate policy before consuming prepared resources. No workers, transports,
// kernel subscriptions or contexts exist until initialize owns the core.
func configuredControlPlane(conf *config.Config, global *config.Global, runtimeSettings *settings.Store) (*ControlPlane, error) {
	var err error
	var mitmClients clientmatch.Matcher
	if conf.MITM.Enabled {
		clients := conf.MITM.ClientSourceAddress
		mitmClients, err = clientmatch.Parse(clients)
		if err != nil {
			return nil, fmt.Errorf("mitm client_source_address: %w", err)
		}
	}
	if runtimeSettings == nil {
		return nil, fmt.Errorf("runtime settings are required")
	}
	global.SoMarkFromDae = common.EffectiveSoMarkFromDae(global.SoMarkFromDae)
	if err = common.ValidateSoMarkFromDae(global.SoMarkFromDae); err != nil {
		return nil, err
	}
	if err := consts.VerifyRerouteMode(string(global.RerouteMode)); err != nil {
		return nil, err
	}
	if err := consts.VerifySniffVerifyMode(string(global.SniffVerifyMode)); err != nil {
		return nil, err
	}

	sniffingTimeout := global.SniffingTimeout
	if !global.DialTargetOverride && global.RerouteMode == consts.RerouteMode_None {
		// Sniff is not needed.
		sniffingTimeout = 0
	}

	if err := config.ValidateConnectionBehavior("route_change_behavior", global.RouteChangeBehavior); err != nil {
		return nil, err
	}
	var noConnectivityOutbound consts.OutboundIndex
	if global.NoConnectivityBehavior == "direct" {
		noConnectivityOutbound = consts.OutboundDirect
	} else if global.NoConnectivityBehavior == "block" {
		noConnectivityOutbound = consts.OutboundBlock
	} else {
		return nil, fmt.Errorf("invalid no_connectivity_behavior: %v", global.NoConnectivityBehavior)
	}

	wanInterface, autoWan := splitWanInterfaces(global.WanInterface)
	clients := make(map[string]config.Client, len(conf.Client))
	for _, client := range conf.Client {
		clients[client.Name] = client
	}
	return &ControlPlane{
		settings:                  runtimeSettings,
		apiKey:                    global.APIKey,
		apiPort:                   global.APIPort,
		clients:                   clients,
		mitmClients:               mitmClients,
		closeOnRouteChange:        global.RouteChangeBehavior == "close",
		noConnectivityOutbound:    noConnectivityOutbound,
		noConnectivityTrySniff:    global.NoConnectivityTrySniff,
		lanInterface:              uniqueInterfaceNames(global.LanInterface),
		wanInterface:              wanInterface,
		autoWan:                   autoWan,
		autoConfigKernelParameter: global.AutoConfigKernelParameter,
		dialTargetOverride:        global.DialTargetOverride,
		rerouteMode:               global.RerouteMode,
		sniffVerifyMode:           global.SniffVerifyMode,
		sniffingTimeout:           sniffingTimeout,
		soMarkFromDae:             global.SoMarkFromDae,
		mptcp:                     global.Mptcp,
	}, nil
}

func (c *ControlPlane) initialize(core *controlPlaneCore) {
	c.core = core
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.planeTraffic = newPlaneTraffic(c.ctx, &core.bpf.tcpConnections, core.bpf.udpEndpoints)
	c.routingGeneration = core.bpf.routingGeneration
	c.deviceRoutes = core.bpf.deviceRoutes
	c.dnsRelay = newDNSRelay()
	c.hostReconcileCh = make(chan struct{}, 1)
	c.realDomainSet = bloom.NewWithEstimates(2048, 0.001)
	// Plugin shutdown drains requests before DNS, outbound checks and transports.
	c.cleanups.add(c.closeOutbounds)
	c.cleanups.add(c.dnsRelay.Close)
}

func (c *ControlPlane) initializeRouting(rules preparedRules, outbounds *outboundBuilder, conf *config.Config) error {
	if err := c.installRouting(&rules, outbounds.nameToID, conf.Group, nil); err != nil {
		return err
	}
	if conf.Global.DNSRetentionWindow > 0 {
		registry := c.core.domainRegistry
		registry.mu.Lock()
		registry.window = conf.Global.DNSRetentionWindow
		registry.mu.Unlock()
	}
	return nil
}
