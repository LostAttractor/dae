// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
)

// Outbounds are immutable after preparation; callbacks consume the published snapshot.
type planeOutbounds struct {
	outbounds              []*outbound.DialerGroup
	outboundReleases       []func() error
	borrowedOutbounds      map[*outbound.DialerGroup]bool
	connectivityOutbounds  atomic.Pointer[[]*outbound.DialerGroup]
	criticalOutbounds      []bool
	outboundCheckAsync     []bool
	noConnectivityOutbound consts.OutboundIndex
}

type planeTraffic struct {
	tcpConnections   *tcpConnectionTracker
	udpTaskPool      *udpTaskPool
	udpSlowWork      atomic.Int32
	udpEndpoints     *UdpEndpointPool
	tcpSetupCtx      context.Context
	cancelTCPSetups  context.CancelFunc
	udpDraining      atomic.Bool
	abortConnections atomic.Bool
}

type planeHTTP struct {
	mitmHost         *mitm.Host
	pluginStatus     api.PluginStatus
	mitmPlan         plugin.Plan // Accepted, expanded routing inputs; immutable.
	mitmMu           sync.RWMutex
	mitmHandoff      *mitmHandoff
	retiredHosts     sync.WaitGroup
	workerRoundTrips sync.WaitGroup
	mitmClients      clientmatch.Matcher
	mitmEnabled      bool
	httpClients      httpClientAdmission
}

type planeAPI struct {
	settings   *settings.Store
	settingsMu sync.Mutex
	apiKey     string
	apiPort    uint16
	clients    map[string]config.Client
	apiBypass  []bpfIpPort
}
