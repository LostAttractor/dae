package outbound

import (
	"errors"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// Connection policies end a generation of relays without retiring their node.
// Each relay holds the generation selected before dialing, so a policy change
// also reaches connections whose setup has not finished yet.
type connectionPolicy struct {
	closeOnReselect bool
	closeOnRecovery bool
	networks        [common.NetworkTypeCount]connectionGeneration
}

type connectionGeneration struct {
	selected string // Stable path identity survives reloads and unavailable nodes.
	regular  *netproxy.Lease
	fallback *netproxy.Lease
}

// SetConnectionPolicy configures the group before connectivity checks start.
func (g *DialerGroup) SetConnectionPolicy(closeOnReselect, closeOnRecovery bool) {
	g.connections.closeOnReselect = closeOnReselect
	g.connections.closeOnRecovery = closeOnRecovery
}

func (g *DialerGroup) connectionLease(network *common.NetworkType, fallback bool) *netproxy.Lease {
	p := &g.connections
	if g.Kind != GroupKindSelector {
		return nil
	}
	generation := &p.networks[network.Index()]
	lease := &generation.regular
	if fallback {
		lease = &generation.fallback
	}
	if *lease == nil {
		*lease = netproxy.NewLease(netproxy.NewResourceRef())
	}
	return *lease
}

// InheritConnections transfers relay generations after old stops. Reload must
// preserve fallback ownership, including recovery completed during preparation.
func (g *DialerGroup) InheritConnections(old *DialerGroup) {
	g.mu.Lock()
	defer g.mu.Unlock()
	old.mu.Lock()
	g.connections.networks = old.connections.networks
	old.connections.networks = [common.NetworkTypeCount]connectionGeneration{}
	old.mu.Unlock()
	// Preparation may already have selected a different path. If no path is
	// ready yet, retain the old identity until the next successful selection.
	for i := range common.NetworkTypeCount {
		_, _ = g.selectLocked(common.NetworkIndex(i).NetworkType())
	}
	g.closeRecoveredConnections()
}

func (g *DialerGroup) updateConnectionSelection(network *common.NetworkType, d *dialer.Dialer) {
	p := &g.connections
	generation := &p.networks[network.Index()]
	selected := d.StatsID()
	if generation.selected != "" && generation.selected != selected {
		g.closeReselectedConnections(network)
	}
	generation.selected = selected
}

func (g *DialerGroup) closeReselectedConnections(network *common.NetworkType) {
	if !g.connections.closeOnReselect {
		return
	}
	generation := &g.connections.networks[network.Index()]
	g.abortConnections(network, "group reselected node", generation.regular, generation.fallback)
	generation.regular, generation.fallback = nil, nil
}

func (g *DialerGroup) closeRecoveredConnections() {
	if !g.connections.closeOnRecovery {
		return
	}
	for i, available := range g.networkAvailable {
		if available {
			generation := &g.connections.networks[i]
			g.abortConnections(common.NetworkIndex(i).NetworkType(), "fallback recovered", generation.fallback)
			generation.fallback = nil
		}
	}
}

// Caller holds mu, closing the gates before exposing a new generation.
func (g *DialerGroup) abortConnections(network *common.NetworkType, reason string, leases ...*netproxy.Lease) {
	cause := netproxy.WrapFailure(errors.New(reason), netproxy.Failure{Origin: netproxy.OriginLocalCleanup})
	closed := false
	for _, lease := range leases {
		closed = lease.Abort(cause) || closed
	}
	if closed {
		log.WithFields(log.Fields{"group": g.Name, "network": network.String()}).Info(reason + "; closing existing connections")
	}
}
