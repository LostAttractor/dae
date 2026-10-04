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
	successor       *DialerGroup
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
	if p.successor != nil {
		return p.successor.inheritedConnectionLease(network, fallback, p.networks[network.Index()].selected)
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

// A retired configuration may still finish an admitted setup or MITM request.
// Its route stays pinned, but the current group owns subsequent close policies.
// Locks follow publication order (predecessor -> successor), never backwards.
func (g *DialerGroup) inheritedConnectionLease(network *common.NetworkType, fallback bool, selected string) *netproxy.Lease {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := &g.connections
	if p.successor != nil {
		return p.successor.inheritedConnectionLease(network, fallback, selected)
	}
	current := p.networks[network.Index()].selected
	if p.closeOnReselect && selected != "" && current != "" && current != selected ||
		fallback && p.closeOnRecovery && g.networkAvailable[network.Index()] {
		lease := netproxy.NewLease(netproxy.NewResourceRef())
		lease.Abort(netproxy.WrapFailure(errors.New("retired route no longer satisfies current connection policy"), netproxy.Failure{Origin: netproxy.OriginLocalCleanup}))
		return lease
	}
	return g.connectionLease(network, fallback)
}

// InheritConnections transfers relay ownership before the new plane admits
// traffic. Later acquisitions by old follow the successor's connection policy.
func (g *DialerGroup) InheritConnections(old *DialerGroup) {
	old.mu.Lock()
	defer old.mu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.connections.networks = old.connections.networks
	old.connections.successor = g
	for i := range old.connections.networks {
		old.connections.networks[i].regular, old.connections.networks[i].fallback = nil, nil
	}
	// Manual choices carry policy identity even while unavailable. Automatic
	// policies retain the old identity until a replacement is ready.
	for i := range common.NetworkTypeCount {
		network := common.NetworkIndex(i).NetworkType()
		if g.IsSelector() {
			if selected := g.fixedDialer(); selected != nil {
				g.updateConnectionSelection(network, selected)
			}
		} else {
			_, _ = g.selectLocked(network)
		}
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
