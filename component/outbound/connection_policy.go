package outbound

import (
	"errors"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

var (
	errConnectionsInherited = cleanupFailure("connection generation replaced by the inherited one")
	errGroupRemoved         = cleanupFailure("group removed")
	errFallbackRecovered    = cleanupFailure("fallback recovered")
	errRouteRetired         = cleanupFailure("retired route no longer satisfies current connection policy")
)

func cleanupFailure(reason string) error {
	return netproxy.WrapFailure(errors.New(reason), netproxy.Failure{Origin: netproxy.OriginLocalCleanup})
}

func endedLease(cause error) *netproxy.Lease {
	lease := netproxy.NewLease(netproxy.NewResourceRef())
	lease.Abort(cause)
	return lease
}

// Connection policies end a generation of relays without retiring their node.
// Each relay holds the generation selected before dialing, so a policy change
// also reaches connections whose setup has not finished yet.
type connectionPolicy struct {
	successor       *DialerGroup
	closeOnReselect bool
	closeOnRecovery bool
	networks        [common.NetworkTypeCount]connectionGeneration
	// Interruptible fallback generations inherited by a policy that keeps
	// fallbacks. Recovery and reselection keep them; removal still ends them.
	keptFallbacks []*netproxy.Lease
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
	if fallback {
		// A recovery under a closing policy has ended the fallback generation;
		// a setup that raced the recovery ends with it.
		if p.closeOnRecovery && g.networkAvailable[network.Index()] {
			return endedLease(errFallbackRecovered)
		}
		return g.fallbackGeneration(network)
	}
	generation := &p.networks[network.Index()]
	if generation.regular == nil {
		generation.regular = netproxy.NewLease(netproxy.NewResourceRef())
	}
	return generation.regular
}

// fallbackGeneration returns the network's current fallback generation, owned
// by the successor after a reload. Caller holds mu.
func (g *DialerGroup) fallbackGeneration(network *common.NetworkType) *netproxy.Lease {
	if successor := g.connections.successor; successor != nil {
		successor.mu.Lock()
		defer successor.mu.Unlock()
		return successor.fallbackGeneration(network)
	}
	generation := &g.connections.networks[network.Index()]
	if generation.fallback == nil {
		generation.fallback = netproxy.NewLease(netproxy.NewResourceRef())
	}
	return generation.fallback
}

// interruptibleFallback returns the fallback generation a connection policy
// can end, so fallback flows forwarded outside this group (by the kernel) end
// with its relays. Caller holds mu.
func (g *DialerGroup) interruptibleFallback(network *common.NetworkType) *netproxy.Lease {
	if g.Kind != GroupKindSelector || !g.connections.endsFallback() {
		return nil
	}
	return g.fallbackGeneration(network)
}

func (p *connectionPolicy) endsFallback() bool {
	return p.closeOnReselect || p.closeOnRecovery
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
	if p.closeOnReselect && selected != "" && current != "" && current != selected {
		return endedLease(errRouteRetired)
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
	// Generations created only to publish this group's initial state have no
	// relays yet; ending them releases their published fallback identities.
	for _, generation := range g.connections.networks {
		generation.regular.Abort(errConnectionsInherited)
		generation.fallback.Abort(errConnectionsInherited)
	}
	g.connections.networks = old.connections.networks
	g.connections.keptFallbacks, old.connections.keptFallbacks = old.connections.keptFallbacks, nil
	old.connections.successor = g
	for i := range old.connections.networks {
		old.connections.networks[i].regular, old.connections.networks[i].fallback = nil, nil
		// New fallback connections no longer join an interruptible generation.
		if generation := &g.connections.networks[i]; old.connections.endsFallback() && !g.connections.endsFallback() && generation.fallback != nil {
			g.connections.keptFallbacks = append(g.connections.keptFallbacks, generation.fallback)
			generation.fallback = nil
		}
		if g.connections.endsFallback() && !g.networkAvailable[i] {
			g.publishFallback(common.NetworkIndex(i).NetworkType())
		}
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
	regular, fallback := generation.regular, generation.fallback
	generation.regular, generation.fallback = nil, nil
	// New fallback flows join the replacement before the old generation ends.
	if !g.networkAvailable[network.Index()] {
		g.publishFallback(network)
	}
	g.abortConnections(network, "group reselected node", regular, fallback)
}

// publishFallback exposes a replaced fallback generation of an unavailable
// network to observers.
func (g *DialerGroup) publishFallback(network *common.NetworkType) {
	if err := g.publishConnectivity(network.Index(), false); err != nil {
		log.WithFields(log.Fields{"group": g.Name, "network": network.String()}).WithError(err).Error("Failed to publish the fallback connection generation")
	}
}

// A removed group never recovers. Its interruptible fallback connections end
// with it instead, including those forwarded outside the group.
func (g *DialerGroup) closeRemovedFallbacks() {
	if g.connections.successor != nil {
		return
	}
	for _, generation := range g.connections.keptFallbacks {
		generation.Abort(errGroupRemoved)
	}
	g.connections.keptFallbacks = nil
	if !g.connections.endsFallback() {
		return
	}
	for i := range g.connections.networks {
		g.connections.networks[i].fallback.Abort(errGroupRemoved)
		g.connections.networks[i].fallback = nil
	}
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

// Caller holds mu, so no relay can join a generation while it ends.
func (g *DialerGroup) abortConnections(network *common.NetworkType, reason string, leases ...*netproxy.Lease) {
	cause := cleanupFailure(reason)
	closed := false
	for _, lease := range leases {
		closed = lease.Abort(cause) || closed
	}
	if closed {
		log.WithFields(log.Fields{"group": g.Name, "network": network.String()}).Info(reason + "; closing connections of the previous generation")
	}
}
