package outbound

import (
	"errors"
	"net"
	"sync"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// Connection policies end a generation of relays without retiring their node.
// Each relay holds the generation selected before dialing, so a policy change
// also reaches connections whose setup has not finished yet.
type connectionPolicy struct {
	mu              sync.Mutex
	closeOnReselect bool
	closeOnRecovery bool
	networks        [common.NetworkTypeCount]connectionGeneration
}

type connectionGeneration struct {
	regular  *netproxy.Lease
	fallback *netproxy.Lease
}

func (g *DialerGroup) SetConnectionPolicy(closeOnReselect, closeOnRecovery bool) {
	g.connections.closeOnReselect = closeOnReselect
	g.connections.closeOnRecovery = closeOnRecovery
}

func (g *DialerGroup) connectionLease(network *common.NetworkType, fallback bool) *netproxy.Lease {
	p := &g.connections
	p.mu.Lock()
	defer p.mu.Unlock()
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
	g.notifyMu.Lock()
	defer g.notifyMu.Unlock()
	old.connections.mu.Lock()
	g.connections.mu.Lock()
	g.connections.networks = old.connections.networks
	old.connections.networks = [common.NetworkTypeCount]connectionGeneration{}
	g.connections.mu.Unlock()
	old.connections.mu.Unlock()
	// Preparation may have completed the recovery before ownership transfers.
	g.closeRecoveredConnections()
}

func (g *DialerGroup) closeConnectionGeneration(network *common.NetworkType, reselected bool) {
	p := &g.connections
	p.mu.Lock()
	generation := &p.networks[network.Index()]
	var regular, fallback *netproxy.Lease
	reason := "fallback recovered"
	if reselected {
		if p.closeOnReselect {
			regular, fallback = generation.regular, generation.fallback
			generation.regular, generation.fallback = nil, nil
		}
		reason = "group reselected node"
	} else if p.closeOnRecovery {
		fallback = generation.fallback
		generation.fallback = nil
	}
	// Close the gates before exposing the next generation.
	cause := netproxy.WrapFailure(errors.New(reason), netproxy.Failure{Origin: netproxy.OriginLocalCleanup})
	regular.Abort(cause)
	fallback.Abort(cause)
	p.mu.Unlock()
	if regular != nil || fallback != nil {
		log.WithFields(log.Fields{"group": g.Name, "network": network.String()}).Info(reason + "; closing existing connections")
	}
}

// SelectConnection returns the policy termination signal with the selection.
// On ErrNoAliveDialer the signal belongs to this group's fallback connections.
func (g *DialerGroup) SelectConnection(network common.NetworkType, strictIP bool) (*dialer.Dialer, common.NetworkType, bool, *netproxy.Lease, error) {
	// Serialize fallback registration with availability publication. A recovery
	// that races a failed selection must also terminate that fallback setup.
	g.notifyMu.Lock()
	defer g.notifyMu.Unlock()
	if g.closed.Load() {
		return nil, network, false, nil, net.ErrClosed
	}
	requested := network
	d, lease, err := g.selectConnection(&network)
	fallbackIP := false
	if !strictIP && errors.Is(err, ErrNoAliveDialer) {
		network.IpVersion = (consts.IpVersion_X - network.IpVersion.ToIpVersionType()).ToIpVersionStr()
		d, lease, err = g.selectConnection(&network)
		fallbackIP = true
	}
	if errors.Is(err, ErrNoAliveDialer) {
		lease = g.connectionLease(&requested, true)
	}
	return d, network, fallbackIP, lease, err
}

func (g *DialerGroup) selectConnection(network *common.NetworkType) (*dialer.Dialer, *netproxy.Lease, error) {
	if g.selector != nil {
		g.selector.mu.Lock()
		defer g.selector.mu.Unlock()
		g.selector.refreshNetwork(network.Index(), nil, false)
		d := g.selector.selected[network.Index()]
		if g.closed.Load() {
			return nil, nil, net.ErrClosed
		}
		if d == nil || !d.Usable(network) {
			return nil, nil, ErrNoAliveDialer
		}
		return d, g.connectionLease(network, false), nil
	}
	d, err := g.Select(network)
	if err != nil {
		return nil, nil, err
	}
	return d, g.connectionLease(network, false), nil
}
