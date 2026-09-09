package outbound

import (
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

// ConnectionSelection binds the selected path to its network and policy lifetime.
// A failed selection can still carry the original group's fallback policy.
type ConnectionSelection struct {
	Dialer  *dialer.Dialer
	Network common.NetworkType
	Lease   *netproxy.Lease
}

// SelectConnection returns the policy termination signal with the selection.
// On ErrNoAliveDialer the signal belongs to this group's fallback connections.
func (g *DialerGroup) SelectConnection(network common.NetworkType, strictIP bool) (ConnectionSelection, error) {
	// Serialize fallback registration with availability publication. A recovery
	// that races a failed selection must also terminate that fallback setup.
	g.mu.Lock()
	defer g.mu.Unlock()
	requested := network
	d, err := g.selectLocked(&network)
	if !strictIP && errors.Is(err, ErrNoAliveDialer) {
		network.IpVersion = (consts.IpVersion_X - network.IpVersion.ToIpVersionType()).ToIpVersionStr()
		d, err = g.selectLocked(&network)
	}
	var lease *netproxy.Lease
	if err == nil {
		lease = g.connectionLease(&network, false)
	} else if errors.Is(err, ErrNoAliveDialer) {
		network = requested
		lease = g.connectionLease(&requested, true)
	}
	return ConnectionSelection{Dialer: d, Network: network, Lease: lease}, err
}

func (g *DialerGroup) IsSelector() bool {
	return g.Kind == GroupKindSelector && g.selectionPolicy.Policy == consts.DialerSelectionPolicy_Selector
}

func (g *DialerGroup) DefaultSelection() string {
	index := g.selectionPolicy.FixedIndex
	if !g.IsSelector() || index < 0 || index >= len(g.Dialers) {
		return ""
	}
	return g.Dialers[index].StatsID()
}

// Selection returns the requested path, including when it is unavailable.
func (g *DialerGroup) Selection() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.IsSelector() {
		return ""
	}
	if selected := g.fixedDialer(); selected != nil {
		return selected.StatsID()
	}
	return ""
}

// SetSelection changes the path for new connections. An empty ID restores the
// configured default. Kernel connectivity is published before success returns.
func (g *DialerGroup) SetSelection(id string) error {
	return g.ChangeSelection(id, func() error { return nil })
}

// ChangeSelection publishes a choice, then commits its settings. On failure it
// restores the old choice without terminating existing connection generations.
// commit must not call this group; notifications and selections wait for it.
func (g *DialerGroup) ChangeSelection(id string, commit func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed.Load() {
		return net.ErrClosed
	}
	if !g.IsSelector() {
		return fmt.Errorf("group %q does not use selector policy", g.Name)
	}
	index := g.selectionPolicy.FixedIndex
	if index < 0 || index >= len(g.Dialers) {
		return fmt.Errorf("group %q: selector default index %d is out of range for %d paths", g.Name, index, len(g.Dialers))
	}
	if id != "" {
		index = slices.IndexFunc(g.Dialers, func(d *dialer.Dialer) bool { return d.StatsID() == id })
		if index == -1 {
			return fmt.Errorf("group %q has no path %q", g.Name, id)
		}
	}
	previous := g.selectionIndex
	if previous == index {
		return commit()
	}
	g.selectionIndex = index
	err := g.updateConnectivity()
	if err == nil {
		err = commit()
	}
	if err != nil {
		g.selectionIndex = previous
		return errors.Join(fmt.Errorf("change selector %q: %w", g.Name, err), g.updateConnectivity())
	}
	g.closeRecoveredConnections()
	for i := range common.NetworkTypeCount {
		g.closeReselectedConnections(common.NetworkIndex(i).NetworkType())
		g.connections.networks[i].selected = g.Dialers[index].StatsID()
	}
	g.Dialers[index].RequestConnectivityCheck()
	return nil
}

// EnableSelectionTolerance switches latency selection from startup best-so-far
// behavior to the configured steady-state hysteresis.
func (g *DialerGroup) EnableSelectionTolerance() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.selector != nil {
		g.selector.toleranceActive = true
	}
}

func (g *DialerGroup) policyDialers() []*dialer.Dialer {
	if g.selectionPolicy.Policy == "" || g.selectionPolicy.Policy == consts.DialerSelectionPolicy_Fixed || g.IsSelector() {
		index := g.selectionIndex
		if index < 0 || index >= len(g.Dialers) {
			return nil
		}
		return g.Dialers[index : index+1]
	}
	return g.Dialers
}

func (g *DialerGroup) fixedDialer() *dialer.Dialer {
	index := g.selectionIndex
	if index < 0 || index >= len(g.Dialers) {
		return nil
	}
	return g.Dialers[index]
}

// SelectedDialer returns the dialer currently selected for the given network
// type. It returns nil for policies without a stable selection (e.g. random)
// or when no dialer is alive.
func (g *DialerGroup) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed.Load() {
		return nil
	}
	var selected *dialer.Dialer
	if g.Kind != GroupKindSelector {
		selected = g.Dialers[0]
	} else {
		switch g.selectionPolicy.Policy {
		case "", consts.DialerSelectionPolicy_Fixed, consts.DialerSelectionPolicy_Selector:
			selected = g.fixedDialer()
		case consts.DialerSelectionPolicy_Random:
			return nil
		default:
			selected = g.selector.selected[networkType.Index()]
		}
	}
	if selected == nil || !selected.Usable(networkType) {
		return nil
	}
	return selected
}

func (g *DialerGroup) Select(networkType *common.NetworkType) (*dialer.Dialer, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.selectLocked(networkType)
}

// Caller holds mu, which also protects the matching connection generation.
func (g *DialerGroup) selectLocked(networkType *common.NetworkType) (*dialer.Dialer, error) {
	if g.closed.Load() {
		return nil, net.ErrClosed
	}
	if len(g.Dialers) == 0 {
		return nil, ErrNoDialer
	}
	if g.Kind != GroupKindSelector {
		d := g.Dialers[0]
		if !d.Usable(networkType) {
			return nil, ErrNoAliveDialer
		}
		return d, nil
	}
	var selected *dialer.Dialer
	switch g.selectionPolicy.Policy {
	case "", consts.DialerSelectionPolicy_Fixed, consts.DialerSelectionPolicy_Selector:
		selected = g.fixedDialer()
	case consts.DialerSelectionPolicy_Random:
		selected = g.selectRandom(networkType)
	default:
		g.selector.refreshNetwork(networkType.Index(), nil, false)
		selected = g.selector.selected[networkType.Index()]
	}
	if selected == nil || !selected.Usable(networkType) {
		return nil, ErrNoAliveDialer
	}
	g.updateConnectionSelection(networkType, selected)
	return selected, nil
}
