// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/internal/apiserver"
	log "github.com/sirupsen/logrus"
)

func (c *ControlPlane) deviceState(ip netip.Addr, mac [6]byte) api.DeviceState {
	state := api.DeviceState{SourceIP: ip.String(), MAC: net.HardwareAddr(mac[:]).String(), Sets: make([]api.ClientSetState, 0)}
	for _, name := range c.clientSets() {
		joined := slices.Contains(c.settings.Members(name), mac)
		state.Sets = append(state.Sets, api.ClientSetState{
			Name: name, Description: c.clients[name].Description, Joined: joined,
		})
	}
	if c.mitmAuthority() != nil {
		enabled, override := c.mitmSelection(ip, mac)
		state.MITM = &api.MITMState{Enabled: enabled, Override: override, CAFingerprint: c.mitmAuthority().Fingerprint()}
	}
	return state
}

func (c *ControlPlane) selectorState(group *outbound.DialerGroup) api.SelectorState {
	state := api.SelectorState{Name: group.Name, DefaultNodeID: group.DefaultSelection(), NodeID: group.Selection(), TrackAll: group.TrackAll(), Nodes: make([]api.SelectorNode, 0, len(group.Dialers))}
	if saved := c.settings.Selection(group.Name); saved != nil {
		_, status := group.ResolveSelection(saved)
		state.Overridden = true
		state.SavedSelection = &api.SavedSelectorSelection{Name: saved.String(), Status: status}
	}
	for _, d := range group.Dialers {
		status := d.RuntimeStatus()
		node := api.SelectorNode{
			ID: d.StatsID(), Name: d.Name, Healthy: status.Healthy,
			Egress:   d.Egress,
			Checking: status.Checking, Tested: !status.CheckedAt.IsZero(),
			Tracking: status.CheckEnabled, CheckedAt: status.CheckedAt,
		}
		if status.Dormant {
			node.Healthy = status.ObservedHealthy
		}
		if node.Healthy && status.HasLatency {
			ms := float64(status.Latency.Last) / float64(time.Millisecond)
			node.LatencyMS = &ms
		}
		state.Nodes = append(state.Nodes, node)
	}
	return state
}

func (c *ControlPlane) Selectors() []api.SelectorState {
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	states := make([]api.SelectorState, 0)
	for _, group := range c.outbounds {
		if group.IsSelector() {
			states = append(states, c.selectorState(group))
		}
	}
	return states
}

func (c *ControlPlane) Select(name, id, source string) (api.SelectorState, error) {
	group := c.outboundGroup(name)
	if group == nil || !group.IsSelector() {
		return api.SelectorState{}, apiserver.ErrSelectorNotFound
	}
	if id == "" && group.DefaultSelection() == "" {
		return api.SelectorState{}, apiserver.ErrSelectorNoDefault
	}
	index := slices.IndexFunc(group.Dialers, func(d *dialer.Dialer) bool { return d.StatsID() == id })
	if id != "" && index == -1 {
		return api.SelectorState{}, apiserver.ErrSelectorNode
	}
	// Keep the live choice and its saved override together, including rollback.
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	if err := c.settings.Update(func(next *settings.Snapshot) error {
		if id == "" {
			delete(next.Selectors, group.Name)
		} else {
			next.Selectors[group.Name] = group.Dialers[index].SelectionReference()
		}
		return nil
	}, c.applyRuntimeSettings); err != nil {
		return api.SelectorState{}, err
	}
	log.WithFields(log.Fields{"event": "selector_update", "group": group.Name, "node_id": group.Selection(), "source_ip": source, "overridden": id != ""}).Info("API settings changed")
	return c.selectorState(group), nil
}

// Probe reuses the bounded checker for any instantiated, checked outbound.
// The API owner keeps this plane alive until the request has returned.
func (c *ControlPlane) Probe(request api.ProbeRequest, source string) (api.ProbeResponse, error) {
	group := c.outboundGroup(request.Outbound)
	if group == nil {
		return api.ProbeResponse{}, apiserver.ErrProbeOutbound
	}
	if !group.ChecksConnectivity() {
		return api.ProbeResponse{}, apiserver.ErrProbeUnsupported
	}
	if request.NodeID != "" && !slices.ContainsFunc(group.Dialers, func(d *dialer.Dialer) bool { return d.StatsID() == request.NodeID }) {
		return api.ProbeResponse{}, apiserver.ErrProbeNode
	}
	response := api.ProbeResponse{Outbound: group.Name, NodeIDs: make([]string, 0, len(group.Dialers))}
	for _, d := range group.Dialers {
		if request.NodeID == "" || d.StatsID() == request.NodeID {
			d.RequestManualCheck()
			response.NodeIDs = append(response.NodeIDs, d.StatsID())
		}
	}
	log.WithFields(log.Fields{"event": "outbound_probe", "outbound": group.Name, "node_id": request.NodeID, "source_ip": source}).Debug("Connectivity probe requested")
	return response, nil
}

func (c *ControlPlane) outboundGroup(name string) *outbound.DialerGroup {
	for _, candidate := range c.outbounds {
		if candidate.Name == name {
			return candidate
		}
	}
	return nil
}

func (c *ControlPlane) HasClientSet(name string) bool {
	return slices.Contains(c.clientSets(), name)
}

func (c *ControlPlane) DeviceState(ip netip.Addr, mac [6]byte) api.DeviceState {
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	return c.deviceState(ip, mac)
}

func (c *ControlPlane) UpdateClientSet(name string, ip netip.Addr, mac [6]byte, joined bool) (api.DeviceState, error) {
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	changed := false
	err := c.settings.Update(func(next *settings.Snapshot) error {
		members := next.Clients[name]
		text := net.HardwareAddr(mac[:]).String()
		index := slices.Index(members, text)
		if (index >= 0) == joined {
			return nil
		}
		changed = true
		if joined {
			members = append(members, text)
		} else {
			members = slices.Delete(members, index, index+1)
		}
		slices.Sort(members)
		if len(members) == 0 {
			delete(next.Clients, name)
		} else {
			next.Clients[name] = members
		}
		return nil
	}, c.applyRuntimeSettings)
	if err != nil {
		return api.DeviceState{}, err
	}
	if changed {
		log.WithFields(log.Fields{"event": "client_set_update", "set": name, "mac": net.HardwareAddr(mac[:]).String(), "source_ip": ip.String(), "joined": joined}).Info("API settings changed")
	}
	return c.deviceState(ip, mac), nil
}

func (c *ControlPlane) UpdateMITM(ip netip.Addr, mac [6]byte, enabled *bool) (api.DeviceState, error) {
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	if err := c.settings.SetMITM(mac, enabled); err != nil {
		return api.DeviceState{}, err
	}
	state := c.deviceState(ip, mac)
	log.WithFields(log.Fields{"event": "mitm_client_update", "source_ip": ip.String(), "mac": net.HardwareAddr(mac[:]).String(), "enabled": state.MITM.Enabled}).Info("API settings changed")
	return state, nil
}
