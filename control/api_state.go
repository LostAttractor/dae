// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/daeuniverse/dae/api"
	managementapi "github.com/daeuniverse/dae/component/api"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
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
	state := api.SelectorState{Name: group.Name, DefaultNodeID: group.DefaultSelection(), NodeID: group.Selection(), Nodes: make([]api.SelectorNode, 0, len(group.Dialers))}
	state.Overridden = c.settings.Selection(group.Name) != ""
	for _, d := range group.Dialers {
		status := d.RuntimeStatus()
		node := api.SelectorNode{ID: d.StatsID(), Name: d.Name, Healthy: status.Healthy, Checking: !d.ConnectivitySnapshot().InitialCheckDone}
		if status.Healthy && status.HasLatency {
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
	var group *outbound.DialerGroup
	for _, candidate := range c.outbounds {
		if candidate.Name == name && candidate.IsSelector() {
			group = candidate
			break
		}
	}
	if group == nil {
		return api.SelectorState{}, managementapi.ErrSelectorNotFound
	}
	if id != "" && !slices.ContainsFunc(group.Dialers, func(d *dialer.Dialer) bool { return d.StatsID() == id }) {
		return api.SelectorState{}, managementapi.ErrSelectorNode
	}
	// Keep the live choice and its saved override together, including rollback.
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	if err := group.ChangeSelection(id, func() error { return c.settings.SetSelection(group.Name, id) }); err != nil {
		return api.SelectorState{}, err
	}
	log.WithFields(log.Fields{"event": "selector_update", "group": group.Name, "node_id": group.Selection(), "source_ip": source, "overridden": id != ""}).Info("API settings changed")
	return c.selectorState(group), nil
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
	previous := c.settings.Members(name)
	index := slices.Index(previous, mac)
	if (index >= 0) != joined {
		next := slices.Clone(previous)
		if joined {
			next = append(next, mac)
		} else {
			next = slices.Delete(next, index, index+1)
		}
		changed := make(map[[6]byte]bool)
		if slices.Contains(c.routingMatcherBuilder.ClientSets(), name) {
			changed[mac] = true
		}
		err := c.changeDeviceRoutes(changed, func(commit func() error) error {
			if err := c.setClientMembers(name, previous, next); err != nil {
				return err
			}
			if err := c.settings.SetMembers(name, next); err != nil {
				return errors.Join(err, c.setClientMembers(name, next, previous))
			}
			if err := commit(); err != nil {
				return errors.Join(err, c.settings.SetMembers(name, previous), c.setClientMembers(name, next, previous))
			}
			return nil
		})
		if err != nil {
			return api.DeviceState{}, err
		}
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
