// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/daeuniverse/dae/api"
)

func (c *ControlPlane) clientGroup(name string) api.ClientGroup {
	configuration := c.clients[name]
	group := api.ClientGroup{Name: name, Description: configuration.Description, IPSet: configuration.IPSet, NFTSet: configuration.NFTSet, Members: []string{}}
	for _, mac := range c.settings.Members(name) {
		group.Members = append(group.Members, net.HardwareAddr(mac[:]).String())
	}
	return group
}

func (c *ControlPlane) ClientGroups() api.ClientGroups {
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	result := api.ClientGroups{Groups: []api.ClientGroup{}}
	for _, name := range c.clientSets() {
		result.Groups = append(result.Groups, c.clientGroup(name))
	}
	return result
}

func (c *ControlPlane) managedDevice(mac [6]byte) api.ManagedDevice {
	result := api.ManagedDevice{MAC: net.HardwareAddr(mac[:]).String(), Sets: []api.ClientSetState{}}
	for _, name := range c.clientSets() {
		result.Sets = append(result.Sets, api.ClientSetState{Name: name, Description: c.clients[name].Description, Joined: slices.Contains(c.settings.Members(name), mac)})
	}
	if enabled, exists := c.settings.MITM(mac); exists {
		result.MITMOverride = new(enabled)
	}
	return result
}

func (c *ControlPlane) ManagedDevice(mac [6]byte) api.ManagedDevice {
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	return c.managedDevice(mac)
}

func (c *ControlPlane) UpdateManagedMembership(name string, mac [6]byte, joined bool) (api.ClientGroup, error) {
	if !c.HasClientSet(name) {
		return api.ClientGroup{}, fmt.Errorf("client set not found")
	}
	if _, err := c.UpdateClientSet(name, netip.Addr{}, mac, joined); err != nil {
		return api.ClientGroup{}, err
	}
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	return c.clientGroup(name), nil
}

func (c *ControlPlane) UpdateManagedMITM(mac [6]byte, enabled *bool) (api.ManagedDevice, error) {
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	if err := c.settings.SetMITM(mac, enabled); err != nil {
		return api.ManagedDevice{}, err
	}
	return c.managedDevice(mac), nil
}

func (c *ControlPlane) DiagnosticDeviceContext(input api.DiagnosticContext) api.DeviceContext {
	ip, _ := diagnosticAddress(input.SourceIP)
	mac, _ := diagnosticMAC(input.MAC)
	result := api.DeviceContext{Generation: c.routingGeneration, Context: input, Fields: []api.DiagnosticField{{Name: "source_ip", Value: input.SourceIP, Source: "request"}, {Name: "link_type", Value: input.LinkType, Source: "request"}}}
	if input.MAC != "" {
		result.Device = new(c.DeviceState(ip, mac))
		result.Fields = append(result.Fields, api.DiagnosticField{Name: "mac", Value: input.MAC, Source: "request"})
	}
	if input.IfIndex != nil {
		result.Fields = append(result.Fields, api.DiagnosticField{Name: "ifindex", Value: fmt.Sprint(*input.IfIndex), Source: "request"})
	}
	if input.PhysicalIfIndex != nil {
		result.Fields = append(result.Fields, api.DiagnosticField{Name: "physical_ifindex", Value: fmt.Sprint(*input.PhysicalIfIndex), Source: "request"})
	}
	return result
}

func (c *ControlPlane) ClientImpact(ctx context.Context, name string, request api.ClientImpactRequest, inherited bool) (*api.ClientImpact, error) {
	if request.Joined == nil {
		return nil, fmt.Errorf("joined is required")
	}
	mac, err := diagnosticMAC(request.Context.MAC)
	if err != nil {
		return nil, err
	}
	if !c.HasClientSet(name) {
		return nil, fmt.Errorf("client set not found")
	}
	contextRequest := api.ExplainRequest{Context: request.Context}
	if err := prepareDiagnosticRequest(&contextRequest); err != nil {
		return nil, err
	}
	request.Context = contextRequest.Context
	if c.routingMatcher == nil {
		return nil, fmt.Errorf("routing is unavailable")
	}
	result := &api.ClientImpact{Generation: c.routingGeneration, Name: name, JoinedAfter: *request.Joined, ConnectionBehavior: "retain", Exports: []string{}, Rules: []api.ExplainStep{}}
	if c.closeOnRouteChange {
		result.ConnectionBehavior = "close"
	}
	group := c.clients[name]
	if group.IPSet != "" {
		result.Exports = append(result.Exports, "ipset:"+group.IPSet)
	}
	if group.NFTSet != "" {
		result.Exports = append(result.Exports, "nftset:"+group.NFTSet)
	}
	c.settingsMu.Lock()
	result.JoinedBefore = slices.Contains(c.settings.Members(name), mac)
	m := c.routingMatcher.diagnosticSnapshot()
	c.settingsMu.Unlock()
	input, missing, _, err := diagnosticInput(contextRequest, m)
	if err != nil {
		return nil, err
	}
	if request.Flow != nil {
		result.Trace, err = c.Explain(ctx, api.ExplainRequest{Context: request.Context, Flow: *request.Flow, Compare: &api.DiagnosticAssumptions{ClientSets: map[string]bool{name: *request.Joined}}, Detail: "predicates"}, inherited)
		if err != nil {
			return nil, err
		}
		for _, field := range result.Trace.Context {
			if field.Name == "client."+name {
				result.JoinedBefore = field.Value == "true"
			}
		}
	}
	sharedRules := make(map[uint32]bool)
	for _, profile := range m.profileInfo {
		occurrence := 0
		for _, span := range profile.Spans {
			for start := span.Start; start < span.End; {
				end := start
				for end+1 < span.End && diagnosticAction(m.matches[end].Action) == "logical" {
					end++
				}
				related := false
				var conditions []api.ExplainCondition
				for i := start; i <= end; i++ {
					if m.clientAt(i) != name {
						continue
					}
					related = true
					before, after := result.JoinedBefore, result.JoinedAfter
					if m.matches[i].Flags&matchFlagNot != 0 {
						before, after = !before, !after
					}
					conditions = append(conditions, api.ExplainCondition{Expression: m.matchMetadata[i].expression, Match: map[bool]string{true: "match", false: "miss"}[after], Status: "supplementary", Reason: "membership_change", Actual: fmt.Sprint(before), Expected: fmt.Sprint(after)})
				}
				if related {
					meta := m.ruleMetadata[start]
					step := api.ExplainStep{ID: fmt.Sprintf("%s/%d/%d", profileName(profile), occurrence, start), Parent: profileName(profile), Policy: profileName(profile), Section: meta.section, Stage: "client_impact", Expression: meta.expression, Sources: meta.sources, Conditions: conditions, Status: "referenced", Match: "unknown", Reason: "client_reference", Action: diagnosticAction(m.matches[end].Action)}
					if span.Global {
						// System/plugin rules have global scope. Reused policy
						// fragments retain each policy occurrence even when compiled once.
						step.ID, step.Parent, step.Policy = fmt.Sprintf("shared/%d", start), "", ""
						if !sharedRules[start] {
							result.Rules = append(result.Rules, step)
							sharedRules[start] = true
						}
					} else {
						result.Rules = append(result.Rules, step)
					}
				}
				occurrence++
				start = end + 1
			}
		}
	}
	m.annotatePolicyMatches(result.Rules, input.profileID, !missing["policy"])
	return result, err
}
