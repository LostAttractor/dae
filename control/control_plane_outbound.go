/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// buildOutbounds owns partially built groups until construction succeeds.
// The caller then owns their connectivity checks, transports and cleanup.
func (core *controlPlaneCore) buildOutbounds(nodes []outbound.NodeDescriptor, groups []config.Group, routingConfig *config.Routing, global *config.Global, noConnectivityOutbound consts.OutboundIndex) (_ []*outbound.DialerGroup, _ map[string]uint8, err error) {
	if global.AllowInsecure {
		log.Warn("TLS certificate verification disabled for outbound connections")
	}
	option := dialer.NewGlobalOption(global)

	_direct, directProperty := D.NewDirectDialer(&option.ExtraOption)
	direct := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: _direct}), option, &dialer.Property{Property: *directProperty}, false, "")
	_block, blockProperty := D.NewBlockDialer(&option.ExtraOption, func() { /*Dialer Outbound*/ })
	block := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: _block}), option, &dialer.Property{Property: *blockProperty}, false, "")
	outbounds := []*outbound.DialerGroup{
		outbound.NewDialerGroup(option, consts.OutboundDirect.String(), outbound.GroupKindSingleAlwaysAlive,
			[]*dialer.Dialer{direct}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{}, nil).SetTargetMetadata(outbound.TargetKindBuiltin),
		outbound.NewDialerGroup(option, consts.OutboundBlock.String(), outbound.GroupKindInvisible,
			[]*dialer.Dialer{block}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{}, nil).SetTargetMetadata(outbound.TargetKindBuiltin),
	}
	defer func() {
		if err != nil {
			_ = closeDialerGroups(outbounds)
		}
	}()
	// Compile groups and all routing target references before assigning outbound
	// IDs. Policyless groups remain compile-time templates unless routing uses
	// them as an exact-one target.
	dialerSet, err := outbound.NewDialerSet(nodes)
	if err != nil {
		return nil, nil, fmt.Errorf("build node descriptors: %w", err)
	}
	routingTargets := collectRoutingTargetNames(routingConfig)
	groupCompiler, err := outbound.NewGroupCompiler(dialerSet, groups, routingTargets)
	if err != nil {
		return nil, nil, fmt.Errorf("compile proxy groups: %w", err)
	}
	materialized := map[string]struct{}{
		consts.OutboundDirect.String(): {},
		consts.OutboundBlock.String():  {},
	}
	materializedPathCount := 0
	materializeTarget := func(target *outbound.ResolvedTarget) error {
		var name string
		var paths []*outbound.PathSpec
		if node := target.Node; node != nil {
			name = node.Property.Name
			paths = []*outbound.PathSpec{outbound.NodePath(node)}
		}
		finalOption := option
		selectionPolicy := dialer.DialerSelectionPolicy{}
		if group := target.Group; group != nil {
			name = group.Name
			var compileErr error
			paths, compileErr = groupCompiler.ExpandRoutable(group)
			if compileErr != nil {
				return fmt.Errorf("failed to expand group %v: %w", name, compileErr)
			}
			if groupOption := parseGroupOverrideOption(*group, *global); groupOption != nil {
				finalOption = groupOption
				log.WithField("group", name).Debug("Using group connectivity check settings")
			}
			if group.Policy != nil {
				policy, policyErr := dialer.NewDialerSelectionPolicyFromGroupParam(group)
				if policyErr != nil {
					return fmt.Errorf("failed to create group %v: %w", name, policyErr)
				}
				selectionPolicy = *policy
			}
		}
		if len(outbounds) >= int(consts.OutboundUserDefinedMax)+1 {
			return fmt.Errorf("too many outbounds: cannot materialize target %q", name)
		}
		if len(paths) > outbound.MaxMaterializedPaths-materializedPathCount {
			return fmt.Errorf("materializing target %q would exceed the global proxy path limit %d", name, outbound.MaxMaterializedPaths)
		}

		dialers := make([]*dialer.Dialer, 0, len(paths))
		annotations := make([]*dialer.Annotation, 0, len(paths))
		pathOccurrences := make(map[string]int, len(paths))
		for _, path := range paths {
			d, buildErr := dialerSet.BuildPath(path, finalOption, candidateStatsScope(name, path, pathOccurrences))
			if buildErr != nil {
				pathBuildErr, isPathBuildErr := errors.AsType[*outbound.PathBuildError](buildErr)
				if isPathBuildErr && !pathBuildErr.Node.Required {
					log.WithFields(log.Fields{"node": pathBuildErr.Node.Property.Name, "target": name}).
						WithError(resource.RedactError(pathBuildErr.Err)).Warn("Could not build subscription path; skipping node")
					continue
				}
				for _, d := range dialers {
					_ = d.Close()
				}
				return fmt.Errorf("failed to build target %v path: %w", name, buildErr)
			}
			dialers = append(dialers, d)
			annotations = append(annotations, path.Annotation)
		}

		if len(dialers) == 0 {
			return fmt.Errorf("target %q has no usable paths", name)
		}
		id := uint8(len(outbounds))
		outbounds = append(outbounds, outbound.NewDialerGroup(finalOption, name, outbound.GroupKindSelector, dialers, annotations, selectionPolicy,
			core.outboundAliveChangeCallback(id, name, global.NoConnectivityTrySniff, noConnectivityOutbound)).
			SetTargetMetadata(target.Kind))
		closeOnReselect := target.Group != nil && target.Group.ReselectBehavior == "close"
		outbounds[len(outbounds)-1].SetConnectionPolicy(closeOnReselect, global.RouteChangeBehavior == "close")
		materializedPathCount += len(dialers)
		materialized[name] = struct{}{}
		return nil
	}

	for _, group := range groupCompiler.SelectorGroups() {
		if err := materializeTarget(&outbound.ResolvedTarget{Kind: outbound.TargetKindGroup, Group: group}); err != nil {
			return nil, nil, err
		}
	}
	for _, targetName := range routingTargets {
		if isReservedRoutingTarget(targetName) {
			continue
		}
		resolved, resolveErr := groupCompiler.ResolveRoutingTarget(targetName)
		if resolveErr != nil {
			return nil, nil, fmt.Errorf("resolve routing target %q: %w", targetName, resolveErr)
		}
		if _, ok := materialized[targetName]; ok {
			continue
		}
		if err := materializeTarget(resolved); err != nil {
			return nil, nil, err
		}
	}

	// Generate outboundName2Id from outbounds.
	outboundName2Id := make(map[string]uint8)
	for i, o := range outbounds {
		if _, exist := outboundName2Id[o.Name]; exist {
			return nil, nil, fmt.Errorf("duplicated outbound name: %v", o.Name)
		}
		outboundName2Id[o.Name] = uint8(i)
	}

	return outbounds, outboundName2Id, nil
}

func collectRoutingTargetNames(routingConfig *config.Routing) []string {
	if routingConfig == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var targets []string
	appendTarget := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		targets = append(targets, name)
	}
	appendStatements := func(statements []config.RoutingStatement) {
		for _, statement := range statements {
			if statement.Kind == config.RoutingStatementRule {
				appendTarget(statement.Rule.Outbound.Name)
			}
		}
	}
	for _, set := range routingConfig.RuleSets {
		appendStatements(set.Statements)
	}
	for _, policy := range routingConfig.Policies {
		appendStatements(policy.Statements)
		appendTarget(policy.Fallback.Name)
	}
	return targets
}

func isReservedRoutingTarget(name string) bool {
	switch name {
	case consts.OutboundDirect.String(), consts.OutboundBlock.String(),
		consts.OutboundMustRules.String(), consts.OutboundControlPlaneRouting.String():
		return true
	default:
		return false
	}
}

func candidateStatsScope(target string, path *outbound.PathSpec, occurrences map[string]int) string {
	identity := path.Identity()
	index := occurrences[identity]
	occurrences[identity] = index + 1
	return strconv.Itoa(len(target)) + ":" + target + ":" + strconv.Itoa(index)
}

func (c *ControlPlane) reconcileStats() {
	nodes := make(map[string]stats.NodeIdentity)
	groups := make(map[string]struct{}, len(c.outbounds))
	for _, group := range c.outbounds {
		if group.ChecksConnectivity() {
			groups[group.Name] = struct{}{}
		}
		for _, d := range group.Dialers {
			key := d.StatsKey()
			nodes[key] = stats.NodeIdentity{
				Subtag: d.Property.SubscriptionTag,
				Name:   d.Name,
			}
		}
	}
	stats.DefaultStore.Reconcile(nodes, groups)
}

func parseGroupOverrideOption(group config.Group, global config.Global) *dialer.GlobalOption {
	result := global
	changed := false
	if group.UdpCheckDns != nil {
		result.UdpCheckDns = group.UdpCheckDns
		changed = true
	}
	if group.CheckInterval != 0 {
		result.CheckInterval = group.CheckInterval
		changed = true
	}
	if group.CheckIntervalMax != 0 {
		result.CheckIntervalMax = group.CheckIntervalMax
		changed = true
	}
	if group.CheckTolerance != 0 || group.Present["check_tolerance"] {
		result.CheckTolerance = group.CheckTolerance
		changed = true
	}
	if changed {
		return dialer.NewGlobalOption(&result)
	}
	return nil
}

// closeOutbounds stops the connectivity checks of all outbound groups.
func (c *ControlPlane) closeOutbounds() (err error) {
	return closeDialerGroups(c.outbounds)
}

func closeDialerGroups(groups []*outbound.DialerGroup) (err error) {
	for _, g := range groups {
		err = errors.Join(err, g.Close())
	}
	return err
}
