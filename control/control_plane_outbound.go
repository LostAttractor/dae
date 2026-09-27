/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

// outboundBuilder exists only during preparation. Definitions are validated
// without constructing transports; only reachable targets receive runtime IDs.
type outboundBuilder struct {
	ctx                    context.Context
	core                   *controlPlaneCore
	set                    *outbound.DialerSet
	compiler               *outbound.GroupCompiler
	global                 *config.Global
	option                 *dialer.GlobalOption
	noConnectivityOutbound consts.OutboundIndex
	outbounds              []*outbound.DialerGroup
	nameToID               map[string]uint8
	validationOutbounds    map[string]uint8
	materializedPathCount  int
}

// buildOutbounds owns partially built groups until construction succeeds.
// The caller then owns their connectivity checks, transports and cleanup,
// including targets appended later by plugin rules.
func (core *controlPlaneCore) buildOutbounds(ctx context.Context, nodes []outbound.NodeDescriptor, groups []config.Group, routingConfig *config.Routing, global *config.Global, noConnectivityOutbound consts.OutboundIndex) (_ *outboundBuilder, err error) {
	if err := routingConfig.Validate(); err != nil {
		return nil, err
	}
	if global.AllowInsecure {
		log.Warn("TLS certificate verification disabled for outbound connections")
	}
	option := dialer.NewGlobalOption(global)

	_direct, directProperty := D.NewDirectDialer(&option.ExtraOption)
	direct := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: _direct}), option, &dialer.Property{Property: *directProperty}, false, "")
	_block, blockProperty := D.NewBlockDialer(&option.ExtraOption, func() { /*Dialer Outbound*/ })
	block := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: _block}), option, &dialer.Property{Property: *blockProperty}, false, "")
	b := &outboundBuilder{
		ctx:  ctx,
		core: core, global: global, option: option, noConnectivityOutbound: noConnectivityOutbound,
		nameToID: map[string]uint8{consts.OutboundDirect.String(): uint8(consts.OutboundDirect), consts.OutboundBlock.String(): uint8(consts.OutboundBlock)},
	}
	b.outbounds = []*outbound.DialerGroup{
		outbound.NewDialerGroup(option, consts.OutboundDirect.String(), outbound.GroupKindSingleAlwaysAlive,
			[]*dialer.Dialer{direct}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{}, nil).SetTargetMetadata(outbound.TargetKindBuiltin),
		outbound.NewDialerGroup(option, consts.OutboundBlock.String(), outbound.GroupKindInvisible,
			[]*dialer.Dialer{block}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{}, nil).SetTargetMetadata(outbound.TargetKindBuiltin),
	}
	defer func() {
		if err != nil {
			_ = closeDialerGroups(b.outbounds)
		}
	}()
	// Compile groups and all routing target references before assigning outbound
	// IDs. Policyless groups remain compile-time templates unless routing uses
	// them as an exact-one target.
	b.set, err = outbound.NewDialerSet(nodes)
	if err != nil {
		return nil, fmt.Errorf("build node descriptors: %w", err)
	}
	routingTargets := collectRoutingTargetNames(routingConfig)
	b.compiler, err = outbound.NewGroupCompiler(b.set, groups, routingTargets)
	if err != nil {
		return nil, fmt.Errorf("compile proxy groups: %w", err)
	}
	b.validationOutbounds = maps.Clone(b.nameToID)
	for _, name := range routingTargets {
		if isReservedRoutingTarget(name) {
			continue
		}
		target, err := b.compiler.ResolveRoutingTarget(name)
		if err != nil {
			return nil, fmt.Errorf("resolve routing target %q: %w", name, err)
		}
		if target.Group != nil {
			if _, err := b.compiler.ExpandRoutable(target.Group); err != nil {
				return nil, fmt.Errorf("validate routing target %q: %w", name, err)
			}
		}
		// Validators never execute these IDs. A user-defined placeholder keeps
		// builtin-only parameter checks without consuming runtime ID capacity.
		b.validationOutbounds[name] = uint8(consts.OutboundUserDefinedMin)
	}
	if err := b.buildTargets(collectActiveRoutingTargetNames(routingConfig)); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *outboundBuilder) buildTargets(names []string) error {
	// Preserve declaration order for selectors, then first-reference order for
	// direct node and exact-one template targets. Later plugin targets append.
	ordered := make([]string, 0, len(names))
	used := make(map[string]bool, len(names))
	for _, name := range names {
		used[name] = true
	}
	for _, group := range b.compiler.SelectorGroups() {
		if used[group.Name] {
			ordered = append(ordered, group.Name)
		}
	}
	ordered = append(ordered, names...)
	for _, name := range ordered {
		if _, exists := b.nameToID[name]; exists || isReservedRoutingTarget(name) {
			continue
		}
		target, err := b.compiler.ResolveRoutingTarget(name)
		if err != nil {
			return fmt.Errorf("resolve routing target %q: %w", name, err)
		}
		if err := b.materializeTarget(target); err != nil {
			return err
		}
	}
	return nil
}

func (b *outboundBuilder) buildRuleTargets(batches ...[]*config_parser.RoutingRule) error {
	var names []string
	for _, rules := range batches {
		for _, rule := range rules {
			if rule == nil {
				return fmt.Errorf("nil plugin routing rule")
			}
			names = append(names, rule.Outbound.Name)
		}
	}
	return b.buildTargets(names)
}

func configureOutboundChecks(outbounds []*outbound.DialerGroup, groups []config.Group, critical []bool) {
	overrides := make(map[string]bool)
	for _, group := range groups {
		if group.CheckAsync || group.Present["check_async"] {
			overrides[group.Name] = group.CheckAsync
		}
	}
	for i, group := range outbounds {
		group.CheckAsync = group.ChecksConnectivity() && !critical[i]
		if value, exists := overrides[group.Name]; exists {
			group.CheckAsync = value
		}
	}
}

func (b *outboundBuilder) materializeTarget(target *outbound.ResolvedTarget) error {
	var name string
	var paths []*outbound.PathSpec
	if node := target.Node; node != nil {
		name = node.Property.Name
		paths = []*outbound.PathSpec{outbound.NodePath(node)}
	}
	finalOption := b.option
	selectionPolicy := dialer.DialerSelectionPolicy{}
	if group := target.Group; group != nil {
		name = group.Name
		var err error
		paths, err = b.compiler.ExpandRoutable(group)
		if err != nil {
			return fmt.Errorf("failed to expand group %v: %w", name, err)
		}
		if groupOption := parseGroupOverrideOption(*group, *b.global); groupOption != nil {
			finalOption = groupOption
			log.WithField("group", name).Debug("Using group connectivity check settings")
		}
		if group.Policy != nil {
			policy, err := dialer.NewDialerSelectionPolicyFromGroupParam(group)
			if err != nil {
				return fmt.Errorf("failed to create group %v: %w", name, err)
			}
			selectionPolicy = *policy
		}
	}
	if len(b.outbounds) >= int(consts.OutboundUserDefinedMax)+1 {
		return fmt.Errorf("too many outbounds: cannot materialize target %q", name)
	}
	logicalPaths := len(paths)
	var err error
	paths, err = outbound.ExpandIPVariants(b.ctx, paths, finalOption)
	if err != nil {
		return fmt.Errorf("expand target %q address families: %w", name, err)
	}
	if logicalPaths == 1 && len(paths) > 1 && selectionPolicy.Policy == "" {
		selectionPolicy = dialer.DialerSelectionPolicy{
			Policy:   consts.DialerSelectionPolicy_MinMovingAverageLatencies,
			EmaAlpha: dialer.DefaultEmaAlpha, TimeoutPenalty: dialer.DefaultTimeoutPenalty,
		}
	}
	if len(paths) > outbound.MaxMaterializedPaths-b.materializedPathCount {
		return fmt.Errorf("materializing target %q would exceed the global proxy path limit %d", name, outbound.MaxMaterializedPaths)
	}

	dialers := make([]*dialer.Dialer, 0, len(paths))
	annotations := make([]*dialer.Annotation, 0, len(paths))
	pathOccurrences := make(map[string]int, len(paths))
	for _, path := range paths {
		d, buildErr := b.set.BuildPath(path, finalOption, candidateStatsScope(name, path, pathOccurrences))
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
	id := uint8(len(b.outbounds))
	group := outbound.NewDialerGroup(finalOption, name, outbound.GroupKindSelector, dialers, annotations, selectionPolicy,
		b.core.outboundAliveChangeCallback(id, name, b.global.NoConnectivityTrySniff, b.noConnectivityOutbound)).SetTargetMetadata(target.Kind)
	closeOnReselect := target.Group != nil && target.Group.ReselectBehavior == "close"
	group.SetConnectionPolicy(closeOnReselect, b.global.RouteChangeBehavior == "close")
	b.outbounds = append(b.outbounds, group)
	b.nameToID[name] = id
	b.materializedPathCount += len(dialers)
	return nil
}

// The routing config has already passed Validate, including use cycles and
// missing policies. Reachability is structural, independent of traffic or health.
func collectActiveRoutingTargetNames(routingConfig *config.Routing) []string {
	selected := map[string]bool{routingConfig.Default: true}
	for _, binding := range routingConfig.Interfaces {
		selected[binding.Policy] = true
	}
	sets := make(map[string][]config.RoutingStatement, len(routingConfig.RuleSets))
	for _, set := range routingConfig.RuleSets {
		sets[set.Name] = set.Statements
	}
	visited := make(map[string]bool)
	var targets []string
	var visit func([]config.RoutingStatement)
	visit = func(statements []config.RoutingStatement) {
		for _, statement := range statements {
			switch statement.Kind {
			case config.RoutingStatementRule:
				targets = append(targets, statement.Rule.Outbound.Name)
			case config.RoutingStatementUse:
				if !visited[statement.Use] {
					visited[statement.Use] = true
					visit(sets[statement.Use])
				}
			}
		}
	}
	for _, policy := range routingConfig.Policies {
		if selected[policy.Name] {
			visit(policy.Statements)
			targets = append(targets, policy.Fallback.Name)
		}
	}
	return targets
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
