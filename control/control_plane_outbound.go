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

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	log "github.com/sirupsen/logrus"
)

// outboundBuilder exists only during preparation. Definitions are validated
// without constructing transports; only reachable targets receive runtime IDs.
type outboundBuilder struct {
	ctx                    context.Context
	core                   *controlPlaneCore
	materializer           *outbound.GroupMaterializer
	compiler               *outbound.GroupCompiler
	global                 *config.Global
	noConnectivityOutbound consts.OutboundIndex
	outbounds              []*outbound.DialerGroup
	nameToID               map[string]uint8
	validationOutbounds    map[string]uint8
	releases               []func() error
	borrowed               map[*outbound.DialerGroup]bool
}

func (b *outboundBuilder) close() (err error) {
	for _, release := range b.releases {
		err = errors.Join(err, release())
	}
	return err
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

	_direct := direct.NewDirectDialer(direct.Option{Mptcp: option.Mptcp, Mark: int(option.SoMarkFromDae)})
	direct := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: _direct}), option, &dialer.Property{Name: "direct"}, false, "")
	_block, blockProperty := D.NewBlockDialer(&option.ExtraOption, func() { /*Dialer Outbound*/ })
	block := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: _block}), option, &dialer.Property{Property: *blockProperty}, false, "")
	b := &outboundBuilder{
		ctx:  ctx,
		core: core, global: global, noConnectivityOutbound: noConnectivityOutbound,
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
			_ = b.close()
		}
	}()
	for _, group := range b.outbounds {
		b.releases = append(b.releases, group.Close)
	}
	var resources *outbound.Resources
	if core.bpf != nil && core.bpf.Runtime != nil {
		resources = &core.bpf.outboundResources
	} else {
		resources = &outbound.Resources{}
	}
	// Compile groups and all routing target references before assigning outbound
	// IDs. Policyless groups remain compile-time templates unless routing uses
	// them as an exact-one target.
	set, err := outbound.NewDialerSet(nodes)
	if err != nil {
		return nil, fmt.Errorf("build node descriptors: %w", err)
	}
	routingTargets := collectRoutingTargetNames(routingConfig)
	b.compiler, err = outbound.NewGroupCompiler(set, groups, routingTargets)
	if err != nil {
		return nil, fmt.Errorf("compile proxy groups: %w", err)
	}
	b.materializer = outbound.NewGroupMaterializer(b.compiler, resources, global)
	b.validationOutbounds = maps.Clone(b.nameToID)
	for _, name := range routingTargets {
		if outbound.IsReservedTargetName(name) {
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
		if _, exists := b.nameToID[name]; exists || outbound.IsReservedTargetName(name) {
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

// Startup policy belongs to the candidate; shared groups only own workers and
// readiness. Borrowing a group neither mutates the accepted plane nor skips a
// newly required barrier.
func configureOutboundChecks(outbounds []*outbound.DialerGroup, groups []config.Group, critical []bool) []bool {
	overrides := make(map[string]bool)
	for _, group := range groups {
		if group.CheckAsync || group.Present["check_async"] {
			overrides[group.Name] = group.CheckAsync
		}
	}
	checks := make([]bool, len(outbounds))
	for i, group := range outbounds {
		async := group.ChecksConnectivity() && !critical[i]
		if value, exists := overrides[group.Name]; exists {
			async = value
		}
		checks[i] = async
	}
	return checks
}

func (b *outboundBuilder) materializeTarget(target *outbound.ResolvedTarget) error {
	if len(b.outbounds) >= int(consts.OutboundUserDefinedMax)+1 {
		return fmt.Errorf("too many outbounds: cannot materialize target %q", target.Name())
	}
	materialized, err := b.materializer.MaterializeGroup(b.ctx, target)
	if err != nil {
		return err
	}
	group, release := materialized.Group, materialized.Release
	name := group.Name

	if materialized.Borrowed {
		if b.borrowed == nil {
			b.borrowed = make(map[*outbound.DialerGroup]bool)
		}
		b.borrowed[group] = true
	}
	id := uint8(len(b.outbounds))
	callback := b.core.outboundAliveChangeCallback(id, name, b.global.NoConnectivityTrySniff, b.noConnectivityOutbound)
	detach, err := group.ObserveConnectivity(func(available bool, network *common.NetworkType) error {
		err := callback(available, network)
		if errors.Is(err, context.Canceled) {
			return nil
		} // The group outlives retired projections.
		return err
	})
	if err != nil {
		return errors.Join(err, release())
	}
	b.releases = append(b.releases, func() error { detach(); return release() })
	b.outbounds = append(b.outbounds, group)
	b.nameToID[name] = id
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
				action := statement.Rule.Outbound
				if !action.Quoted && (action.Name == "must" || action.Name == "bump" || action.Name == "dnat") {
					continue
				}
				appendTarget(action.Name)
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

func (c *ControlPlane) reconcileStats() {
	nodes := make(map[string]stats.NodeIdentity)
	groups := make(map[string]struct{}, len(c.outbounds))
	var selections []stats.SelectionMetricsSource
	for _, group := range c.outbounds {
		if group.ChecksConnectivity() {
			groups[group.Name] = struct{}{}
			selections = append(selections, group)
		}
		for _, d := range group.Dialers {
			key := d.StatsKey()
			nodes[key] = stats.NodeIdentity{
				Subtag: d.Property.SubscriptionTag,
				Name:   d.Name,
			}
		}
	}
	stats.DefaultStore.Reconcile(nodes, groups, selections...)
}

// closeOutbounds detaches this generation's observers and releases its group
// references. Shared groups remain live until their final owner releases them.
func (c *planeOutbounds) closeOutbounds() (err error) {
	for _, release := range c.outboundReleases {
		err = errors.Join(err, release())
	}
	return err
}

// Transfer both successful and partial builds before any possible return. Plugin
// preparation can append targets after the initial connectivity checks.
func (c *planeOutbounds) adoptOutbounds(builder *outboundBuilder) {
	c.outbounds, c.outboundReleases, c.borrowedOutbounds = builder.outbounds, builder.releases, builder.borrowed
}
