/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/mohae/deepcopy"
)

type preparedRules struct {
	apiBypass    []bpfIpPort
	destinations routing.DestinationRewrites
	geoDirs      []string
	routing      *config.Routing
	bypass       []*config_parser.RoutingRule
	earlyRoutes  []*config_parser.RoutingRule
	lateRoutes   []*config_parser.RoutingRule
	capture      *routingCapture
	dnsRequest   []*config_parser.RoutingRule
	dnsResponse  []*config_parser.RoutingRule
}

func (p *preparedRules) enableFlowRules(ctx context.Context, rules config.Rules, dirs []string) error {
	plan, err := rules.Plan()
	if err != nil {
		return err
	}
	p.destinations, err = prepareDestinationRules(ctx, plan.Destinations, dirs)
	if err != nil {
		return err
	}
	if len(plan.Controls) != 0 {
		reader := routing.NewDatReaderOptimizer(ctx, assets.NewLocationFinder(dirs))
		for i := range plan.Controls {
			rule := &plan.Controls[i]
			normalized, err := routing.ApplyRulesOptimizers([]*config_parser.RoutingRule{{AndFunctions: rule.Filter}}, &routing.AliasOptimizer{}, reader, &routing.DeduplicateParamsOptimizer{})
			if err != nil {
				return fmt.Errorf("rules control %d: %w", i+1, err)
			}
			rule.Filter = normalized[0].AndFunctions
		}
		if p.capture == nil {
			p.capture = &routingCapture{}
		}
		p.capture.controls = plan.Controls
	}
	return nil
}

func prepareDestinationRules(ctx context.Context, rules routing.DestinationRewrites, dirs []string) (routing.DestinationRewrites, error) {
	reader := routing.NewDatReaderOptimizer(ctx, assets.NewLocationFinder(dirs))
	result := make(routing.DestinationRewrites, 0, len(rules))
	for i, rule := range rules {
		if len(rule.To) == 0 {
			return nil, fmt.Errorf("destination rule %d: missing target", i+1)
		}
		for _, ip := range rule.To {
			if !ip.IsValid() || ip.Zone() != "" {
				return nil, fmt.Errorf("destination rule %d: invalid target IP", i+1)
			}
		}
		filter := deepcopy.Copy(rule.Filter).([]*config_parser.Function)
		if len(filter) == 0 {
			return nil, fmt.Errorf("destination rule %d: missing predicate", i+1)
		}
		// Only predicate normalization applies here; rules with equal actions
		// must retain their original order, without merging equal actions.
		normalized, err := routing.ApplyRulesOptimizers([]*config_parser.RoutingRule{{AndFunctions: filter, Outbound: config_parser.Function{Name: "direct"}}}, &routing.AliasOptimizer{}, reader, &routing.DeduplicateParamsOptimizer{})
		if err != nil {
			return nil, fmt.Errorf("destination rule %d: %w", i+1, err)
		}
		rule.Filter = normalized[0].AndFunctions
		result = append(result, rule)
	}
	return result, nil
}

func prepareRoutingRules(ctx context.Context, routingConfig *config.Routing, dnsConfig *config.Dns, externGeoDataDirs []string) (preparedRules, error) {
	var prepared preparedRules
	prepared.geoDirs = append([]string(nil), externGeoDataDirs...)
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	datReader := routing.NewDatReaderOptimizer(ctx, locationFinder)
	if err := ctx.Err(); err != nil {
		return prepared, err
	}
	var err error
	prepared.routing, err = prepareRoutingConfig(routingConfig, datReader)
	if err != nil {
		return prepared, fmt.Errorf("prepare routing rules: %w", err)
	}
	prepared.dnsRequest, err = routing.ApplyRulesOptimizers(dnsConfig.Routing.Request.Rules,
		&routing.AliasOptimizer{}, datReader,
		&routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		return prepared, fmt.Errorf("prepare DNS request rules: %w", err)
	}
	prepared.dnsResponse, err = routing.ApplyRulesOptimizers(dnsConfig.Routing.Response.Rules,
		datReader, &routing.MergeAndSortRulesOptimizer{}, &routing.DeduplicateParamsOptimizer{})
	if err != nil {
		return prepared, fmt.Errorf("prepare DNS response rules: %w", err)
	}
	return prepared, nil
}

func (p *preparedRules) enableMITMPlan(plan plugin.Plan) {
	p.earlyRoutes = plan.EarlyRoutes
	p.lateRoutes = plan.Routes
	if len(plan.Scopes) != 0 {
		if p.capture == nil {
			p.capture = &routingCapture{}
		}
		for _, scope := range plan.Scopes {
			if scope.PreserveRoute {
				p.capture.http = append(p.capture.http, scope.Scope)
			} else {
				p.capture.requestRouting = append(p.capture.requestRouting, scope.Scope)
			}
		}
	}
}
