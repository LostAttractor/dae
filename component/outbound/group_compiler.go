/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"slices"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	MaxProxyPathDepth    = 16
	MaxExpandedPaths     = 4096
	MaxMaterializedPaths = 16384
)

type TargetKind string

const (
	TargetKindGroup   TargetKind = "group"
	TargetKindNode    TargetKind = "node"
	TargetKindBuiltin TargetKind = "builtin"
)

func (k TargetKind) String() string { return string(k) }

type ResolvedTarget struct {
	Kind  TargetKind
	Group *config.Group
	Node  *NodeInfo
}

type compiledStage struct {
	nodes      []*NodeInfo
	group      *groupDefinition
	annotation *dialer.Annotation
}

type groupDefinition struct {
	config       *config.Group
	paths        [][]*compiledStage
	dependencies []*groupDefinition
	template     []*PathSpec
	templateDone bool
}

type GroupCompiler struct {
	set     *DialerSet
	ordered []*groupDefinition
	byName  map[string]*groupDefinition
}

func isReservedTargetName(name string) bool {
	switch name {
	case consts.OutboundDirect.String(), consts.OutboundBlock.String(),
		consts.OutboundMustRules.String(), consts.OutboundControlPlaneRouting.String():
		return true
	default:
		return false
	}
}

func NewGroupCompiler(set *DialerSet, groups []config.Group, routingTargets []string) (*GroupCompiler, error) {
	compiler := &GroupCompiler{
		set:    set,
		byName: make(map[string]*groupDefinition, len(groups)),
	}
	routedNames := make(map[string]struct{}, len(routingTargets))
	for _, name := range routingTargets {
		routedNames[name] = struct{}{}
	}
	for i := range groups {
		group := &groups[i]
		if isReservedTargetName(group.Name) {
			return nil, fmt.Errorf("group name %q is reserved", group.Name)
		}
		if _, ok := compiler.byName[group.Name]; ok {
			return nil, fmt.Errorf("duplicated group name: %q", group.Name)
		}
		definition := &groupDefinition{config: group}
		compiler.ordered = append(compiler.ordered, definition)
		compiler.byName[group.Name] = definition
		if group.Policy != nil {
			if _, err := dialer.NewDialerSelectionPolicyFromGroupParam(group); err != nil {
				return nil, fmt.Errorf("group %q: %w", group.Name, err)
			}
		}
	}

	for _, definition := range compiler.ordered {
		paths := definition.config.Paths
		if len(paths) == 0 {
			// An empty group retains the traditional meaning of selecting all nodes.
			definition.paths = append(definition.paths, []*compiledStage{{
				nodes:      compiler.set.nodeInfos,
				annotation: &dialer.Annotation{},
			}})
			continue
		}
		for pathIndex, path := range paths {
			if path == nil || len(path.Stages) == 0 {
				return nil, fmt.Errorf("group %q path %d: path has no stages", definition.config.Name, pathIndex+1)
			}
			compiled := make([]*compiledStage, 0, len(path.Stages))
			for stageIndex, stage := range path.Stages {
				compiledStage, err := compiler.compileStage(definition, stage)
				if err != nil {
					return nil, fmt.Errorf("group %q path %d stage %d: %w", definition.config.Name, pathIndex+1, stageIndex+1, err)
				}
				compiled = append(compiled, compiledStage)
			}
			definition.paths = append(definition.paths, compiled)
		}
	}

	for _, definition := range compiler.ordered {
		if definition.config.Policy != nil {
			continue
		}
		group := definition.config
		if group.CheckTolerance != 0 || group.Present["check_tolerance"] {
			return nil, fmt.Errorf("group %q: check_tolerance requires a selection policy", group.Name)
		}
		hasRuntimeOption := group.UdpCheckDns != nil || group.CheckInterval != 0 || group.CheckIntervalMax != 0 ||
			group.Present["udp_check_dns"] || group.Present["check_interval"] || group.Present["check_interval_max"]
		_, routed := routedNames[group.Name]
		if !routed && hasRuntimeOption {
			return nil, fmt.Errorf("group %q: connectivity-check options require a routing target or selection policy", group.Name)
		}
	}

	if err := compiler.validateCycles(); err != nil {
		return nil, err
	}
	return compiler, nil
}

func (c *GroupCompiler) compileStage(owner *groupDefinition, stage *config_parser.Param) (*compiledStage, error) {
	if stage == nil {
		return nil, fmt.Errorf("nil proxy stage")
	}
	annotation, err := dialer.NewAnnotation(stage.Annotation)
	if err != nil {
		return nil, fmt.Errorf("apply stage annotation: %w", err)
	}
	if stage.Key == "filter" {
		nodes, err := c.set.Filter(stage.AndFunctions)
		if err != nil {
			return nil, err
		}
		return &compiledStage{nodes: nodes, annotation: annotation}, nil
	}
	if stage.Key != "" || len(stage.AndFunctions) != 1 {
		return nil, fmt.Errorf("path reference must be node(name) or group(name)")
	}
	ref := stage.AndFunctions[0]
	if ref.Not || ref.Quoted || len(ref.Params) != 1 || ref.Params[0].Key != "" || strings.TrimSpace(ref.Params[0].Val) == "" {
		return nil, fmt.Errorf("path reference must be node(name) or group(name)")
	}
	name := ref.Params[0].Val
	switch ref.Name {
	case "node":
		nodes := c.set.NodesNamed(name)
		switch len(nodes) {
		case 0:
			return nil, fmt.Errorf("node(%q): node not found", name)
		case 1:
			return &compiledStage{nodes: nodes, annotation: annotation}, nil
		default:
			return nil, fmt.Errorf("node(%q): node is ambiguous (%d matching definitions)", name, len(nodes))
		}
	case "group":
		group := c.byName[name]
		if group == nil {
			return nil, fmt.Errorf("group(%q): group not found", name)
		}
		if group.config.Policy != nil {
			return nil, fmt.Errorf("group(%q): a selector group cannot be used as a path stage", name)
		}
		owner.dependencies = append(owner.dependencies, group)
		return &compiledStage{group: group, annotation: annotation}, nil
	default:
		return nil, fmt.Errorf("path reference must be node(name) or group(name)")
	}
}

func (c *GroupCompiler) ResolveRoutingTarget(name string) (*ResolvedTarget, error) {
	group := c.byName[name]
	nodes := c.set.NodesNamed(name)
	candidates := len(nodes)
	if group != nil {
		candidates++
	}
	switch {
	case candidates == 0:
		return nil, fmt.Errorf("target not found")
	case candidates > 1:
		return nil, fmt.Errorf("target is ambiguous (%d matching definitions)", candidates)
	case group != nil:
		return &ResolvedTarget{Kind: TargetKindGroup, Group: group.config}, nil
	default:
		return &ResolvedTarget{Kind: TargetKindNode, Node: nodes[0]}, nil
	}
}

func (c *GroupCompiler) SelectorGroups() []*config.Group {
	groups := make([]*config.Group, 0, len(c.ordered))
	for _, definition := range c.ordered {
		if definition.config.Policy != nil {
			groups = append(groups, definition.config)
		}
	}
	return groups
}

func (c *GroupCompiler) validateCycles() error {
	state := make(map[*groupDefinition]uint8, len(c.ordered))
	var stack []*groupDefinition
	var visit func(*groupDefinition) error
	visit = func(group *groupDefinition) error {
		switch state[group] {
		case 1:
			start := slices.Index(stack, group)
			cycle := append(slices.Clone(stack[start:]), group)
			names := make([]string, 0, len(cycle))
			for _, item := range cycle {
				names = append(names, item.config.Name)
			}
			return fmt.Errorf("group path cycle: %s", strings.Join(names, " -> "))
		case 2:
			return nil
		}
		state[group] = 1
		stack = append(stack, group)
		for _, dependency := range group.dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		stack = stack[:len(stack)-1]
		state[group] = 2
		return nil
	}
	for _, group := range c.ordered {
		if err := visit(group); err != nil {
			return err
		}
	}
	return nil
}

func (c *GroupCompiler) expandStage(stage *compiledStage) ([]*PathSpec, error) {
	if stage.group != nil {
		fragments, err := c.expandTemplate(stage.group)
		if err != nil {
			return nil, err
		}
		paths := make([]*PathSpec, 0, len(fragments))
		for _, fragment := range fragments {
			merged, err := dialer.MergeAnnotations(fragment.Annotation, stage.annotation)
			if err != nil {
				return nil, fmt.Errorf("merge group stage annotation: %w", err)
			}
			paths = append(paths, &PathSpec{
				Nodes:      fragment.Nodes,
				Annotation: merged,
			})
		}
		return paths, nil
	}
	paths := make([]*PathSpec, 0, len(stage.nodes))
	for _, node := range stage.nodes {
		paths = append(paths, &PathSpec{Nodes: []*NodeInfo{node}, Annotation: stage.annotation})
	}
	return paths, nil
}

func (c *GroupCompiler) expand(group *groupDefinition) ([]*PathSpec, error) {
	var paths []*PathSpec
	for pathIndex, path := range group.paths {
		current := []*PathSpec{{Annotation: &dialer.Annotation{}}}
		for stageIndex, stage := range path {
			fragments, err := c.expandStage(stage)
			if err != nil {
				return nil, fmt.Errorf("group %q path %d stage %d: %w", group.config.Name, pathIndex+1, stageIndex+1, err)
			}
			if len(fragments) != 0 && len(current) > MaxExpandedPaths/len(fragments) {
				return nil, fmt.Errorf("group %q: proxy path expansion exceeds limit %d", group.config.Name, MaxExpandedPaths)
			}
			next := make([]*PathSpec, 0, len(current)*len(fragments))
			// Later stages are the major dimension, preserving the historical
			// terminal-major ordering used by fixed(n).
			for _, fragment := range fragments {
				for _, prefix := range current {
					nodes := make([]*NodeInfo, 0, len(prefix.Nodes)+len(fragment.Nodes))
					nodes = append(nodes, prefix.Nodes...)
					nodes = append(nodes, fragment.Nodes...)
					if len(nodes) > MaxProxyPathDepth {
						return nil, fmt.Errorf("group %q: proxy path depth %d exceeds limit %d", group.config.Name, len(nodes), MaxProxyPathDepth)
					}
					annotation, err := dialer.MergeAnnotations(prefix.Annotation, fragment.Annotation)
					if err != nil {
						return nil, fmt.Errorf("group %q: merge path annotation: %w", group.config.Name, err)
					}
					next = append(next, &PathSpec{Nodes: nodes, Annotation: annotation})
				}
			}
			current = next
		}
		if len(current) > MaxExpandedPaths-len(paths) {
			return nil, fmt.Errorf("group %q: proxy path expansion exceeds limit %d", group.config.Name, MaxExpandedPaths)
		}
		paths = append(paths, current...)
	}
	return paths, nil
}

func (c *GroupCompiler) expandTemplate(group *groupDefinition) ([]*PathSpec, error) {
	if group.templateDone {
		return group.template, nil
	}
	paths, err := c.expand(group)
	if err != nil {
		return nil, err
	}
	group.template = paths
	group.templateDone = true
	return paths, nil
}

func (c *GroupCompiler) ExpandRoutable(group *config.Group) ([]*PathSpec, error) {
	definition := c.byName[group.Name]
	if definition == nil {
		return nil, fmt.Errorf("group %q not found", group.Name)
	}
	paths, err := c.expand(definition)
	if err != nil {
		return nil, err
	}
	if definition.config.Policy == nil && len(paths) > 1 {
		return nil, fmt.Errorf("group %q has no policy and expands to %d paths; exactly one is required for a routing target", group.Name, len(paths))
	}
	return paths, nil
}

func NodePath(node *NodeInfo) *PathSpec {
	return &PathSpec{Nodes: []*NodeInfo{node}, Annotation: &dialer.Annotation{}}
}
