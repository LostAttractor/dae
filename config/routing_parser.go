/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	maxRoutingBlocks            = 1024
	maxRoutingStatements        = 65536
	maxRoutingReferenceDepth    = 64
	maxRoutingInterfaceBindings = 256
)

// ValidateRoutingInterfaceName accepts literal Linux device names. Characters
// used by glob syntax are ordinary characters here; profiles never expand patterns.
func ValidateRoutingInterfaceName(name string) error {
	if name == "" || len(name) > 15 || name == "." || name == ".." || strings.ContainsAny(name, "/:\x00 \t\n\r\v\f") {
		return fmt.Errorf("invalid exact routing interface name %q", name)
	}
	return nil
}

func parseRouting(to *Routing, section *config_parser.Section) error {
	var inline config_parser.Section
	selectedDefault := false
	for _, item := range section.Items {
		if child, ok := item.Value.(*config_parser.Section); ok {
			switch child.Name {
			case "rule_set", "policy":
				for _, declaration := range child.Items {
					block, ok := declaration.Value.(*config_parser.Section)
					if !ok {
						return fmt.Errorf("%s only accepts named sections", child.Name)
					}
					statements, fallback, err := parseRoutingBlock(block, child.Name == "policy")
					if err != nil {
						return fmt.Errorf("%s %q: %w", child.Name, block.Name, err)
					}
					if child.Name == "rule_set" {
						to.RuleSets = append(to.RuleSets, RoutingRuleSet{Name: block.Name, Statements: statements})
					} else {
						to.Policies = append(to.Policies, RoutingPolicy{Name: block.Name, Statements: statements, Fallback: fallback})
					}
				}
			case "interface":
				for _, binding := range child.Items {
					param, ok := binding.Value.(*config_parser.Param)
					if !ok {
						return fmt.Errorf("routing interface expects interface_name: policy_name")
					}
					name, err := routingReference(param)
					if err != nil {
						return err
					}
					to.Interfaces = append(to.Interfaces, RoutingInterface{Name: param.Key, Policy: name})
				}
			default:
				return fmt.Errorf("unexpected routing section %q", child.Name)
			}
		} else if param, ok := item.Value.(*config_parser.Param); ok && param.Key == "default" {
			if selectedDefault {
				return fmt.Errorf("duplicate routing default")
			}
			name, err := routingReference(param)
			if err != nil {
				return err
			}
			to.Default, selectedDefault = name, true
		} else {
			inline.Items = append(inline.Items, item)
		}
	}
	if selectedDefault {
		if len(inline.Items) != 0 {
			return fmt.Errorf("routing default cannot be combined with inline rules, use or fallback")
		}
	} else {
		statements, fallback, err := parseRoutingBlock(&inline, true)
		if err != nil {
			return fmt.Errorf("routing inline policy: %w", err)
		}
		// Normalize both forms to policies; the anonymous default is first.
		to.Policies = append([]RoutingPolicy{{Statements: statements, Fallback: fallback}}, to.Policies...)
	}
	return to.Validate()
}

func routingReference(param *config_parser.Param) (string, error) {
	if len(param.Annotation) != 0 || param.AndFunctions != nil || len(param.ValueList) != 1 || param.ValueList[0] == "" {
		return "", fmt.Errorf("%q requires exactly one policy name without annotations", param.Key)
	}
	return param.ValueList[0], nil
}

func parseRoutingBlock(section *config_parser.Section, policy bool) (statements []RoutingStatement, fallback *config_parser.Function, err error) {
	for _, item := range section.Items {
		switch value := item.Value.(type) {
		case *config_parser.RoutingRule:
			statements = append(statements, RoutingStatement{Kind: RoutingStatementRule, Rule: value})
		case *config_parser.Param:
			if len(value.Annotation) > 0 {
				return nil, nil, fmt.Errorf("field %q does not support annotations", value.Key)
			}
			switch value.Key {
			case "use":
				if value.AndFunctions != nil || len(value.ValueList) == 0 {
					return nil, nil, fmt.Errorf("use requires one or more rule_set names")
				}
				for _, name := range value.ValueList {
					if name == "" {
						return nil, nil, fmt.Errorf("use requires nonempty rule_set names")
					}
					statements = append(statements, RoutingStatement{Kind: RoutingStatementUse, Use: name})
				}
			case "fallback":
				if !policy {
					return nil, nil, fmt.Errorf("rule_set cannot contain fallback")
				}
				if fallback != nil {
					return nil, nil, fmt.Errorf("duplicate policy fallback")
				}
				fallback, err = parseRoutingFallback(value)
				if err != nil {
					return nil, nil, err
				}
			default:
				return nil, nil, fmt.Errorf("unexpected key %q", value.Key)
			}
		default:
			return nil, nil, fmt.Errorf("unsupported routing item: %v", item.String(false, false))
		}
	}
	if policy && fallback == nil {
		return nil, nil, fmt.Errorf("policy requires exactly one fallback")
	}
	return statements, fallback, nil
}

func parseRoutingFallback(param *config_parser.Param) (*config_parser.Function, error) {
	if param.AndFunctions == nil && len(param.ValueList) != 1 {
		return nil, fmt.Errorf("fallback requires exactly one outbound")
	}
	var raw FunctionOrString
	switch {
	case param.AndFunctions != nil:
		raw = param.AndFunctions
	case param.Quoted:
		raw = QuotedString(param.Val)
	default:
		raw = param.Val
	}
	fallback, err := ParseFunctionOrString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid fallback: %w", err)
	}
	return fallback, nil
}

func (routing *Routing) Validate() error {
	if routing == nil {
		return fmt.Errorf("routing requires a default policy")
	}
	if len(routing.RuleSets)+len(routing.Policies) > maxRoutingBlocks {
		return fmt.Errorf("routing exceeds %d blocks", maxRoutingBlocks)
	}
	validateName := func(name string) error {
		if !isBareRoutingValue(name) || !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_", rune(name[0])) {
			return fmt.Errorf("routing block name %q cannot be represented as a section name", name)
		}
		return nil
	}
	validateFunction := func(f *config_parser.Function) error {
		if f == nil {
			return fmt.Errorf("routing function must not be nil")
		}
		for _, p := range f.Params {
			if p == nil {
				return fmt.Errorf("routing parameter must not be nil")
			}
			if p.AndFunctions != nil || len(p.Annotation) != 0 {
				return fmt.Errorf("routing parameters cannot contain functions or annotations")
			}
		}
		return nil
	}
	statementCount := 0
	validateBlock := func(name string, statements []RoutingStatement) error {
		statementCount += len(statements)
		if statementCount > maxRoutingStatements {
			return fmt.Errorf("routing exceeds %d statements", maxRoutingStatements)
		}
		for _, statement := range statements {
			switch statement.Kind {
			case RoutingStatementRule:
				if statement.Rule == nil || len(statement.Rule.AndFunctions) == 0 || statement.Use != "" {
					return fmt.Errorf("routing block %q contains an invalid rule", name)
				}
				if err := validateFunction(&statement.Rule.Outbound); err != nil {
					return fmt.Errorf("routing block %q: %w", name, err)
				}
				for _, f := range statement.Rule.AndFunctions {
					if err := validateFunction(f); err != nil {
						return fmt.Errorf("routing block %q: %w", name, err)
					}
				}
			case RoutingStatementUse:
				if statement.Use == "" || statement.Rule != nil {
					return fmt.Errorf("routing block %q contains an invalid use", name)
				}
			default:
				return fmt.Errorf("routing block %q contains an unknown statement", name)
			}
		}
		return nil
	}
	sets := make(map[string]RoutingRuleSet, len(routing.RuleSets))
	for _, set := range routing.RuleSets {
		if err := validateName(set.Name); err != nil {
			return err
		}
		if err := validateBlock(set.Name, set.Statements); err != nil {
			return err
		}
		if _, exists := sets[set.Name]; exists {
			return fmt.Errorf("duplicate routing rule_set %q", set.Name)
		}
		sets[set.Name] = set
	}
	policies := make(map[string]struct{}, len(routing.Policies))
	for _, policy := range routing.Policies {
		if policy.Name != "" {
			if err := validateName(policy.Name); err != nil {
				return err
			}
		} else if routing.Default != "" {
			return fmt.Errorf("routing default cannot be combined with an inline policy")
		}
		if _, exists := policies[policy.Name]; exists {
			return fmt.Errorf("duplicate routing policy %q", policy.Name)
		}
		policies[policy.Name] = struct{}{}
		if policy.Fallback == nil {
			return fmt.Errorf("routing policy %q requires exactly one fallback", policy.Name)
		}
		if err := validateFunction(policy.Fallback); err != nil {
			return fmt.Errorf("routing policy %q fallback: %w", policy.Name, err)
		}
		if err := validateBlock(policy.Name, policy.Statements); err != nil {
			return err
		}
	}
	if _, exists := policies[routing.Default]; !exists {
		return fmt.Errorf("routing default selects undefined policy %q", routing.Default)
	}
	if len(routing.Interfaces) > maxRoutingInterfaceBindings {
		return fmt.Errorf("routing exceeds %d interface bindings", maxRoutingInterfaceBindings)
	}
	interfaces := make(map[string]struct{}, len(routing.Interfaces))
	for _, binding := range routing.Interfaces {
		if err := ValidateRoutingInterfaceName(binding.Name); err != nil {
			return err
		}
		if _, exists := interfaces[binding.Name]; exists {
			return fmt.Errorf("duplicate routing interface binding %q", binding.Name)
		}
		interfaces[binding.Name] = struct{}{}
		if _, exists := policies[binding.Policy]; !exists || binding.Policy == "" {
			return fmt.Errorf("routing interface %q selects undefined policy %q", binding.Name, binding.Policy)
		}
	}

	// A visiting marker detects cycles; memoized depths also catch long chains
	// whose children were resolved earlier in declaration order.
	depths := make(map[string]int, len(sets))
	var stack []string
	var resolve func(string, []RoutingStatement) (int, error)
	resolve = func(name string, statements []RoutingStatement) (int, error) {
		depth := 1
		for _, statement := range statements {
			if statement.Kind != RoutingStatementUse {
				continue
			}
			set, exists := sets[statement.Use]
			if !exists {
				return 0, fmt.Errorf("routing block %q uses undefined rule_set %q", name, statement.Use)
			}
			childDepth, resolved := depths[set.Name]
			if resolved && childDepth == 0 {
				return 0, fmt.Errorf("routing rule_set cycle: %s -> %s", strings.Join(stack, " -> "), set.Name)
			}
			if !resolved {
				if len(stack) >= maxRoutingReferenceDepth {
					return 0, fmt.Errorf("routing rule_set %q exceeds reference depth %d", set.Name, maxRoutingReferenceDepth)
				}
				depths[set.Name] = 0
				stack = append(stack, set.Name)
				var err error
				childDepth, err = resolve(set.Name, set.Statements)
				stack = stack[:len(stack)-1]
				if err != nil {
					return 0, err
				}
				depths[set.Name] = childDepth
			}
			depth = max(depth, childDepth+1)
			if depth > maxRoutingReferenceDepth {
				return 0, fmt.Errorf("routing block %q exceeds reference depth %d", name, maxRoutingReferenceDepth)
			}
		}
		return depth, nil
	}
	for _, set := range routing.RuleSets {
		if _, err := resolve(set.Name, set.Statements); err != nil {
			return err
		}
	}
	for _, policy := range routing.Policies {
		if _, err := resolve(policy.Name, policy.Statements); err != nil {
			return err
		}
	}
	return nil
}
