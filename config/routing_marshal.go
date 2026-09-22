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

func (m *Marshaller) marshalRouting(routing Routing, depth int) error {
	if err := routing.Validate(); err != nil {
		return err
	}
	if len(routing.RuleSets) > 0 {
		m.writeLine(depth, "rule_set {")
		for _, set := range routing.RuleSets {
			m.writeLine(depth+1, set.Name+" {")
			if err := m.marshalRoutingStatements(set.Statements, depth+2); err != nil {
				return err
			}
			m.writeLine(depth+1, "}")
		}
		m.writeLine(depth, "}")
	}
	var named []RoutingPolicy
	for _, policy := range routing.Policies {
		if policy.Name == "" {
			if err := m.marshalRoutingPolicy(policy, depth); err != nil {
				return err
			}
		} else {
			named = append(named, policy)
		}
	}
	if len(named) > 0 {
		m.writeLine(depth, "policy {")
		for _, policy := range named {
			m.writeLine(depth+1, policy.Name+" {")
			if err := m.marshalRoutingPolicy(policy, depth+2); err != nil {
				return err
			}
			m.writeLine(depth+1, "}")
		}
		m.writeLine(depth, "}")
	}
	if routing.Default != "" {
		m.writeLine(depth, "default:"+routing.Default)
	}
	if len(routing.Interfaces) > 0 {
		m.writeLine(depth, "interface {")
		for _, binding := range routing.Interfaces {
			m.writeLine(depth+1, quoteRoutingValue(binding.Name)+":"+binding.Policy)
		}
		m.writeLine(depth, "}")
	}
	return nil
}

func (m *Marshaller) marshalRoutingPolicy(policy RoutingPolicy, depth int) error {
	if err := m.marshalRoutingStatements(policy.Statements, depth); err != nil {
		return err
	}
	fallback, err := marshalRoutingOutbound(policy.Fallback)
	if err != nil {
		return err
	}
	m.writeLine(depth, "fallback:"+fallback)
	return nil
}

func (m *Marshaller) marshalRoutingStatements(statements []RoutingStatement, depth int) error {
	for _, statement := range statements {
		switch statement.Kind {
		case RoutingStatementRule:
			line, err := marshalRoutingRule(statement.Rule)
			if err != nil {
				return err
			}
			m.writeLine(depth, line)
		case RoutingStatementUse:
			if len(statement.Condition) == 0 {
				m.writeLine(depth, "use:"+statement.Use)
				continue
			}
			// use arguments are fragment names, including the literal name must.
			rule := config_parser.RoutingRule{
				AndFunctions: statement.Condition,
				Outbound:     config_parser.Function{Name: "use", Params: []*config_parser.Param{{Val: statement.Use}}},
			}
			m.writeLine(depth, rule.String(false, true, true))
		}
	}
	return nil
}

func quoteRoutingValue(value string) string {
	if isBareRoutingValue(value) {
		return value
	}
	return config_parser.QuoteLiteral(value)
}

func isBareRoutingValue(value string) bool {
	return !strings.HasPrefix(value, "/*") && config_parser.IsBareLiteral(value)
}

func marshalRoutingParam(param *config_parser.Param) (string, error) {
	if param == nil {
		return "", fmt.Errorf("routing parameter must not be nil")
	}
	if param.AndFunctions != nil {
		return "", fmt.Errorf("nested functions are not valid routing parameters")
	}
	value := config_parser.QuoteLiteral(param.Val)
	if param.Key == "" {
		return value, nil
	}
	return param.Key + ":" + value, nil
}

func marshalRoutingOutbound(function *config_parser.Function) (string, error) {
	if function == nil {
		return "", fmt.Errorf("routing function must not be nil")
	}
	if !function.Not && !function.Quoted && len(function.Params) == 1 &&
		function.Params[0] != nil && function.Params[0].Key == "" &&
		function.Params[0].Val == "must" && function.Params[0].AndFunctions == nil {
		return quoteRoutingValue("must_" + function.Name), nil
	}
	if !function.Not && len(function.Params) == 0 {
		if function.Quoted {
			return config_parser.QuoteLiteral(function.Name), nil
		}
		return quoteRoutingValue(function.Name), nil
	}
	return marshalRoutingFunction(function)
}

func marshalRoutingFunction(function *config_parser.Function) (string, error) {
	if function == nil {
		return "", fmt.Errorf("routing function must not be nil")
	}
	var builder strings.Builder
	if function.Not {
		builder.WriteByte('!')
	}
	if function.Quoted || !isBareRoutingValue(function.Name) {
		builder.WriteString(config_parser.QuoteLiteral(function.Name))
	} else {
		builder.WriteString(function.Name)
	}
	builder.WriteByte('(')
	for i, param := range function.Params {
		if i > 0 {
			builder.WriteByte(',')
		}
		encoded, err := marshalRoutingParam(param)
		if err != nil {
			return "", err
		}
		builder.WriteString(encoded)
	}
	builder.WriteByte(')')
	return builder.String(), nil
}

func marshalRoutingRule(rule *config_parser.RoutingRule) (string, error) {
	if rule == nil {
		return "", fmt.Errorf("routing rule must not be nil")
	}
	functions := make([]string, 0, len(rule.AndFunctions))
	for _, function := range rule.AndFunctions {
		encoded, err := marshalRoutingFunction(function)
		if err != nil {
			return "", err
		}
		functions = append(functions, encoded)
	}
	outbound, err := marshalRoutingOutbound(&rule.Outbound)
	if err != nil {
		return "", err
	}
	return strings.Join(functions, "&&") + "->" + outbound, nil
}
