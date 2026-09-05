// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxModuleRuleDepth      = 10
	maxModuleRuleClauses    = 128
	maxModuleRulePredicates = 512
)

var errUnsupportedModuleRule = errors.New("unsupported module rule")

// ModuleRule describes the bounded, domain-only subset of Surge [Rule]. Clauses
// are ORed; predicates within one clause are ANDed. This representation maps to
// native dae routing without changing its regex or shared-IP bitmap semantics.
type ModuleRule struct {
	Policy      string
	PreMatching bool
	clauses     [][]RuleDomain
}

type RuleDomain struct {
	Type, Value string
	Not         bool
}

func (r ModuleRule) RoutingClauses() [][]RuleDomain {
	clauses := make([][]RuleDomain, len(r.clauses))
	for i, clause := range r.clauses {
		clauses[i] = append([]RuleDomain(nil), clause...)
	}
	return clauses
}

// DomainParameter returns the corresponding dae domain() key and value.
func (p RuleDomain) DomainParameter() (key, value string) {
	switch p.Type {
	case "DOMAIN":
		return "full", p.Value
	case "DOMAIN-SUFFIX":
		return "suffix", p.Value
	case "DOMAIN-KEYWORD":
		return "keyword", p.Value
	case "DOMAIN-WILDCARD":
		pattern := regexp.QuoteMeta(p.Value)
		pattern = strings.ReplaceAll(strings.ReplaceAll(pattern, `\*`, ".*"), `\?`, ".")
		return "regex", "^" + pattern + "$"
	default:
		return "", ""
	}
}

func parseModuleRule(line string, warnings *[]string) (*ModuleRule, error) {
	line = trimModuleRuleComment(line)
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	fields, err := splitModuleRuleFields(line)
	if err != nil {
		return nil, err
	}
	if len(fields) < 3 {
		return nil, fmt.Errorf("Rule requires type, value, and policy")
	}
	rule := &ModuleRule{Policy: strings.ToUpper(fields[2])}
	if rule.Policy != "DIRECT" && rule.Policy != "REJECT" {
		*warnings = append(*warnings, fmt.Sprintf("Rule %q: policy %q is unsupported; entire rule is ignored", line, fields[2]))
		return nil, nil
	}
	var extendedMatching bool
	for _, flag := range fields[3:] {
		switch strings.ToLower(flag) {
		case "pre-matching":
			rule.PreMatching = true
		case "extended-matching":
			extendedMatching = true
		default:
			*warnings = append(*warnings, fmt.Sprintf("Rule %q: option %q is unsupported; entire rule is ignored", line, flag))
			return nil, nil
		}
	}
	if rule.PreMatching && rule.Policy != "REJECT" {
		return nil, fmt.Errorf("pre-matching requires a REJECT policy")
	}
	clauses, extended, err := parseModuleRuleExpression(fields[:2], 0, false)
	if err != nil {
		if errors.Is(err, errUnsupportedModuleRule) {
			*warnings = append(*warnings, fmt.Sprintf("Rule %q: %v; entire rule is ignored", line, err))
			return nil, nil
		}
		return nil, err
	}
	extendedMatching = extendedMatching || extended
	rule.clauses = clauses
	if rule.PreMatching {
		appendModuleWarning(warnings, "Rule pre-matching uses high-priority dae connection blocking; Surge DNS No Record, TCP RST, and adaptive rejection are not implemented")
	} else if rule.Policy == "REJECT" {
		appendModuleWarning(warnings, "Rule REJECT maps to dae block, without Surge DNS or adaptive TCP RST behavior")
	}
	if extendedMatching {
		appendModuleWarning(warnings, "Rule extended-matching uses dae DNS and verified connection SNI/HTTP Host recognition; differing URL/Host/SNI values are not independently matched per HTTP request")
	}
	if rule.Policy == "DIRECT" {
		appendModuleWarning(warnings, "Rule DIRECT has lower priority than explicit dae routing rules and does not reroute script-generated $httpClient requests, which retain the current outbound")
	}
	return rule, nil
}

// Parse directly into OR clauses of AND predicates. Negation is pushed down to
// the domains with De Morgan's laws, so no intermediate expression tree is needed.
func parseModuleRuleExpression(fields []string, depth int, negated bool) (clauses [][]RuleDomain, extended bool, err error) {
	if depth > maxModuleRuleDepth {
		return nil, false, fmt.Errorf("Rule logical nesting exceeds %d levels", maxModuleRuleDepth)
	}
	if len(fields) < 2 {
		return nil, false, fmt.Errorf("Rule subexpression requires type and value")
	}
	for _, flag := range fields[2:] {
		if !strings.EqualFold(flag, "extended-matching") {
			return nil, false, fmt.Errorf("%w: sub-rule option %q", errUnsupportedModuleRule, flag)
		}
		extended = true
	}
	kind := strings.ToUpper(fields[0])
	switch kind {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD":
		value := strings.ToLower(fields[1])
		if kind != "DOMAIN-KEYWORD" {
			value = strings.TrimSuffix(value, ".")
		}
		if kind == "DOMAIN-SUFFIX" {
			value = strings.TrimPrefix(value, ".")
		}
		if value == "" || strings.ContainsAny(value, " /\\\t\r\n,:()") {
			return nil, false, fmt.Errorf("invalid Rule hostname or keyword %q", fields[1])
		}
		if kind == "DOMAIN-WILDCARD" && strings.ContainsAny(value, "[]") {
			return nil, false, fmt.Errorf("%w: DOMAIN-WILDCARD character classes", errUnsupportedModuleRule)
		}
		if kind != "DOMAIN-WILDCARD" && kind != "DOMAIN-KEYWORD" && strings.ContainsAny(value, "*?[]") {
			return nil, false, fmt.Errorf("invalid literal Rule hostname %q", value)
		}
		return [][]RuleDomain{{{Type: kind, Value: value, Not: negated}}}, extended, nil
	case "AND", "OR", "NOT":
	default:
		return nil, false, fmt.Errorf("%w: type %q", errUnsupportedModuleRule, fields[0])
	}
	value := strings.TrimSpace(fields[1])
	if len(value) < 2 || value[0] != '(' || value[len(value)-1] != ')' {
		return nil, false, fmt.Errorf("logical Rule requires a parenthesized sub-rule list")
	}
	children, err := splitModuleRuleFields(value[1 : len(value)-1])
	if err != nil {
		return nil, false, err
	}
	if kind == "NOT" && len(children) != 1 {
		return nil, false, fmt.Errorf("NOT requires exactly one sub-rule")
	}
	and := (kind == "AND") != negated
	if and {
		clauses = [][]RuleDomain{{}}
	}
	for _, child := range children {
		if len(child) < 2 || child[0] != '(' || child[len(child)-1] != ')' {
			return nil, false, fmt.Errorf("each logical sub-rule must be parenthesized")
		}
		parts, err := splitModuleRuleFields(child[1 : len(child)-1])
		if err != nil {
			return nil, false, err
		}
		part, childExtended, err := parseModuleRuleExpression(parts, depth+1, negated != (kind == "NOT"))
		if err != nil {
			return nil, false, err
		}
		extended = extended || childExtended
		if kind == "NOT" {
			return part, extended, nil
		}
		if and {
			if len(clauses)*len(part) > maxModuleRuleClauses {
				return nil, false, fmt.Errorf("Rule expansion exceeds %d clauses", maxModuleRuleClauses)
			}
			var product [][]RuleDomain
			for _, a := range clauses {
				for _, b := range part {
					joined := make([]RuleDomain, 0, len(a)+len(b))
					joined = append(joined, a...)
					joined = append(joined, b...)
					product = append(product, joined)
				}
			}
			clauses = product
		} else {
			clauses = append(clauses, part...)
		}
		predicates := 0
		for _, clause := range clauses {
			predicates += len(clause)
		}
		if len(clauses) > maxModuleRuleClauses || predicates > maxModuleRulePredicates {
			return nil, false, fmt.Errorf("Rule expansion exceeds %d clauses or %d predicates", maxModuleRuleClauses, maxModuleRulePredicates)
		}
	}
	return clauses, extended, nil
}

func splitModuleRuleFields(source string) ([]string, error) {
	if len(source) > 64<<10 {
		return nil, fmt.Errorf("Rule exceeds 64 KiB")
	}
	var fields []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(source); i++ {
		ch := source[i]
		if quote != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case '(':
			depth++
			if depth > 64 {
				return nil, fmt.Errorf("Rule parentheses exceed nesting limit")
			}
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced Rule parentheses")
			}
		case ',':
			if depth == 0 {
				fields = append(fields, strings.TrimSpace(source[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 || quote != 0 {
		return nil, fmt.Errorf("unbalanced Rule parentheses or quotes")
	}
	fields = append(fields, strings.TrimSpace(source[start:]))
	for i, field := range fields {
		if len(field) >= 2 && (field[0] == '"' || field[0] == '\'') && field[len(field)-1] == field[0] {
			field = field[1 : len(field)-1]
			fields[i] = field
		}
		if field == "" {
			return nil, fmt.Errorf("empty Rule field")
		}
	}
	return fields, nil
}

func trimModuleRuleComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		if line[i] == '\\' && quote != 0 {
			i++
			continue
		}
		if line[i] == '"' || line[i] == '\'' {
			if quote == line[i] {
				quote = 0
			} else if quote == 0 {
				quote = line[i]
			}
			continue
		}
		if quote == 0 && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') && (line[i] == '#' || line[i] == ';' || strings.HasPrefix(line[i:], "//")) {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}
