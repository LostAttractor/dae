/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/dlclark/regexp2"
	"strings"
)

const (
	FilterInput_Name            = "name"
	FilterInput_SubscriptionTag = "subtag"
	FilterInput_Link            = "link"
	FilterInput_Protocol        = "protocol"
)

const (
	FilterKey_Name_Regex   = "regex"
	FilterKey_Name_Keyword = "keyword"
)

type compiledFilter struct {
	name   string
	not    bool
	params []compiledFilterParam
}
type compiledFilterParam struct {
	key, value string
	regex      *regexp2.Regexp
}

// Compiled filters belong to one preparation. Nodes from the same subscription
// share the immutable rule AST, so pointer keys avoid parsing or serializing it.
func compileFilters(filters []*config_parser.Function, cache map[*config_parser.Function]*compiledFilter) ([]*compiledFilter, error) {
	compiled := make([]*compiledFilter, 0, len(filters))
	for _, filter := range filters {
		if existing := cache[filter]; existing != nil {
			compiled = append(compiled, existing)
			continue
		}
		switch filter.Name {
		case FilterInput_Name, FilterInput_SubscriptionTag, FilterInput_Link, FilterInput_Protocol:
		default:
			return nil, fmt.Errorf("unsupported filter input type: %q", filter.Name)
		}
		entry := &compiledFilter{name: filter.Name, not: filter.Not}
		for _, param := range filter.Params {
			p := compiledFilterParam{key: param.Key, value: param.Val}
			switch param.Key {
			case "":
			case FilterKey_Name_Keyword:
				if filter.Name == FilterInput_SubscriptionTag {
					return nil, fmt.Errorf(`unsupported filter key %q in "filter: %v()"`, param.Key, filter.Name)
				}
			case FilterKey_Name_Regex:
				var err error
				p.regex, err = regexp2.Compile(param.Val, 0)
				if err != nil {
					return nil, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
				}
			default:
				return nil, fmt.Errorf(`unsupported filter key %q in "filter: %v()"`, param.Key, filter.Name)
			}
			entry.params = append(entry.params, p)
		}
		if cache != nil {
			cache[filter] = entry
		}
		compiled = append(compiled, entry)
	}
	return compiled, nil
}

func (node *NodeInfo) filterValue(name string) string {
	switch name {
	case FilterInput_Name:
		return node.Property.Name
	case FilterInput_SubscriptionTag:
		return node.Property.SubscriptionTag
	case FilterInput_Link:
		return node.Link
	case FilterInput_Protocol:
		return node.Property.Protocol
	default:
		return ""
	}
}

func (filter *compiledFilter) matches(value string) bool {
	for _, param := range filter.params {
		var hit bool
		switch param.key {
		case FilterKey_Name_Regex:
			hit, _ = param.regex.MatchString(value)
		case FilterKey_Name_Keyword:
			hit = strings.Contains(value, param.value)
		default:
			hit = value == param.value
		}
		if hit {
			return !filter.not
		}
	}
	return filter.not
}

func filterHit(nodeInfo *NodeInfo, filters []*compiledFilter) bool {
	for _, filter := range filters {
		if !filter.matches(nodeInfo.filterValue(filter.name)) {
			return false
		}
	}
	return true
}

func (s *DialerSet) Filter(filters []*config_parser.Function) ([]*NodeInfo, error) {
	compiled, err := compileFilters(filters, nil)
	if err != nil {
		return nil, err
	}
	filtered := make([]*NodeInfo, 0, len(s.nodeInfos))
	for _, node := range s.nodeInfos {
		if filterHit(node, compiled) {
			filtered = append(filtered, node)
		}
	}
	return filtered, nil
}
