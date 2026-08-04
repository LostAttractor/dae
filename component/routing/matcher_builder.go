/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	log "github.com/sirupsen/logrus"
)

type DomainSet struct {
	Key       consts.RoutingDomainKey
	RuleIndex int
	Domains   []string
}

type Outbound struct {
	Name string
	Mark uint32
	Must bool
	// SkipWhileNoalive makes the rule conditional on the target outbound
	// group's connectivity: if the group cannot serve the network type of
	// the current traffic, the rule is treated as not hit and routing falls
	// through to the next rule.
	SkipWhileNoalive bool
}

type RulesBuilder struct {
	parsers map[string]FunctionParser
}

func NewRulesBuilder() *RulesBuilder {
	return &RulesBuilder{
		parsers: make(map[string]FunctionParser),
	}
}

func (b *RulesBuilder) RegisterFunctionParser(funcName string, parser FunctionParser) {
	b.parsers[funcName] = parser
}

func (b *RulesBuilder) Apply(rules []*config_parser.RoutingRule) (err error) {
	for _, rule := range rules {
		log.Debugln("[rule]", rule.String(true, false, false))
		outbound, err := ParseOutbound(&rule.Outbound)
		if err != nil {
			return err
		}

		// rule is like: domain(domain:baidu.com) && port(443) -> proxy
		for iFunc, f := range rule.AndFunctions {
			// f is like: domain(domain:baidu.com)
			functionParser, ok := b.parsers[f.Name]
			if !ok {
				return fmt.Errorf("unknown function: %v", f.Name)
			}
			paramValueGroups, keyOrder := groupParamValuesByKey(f.Params)
			for jMatchSet, key := range keyOrder {
				paramValueGroup := paramValueGroups[key]
				// Preprocess the outbound.
				overrideOutbound := &Outbound{
					Name:             consts.OutboundLogicalOr.String(),
					Mark:             outbound.Mark,
					Must:             outbound.Must,
					SkipWhileNoalive: outbound.SkipWhileNoalive,
				}
				if jMatchSet == len(keyOrder)-1 {
					overrideOutbound.Name = consts.OutboundLogicalAnd.String()
					if iFunc == len(rule.AndFunctions)-1 {
						overrideOutbound.Name = outbound.Name
					}
				}

				{
					// Debug
					symNot := ""
					if f.Not {
						symNot = "!"
					}
					log.Tracef("\t%v%v(%v) -> %v", symNot, f.Name, key, overrideOutbound.Name)
				}

				if err = functionParser(f, key, paramValueGroup, overrideOutbound); err != nil {
					return fmt.Errorf("failed to parse '%v': %w", f.String(false, false, false), err)
				}
			}
		}
	}
	return nil
}

func groupParamValuesByKey(params []*config_parser.Param) (keyToValues map[string][]string, keyOrder []string) {
	groups := make(map[string][]string)
	for _, param := range params {
		if _, ok := groups[param.Key]; !ok {
			keyOrder = append(keyOrder, param.Key)
		}
		groups[param.Key] = append(groups[param.Key], param.Val)
	}
	return groups, keyOrder
}

func ParseOutbound(rawOutbound *config_parser.Function) (outbound *Outbound, err error) {
	outbound = &Outbound{
		Name: rawOutbound.Name,
		Mark: 0,
		Must: false,
	}
	for _, p := range rawOutbound.Params {
		switch p.Key {
		case consts.OutboundParam_Mark:
			var _mark uint64
			_mark, err = strconv.ParseUint(p.Val, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("failed to parse mark: %v", err)
			}
			outbound.Mark = uint32(_mark)
		case consts.OutboundParam_SkipWhileNoalive:
			skip, parseErr := strconv.ParseBool(p.Val)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse %v: %v", consts.OutboundParam_SkipWhileNoalive, parseErr)
			}
			outbound.SkipWhileNoalive = skip
		case "":
			if p.Val == "must" {
				outbound.Must = true
			} else if p.Val == consts.OutboundParam_SkipWhileNoalive {
				outbound.SkipWhileNoalive = true
			} else {
				return nil, fmt.Errorf("unknown outbound param: %v", p.Val)
			}
		default:
			return nil, fmt.Errorf("unknown outbound param key: %v", p.Key)
		}
	}
	return outbound, nil
}
