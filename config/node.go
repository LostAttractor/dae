/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/dlclark/regexp2"
)

type MultiplexMode string

const (
	MultiplexModeSmux               MultiplexMode = "smux"
	MultiplexModeSmuxUDPPassthrough MultiplexMode = "smux-udp-passthrough"
	MultiplexModeOff                MultiplexMode = "off"
)

type NodeOptions struct {
	// Empty means that this layer does not override a lower-precedence value.
	Multiplex MultiplexMode `mapstructure:"multiplex"`
}

func (o *NodeOptions) Overlay(override NodeOptions) {
	if override.Multiplex != "" {
		o.Multiplex = override.Multiplex
	}
}

type NodeOptionRule struct {
	Filter  []*config_parser.Function `mapstructure:"filter"`
	Options NodeOptions               `mapstructure:"_"`
}

type SubscriptionOption struct {
	Defaults NodeOptions      `mapstructure:"_"`
	Rules    []NodeOptionRule `mapstructure:"_"`
}

func (o SubscriptionOption) IsZero() bool {
	return o.Defaults.Multiplex == "" && len(o.Rules) == 0
}

type Subscription struct {
	Name   string             `mapstructure:"_"`
	Link   string             `mapstructure:"link"`
	Option SubscriptionOption `mapstructure:"option"`
}

func (s Subscription) String() string {
	if s.Name != "" {
		return s.Name + ":" + s.Link
	}
	return s.Link
}

type Node struct {
	Name    string      `mapstructure:"_"`
	Link    string      `mapstructure:"link"`
	Options NodeOptions `mapstructure:"option"`
}

func (o *NodeOptions) parse(params ...*config_parser.Param) error {
	for _, param := range params {
		if param.AndFunctions != nil {
			return fmt.Errorf("node option %q must be a literal", param.Key)
		}
		if param.Key != "multiplex" {
			return fmt.Errorf("unknown node option %q", param.Key)
		}
		mode := MultiplexMode(strings.ToLower(strings.TrimSpace(param.Val)))
		switch mode {
		case MultiplexModeSmux, MultiplexModeSmuxUDPPassthrough, MultiplexModeOff:
			o.Multiplex = mode
		default:
			return fmt.Errorf("unsupported multiplex mode %q; expected smux, smux-udp-passthrough or off", param.Val)
		}
	}
	return nil
}

func validateNodeOptionFilter(filters []*config_parser.Function) error {
	for _, filter := range filters {
		if filter.Name != "name" && filter.Name != "protocol" && filter.Name != "link" {
			return fmt.Errorf("unsupported node option filter %q", filter.Name)
		}
		for _, param := range filter.Params {
			if param.AndFunctions != nil || len(param.Annotation) != 0 {
				return fmt.Errorf("node option filter %q parameters must be literals", filter.Name)
			}
			switch param.Key {
			case "", "keyword":
			case "regex":
				if _, err := regexp2.Compile(param.Val, 0); err != nil {
					return fmt.Errorf("bad regexp in node option filter %q: %w", filter.Name, err)
				}
			default:
				return fmt.Errorf("unsupported key %q in node option filter %q", param.Key, filter.Name)
			}
		}
	}
	return nil
}

func parseNodeList(nodes *[]Node, section *config_parser.Section) error {
	for _, item := range section.Items {
		param, ok := item.Value.(*config_parser.Param)
		if !ok {
			return fmt.Errorf("node section does not support %v", item.String(false, false))
		}
		if param.AndFunctions != nil {
			return fmt.Errorf("node link %q must be a literal", param.Key)
		}
		var options NodeOptions
		if err := options.parse(param.Annotation...); err != nil {
			return fmt.Errorf("node %q: %w", param.Key, err)
		}
		*nodes = append(*nodes, Node{Name: param.Key, Link: param.Val, Options: options})
	}
	return nil
}

func parseSubscriptionOption(section *config_parser.Section) (option SubscriptionOption, err error) {
	for _, item := range section.Items {
		param, ok := item.Value.(*config_parser.Param)
		if !ok {
			return SubscriptionOption{}, fmt.Errorf("option section does not support %v", item.String(false, false))
		}
		if param.Key == "filter" {
			if param.AndFunctions == nil {
				return SubscriptionOption{}, fmt.Errorf("option filter must be a function expression")
			}
			if err := validateNodeOptionFilter(param.AndFunctions); err != nil {
				return SubscriptionOption{}, err
			}
			var options NodeOptions
			if err := options.parse(param.Annotation...); err != nil {
				return SubscriptionOption{}, fmt.Errorf("option filter: %w", err)
			}
			if options.Multiplex == "" {
				return SubscriptionOption{}, fmt.Errorf("option filter must set at least one node option")
			}
			option.Rules = append(option.Rules, NodeOptionRule{
				Filter:  param.AndFunctions,
				Options: options,
			})
			continue
		}
		if len(param.Annotation) != 0 {
			return SubscriptionOption{}, fmt.Errorf("default node option %q cannot have an annotation", param.Key)
		}
		if err := option.Defaults.parse(param); err != nil {
			return SubscriptionOption{}, err
		}
	}
	return option, nil
}

func parseExpandedSubscription(section *config_parser.Section) (subscription Subscription, err error) {
	subscription.Name = section.Name
	var linkSet, optionSet bool
	for _, item := range section.Items {
		switch value := item.Value.(type) {
		case *config_parser.Param:
			if value.Key != "link" || value.AndFunctions != nil || len(value.Annotation) != 0 {
				return Subscription{}, fmt.Errorf("subscription %q: expected a literal link", section.Name)
			}
			if linkSet {
				return Subscription{}, fmt.Errorf("subscription %q: duplicate link", section.Name)
			}
			subscription.Link = value.Val
			linkSet = true
		case *config_parser.Section:
			if value.Name != "option" {
				return Subscription{}, fmt.Errorf("subscription %q: unknown section %q", section.Name, value.Name)
			}
			if optionSet {
				return Subscription{}, fmt.Errorf("subscription %q: duplicate option section", section.Name)
			}
			subscription.Option, err = parseSubscriptionOption(value)
			if err != nil {
				return Subscription{}, fmt.Errorf("subscription %q: %w", section.Name, err)
			}
			optionSet = true
		default:
			return Subscription{}, fmt.Errorf("subscription %q does not support %v", section.Name, item.String(false, false))
		}
	}
	if !linkSet || subscription.Link == "" {
		return Subscription{}, fmt.Errorf("subscription %q requires link", section.Name)
	}
	return subscription, nil
}

func parseSubscriptionList(subscriptions *[]Subscription, section *config_parser.Section) error {
	for _, item := range section.Items {
		switch value := item.Value.(type) {
		case *config_parser.Param:
			if value.AndFunctions != nil || len(value.Annotation) != 0 {
				return fmt.Errorf("subscription %q must be a literal; use the expanded form for options", value.Key)
			}
			*subscriptions = append(*subscriptions, Subscription{Name: value.Key, Link: value.Val})
		case *config_parser.Section:
			subscription, err := parseExpandedSubscription(value)
			if err != nil {
				return err
			}
			*subscriptions = append(*subscriptions, subscription)
		default:
			return fmt.Errorf("subscription section does not support %v", item.String(false, false))
		}
	}
	return nil
}
