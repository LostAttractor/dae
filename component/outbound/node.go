/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"errors"
	"fmt"
	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/transport/smux"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
)

type NodeDescriptor struct {
	Name            string
	Link            string
	SubscriptionTag string
	SelectionSource string
	Defaults        config.NodeOptions
	Rules           []config.NodeOptionRule
	Options         config.NodeOptions
	Required        bool
}

// NodeInfo is one original node. It never represents an expanded chain.
type NodeInfo struct {
	Link      string
	Property  *dialer.Property
	Dialers   []D.Builder
	Required  bool
	Selection selector.Node
}

type DialerSet struct {
	nodeInfos []*NodeInfo
	local     PathPool
	shared    *PathPool
}

func applyNodeOptions(builder D.Builder, options config.NodeOptions) ([]D.Builder, error) {
	if options.MultiplexMaxConnections != nil && (*options.MultiplexMaxConnections < 1 || *options.MultiplexMaxConnections > smux.MaxConnectionsLimit) {
		return nil, fmt.Errorf("multiplex_max_connections must be between 1 and %d", smux.MaxConnectionsLimit)
	}
	switch options.Multiplex {
	case "", config.MultiplexModeOff:
		if options.MultiplexMaxConnections != nil {
			return nil, fmt.Errorf("multiplex_max_connections requires multiplex: smux or smux-udp-passthrough")
		}
		return []D.Builder{builder}, nil
	case config.MultiplexModeSmux, config.MultiplexModeSmuxUDPPassthrough:
		configured := []D.Builder{builder, &smux.SmuxConfig{
			PassThroughUDP: options.Multiplex == config.MultiplexModeSmuxUDPPassthrough,
			MaxConnections: multiplexMaxConnections(options),
		}}
		return configured, nil
	default:
		return nil, fmt.Errorf("unsupported multiplex mode %q", options.Multiplex)
	}
}

func multiplexMaxConnections(options config.NodeOptions) int {
	if options.MultiplexMaxConnections == nil {
		return smux.DefaultMaxConnections
	}
	return int(*options.MultiplexMaxConnections)
}

func nodeIdentity(link string, options config.NodeOptions) string {
	if options.Multiplex != "" {
		identity := link + "\x1emultiplex=" + string(options.Multiplex)
		if options.Multiplex != config.MultiplexModeOff {
			identity += "\x1emultiplex_max_connections=" + strconv.Itoa(multiplexMaxConnections(options))
		}
		return identity
	}
	return link
}

func nodeDisplayProtocol(node *NodeInfo) string {
	for _, builder := range node.Dialers {
		mux, ok := builder.(*smux.SmuxConfig)
		if !ok {
			continue
		}
		mode := "smux"
		if mux.PassThroughUDP {
			mode = "smux/udp-pass"
		}
		return node.Property.Protocol + "(" + mode + ")"
	}
	return node.Property.Protocol
}

func NewDialerSet(nodes []NodeDescriptor) (*DialerSet, error) {
	set := new(DialerSet)
	filterCache := make(map[*config_parser.Function]*compiledFilter)
	for index, node := range nodes {
		builder, property, err := D.NewFromLink(node.Link)
		if err != nil {
			if node.Required {
				return nil, fmt.Errorf("parse local node %d (%q): %w", index+1, node.Name, err)
			}
			log.WithFields(log.Fields{"subscription": node.SubscriptionTag, "node": node.Name, "index": index + 1}).WithError(err).Warn("Skipping invalid subscription node")
			continue
		}
		if node.Name != "" {
			property.Name = node.Name
		}
		if IsReservedTargetName(property.Name) {
			if node.Required {
				return nil, fmt.Errorf("local node name %q is reserved", property.Name)
			}
			log.WithFields(log.Fields{"subscription": node.SubscriptionTag, "node": property.Name}).Warn("Skipping subscription node with reserved name")
			continue
		}
		nodeInfo := &NodeInfo{
			Link:     node.Link,
			Required: node.Required,
			Property: &dialer.Property{
				Property:        *property,
				SubscriptionTag: node.SubscriptionTag,
			},
		}
		effectiveOptions := node.Defaults
		for _, rule := range node.Rules {
			filters, err := compileFilters(rule.Filter, filterCache)
			if err != nil {
				return nil, fmt.Errorf("apply options to node %q: %w", property.Name, err)
			}
			if filterHit(nodeInfo, filters) {
				effectiveOptions.Overlay(rule.Options)
			}
		}
		effectiveOptions.Overlay(node.Options)
		builders, err := applyNodeOptions(builder, effectiveOptions)
		if err != nil {
			return nil, fmt.Errorf("apply options to node %q: %w", property.Name, err)
		}
		nodeInfo.Property.Link = nodeIdentity(property.Link, effectiveOptions)
		source := node.SelectionSource
		if source == "" {
			source = "local"
			if node.SubscriptionTag != "" {
				source = selector.SubscriptionSource(node.SubscriptionTag, "")
			}
		}
		nodeInfo.Selection = selector.Node{Source: source, Name: property.Name, Fingerprint: selector.Fingerprint(node.Link)}
		nodeInfo.Dialers = builders
		set.nodeInfos = append(set.nodeInfos, nodeInfo)
	}
	// Record ambiguity in the full source, not just the current filter results.
	counts := make(map[[2]string]int)
	for _, node := range set.nodeInfos {
		counts[[2]string{node.Selection.Source, node.Selection.Name}]++
	}
	for _, node := range set.nodeInfos {
		node.Selection.Exact = node.Selection.Name == "" || counts[[2]string{node.Selection.Source, node.Selection.Name}] > 1
	}
	return set, nil
}

const maxConcurrentNodeValidations = 4

var nodeValidationSlots = make(chan struct{}, maxConcurrentNodeValidations)

type nodeValidationFunc func(*dialer.GlobalOption, string) error

// NewNodeValidator validates both link syntax and protocol construction using
// the options that will be used by the control plane.
func NewNodeValidator(ctx context.Context, global *config.Global) func(string) error {
	return newNodeValidator(ctx, dialer.NewGlobalOption(global), validateNodeDialer)
}

func newNodeValidator(ctx context.Context, option *dialer.GlobalOption, validate nodeValidationFunc) func(string) error {
	return func(link string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case nodeValidationSlots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		result := make(chan error, 1)
		go func() {
			err := validate(option, link)
			<-nodeValidationSlots
			result <- err
		}()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-result:
			return err
		}
	}
}

func validateNodeDialer(option *dialer.GlobalOption, link string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("node dialer construction panicked")
		}
	}()
	builder, property, err := D.NewFromLink(link)
	if err != nil {
		return errors.New("node parser rejected link")
	}
	name := property.Name
	// Validate the same entry and protocol constructors used by BuildPath.
	// Group members, presentation keys and dormant-session watchers belong to
	// serving paths and provide no additional validation here.
	base, err := new(PathSpec).entryDialer(option)
	if err != nil {
		return errors.New("node dialer construction failed")
	}
	created, err := D.BuildRuntime(netproxy.Layer{Data: base}, &option.ExtraOption, builder)
	if err != nil {
		return errors.New("node dialer construction failed")
	}
	created.Retire()
	go func() {
		if err := created.Wait(context.Background()); err != nil {
			log.WithField("node", name).WithError(err).Debug("Outbound cleanup completed with an error")
		}
	}()
	return nil
}

func (s *DialerSet) NodesNamed(name string) []*NodeInfo {
	var nodes []*NodeInfo
	for _, node := range s.nodeInfos {
		if node.Property.Name == name {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func nodeKey(node *NodeInfo) string {
	var builder strings.Builder
	for _, value := range []string{node.Property.SubscriptionTag, node.Property.Name, node.Property.Link} {
		fmt.Fprintf(&builder, "%d:%s", len(value), value)
	}
	return builder.String()
}
