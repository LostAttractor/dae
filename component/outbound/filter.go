/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/transport/smux"
	"github.com/dlclark/regexp2"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
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

	FilterInput_SubscriptionTag_Regex = "regex"
)

// NodeInfo stores the original node information for lazy creation
type NodeInfo struct {
	Link          string
	Property      *dialer.Property
	Dialers       []D.Dialer
	CreatedDialer *dialer.Dialer
	sourceIndex   int
}

func nodeLogID(node *NodeInfo) string {
	tag := node.Property.SubscriptionTag
	if tag == "" {
		tag = "local"
	}
	return fmt.Sprintf("node %d from %q", node.sourceIndex+1, tag)
}

type NodeDescriptor struct {
	Name            string
	Link            string
	SubscriptionTag string
	Defaults        config.NodeOptions
	Rules           []config.NodeOptionRule
	Options         config.NodeOptions
	SourceIndex     int
}

func (n *NodeInfo) createDialerIfNeeded(option *dialer.GlobalOption, d netproxy.Dialer) (created *dialer.Dialer, err error) {
	if n.CreatedDialer == nil {
		runtime, err := D.BuildRuntime(d, &option.ExtraOption, n.Dialers...)
		if err != nil {
			return nil, err
		}
		n.CreatedDialer = dialer.NewDialer(runtime, option, n.Property, true)
	}
	return n.CreatedDialer, nil
}

type DialerSet struct {
	option             *dialer.GlobalOption
	prometheusRegistry prometheus.Registerer
	nodeInfos          []*NodeInfo
	nodeInfosMap       map[dialer.Property]*NodeInfo
	nodeToTagMap       map[*dialer.Dialer]string
}

func (s *DialerSet) Close() error {
	nodes := make(map[*NodeInfo]struct{}, len(s.nodeInfos)+len(s.nodeInfosMap))
	for _, node := range s.nodeInfos {
		nodes[node] = struct{}{}
	}
	for _, node := range s.nodeInfosMap {
		nodes[node] = struct{}{}
	}
	dialers := make(map[*dialer.Dialer]struct{})
	transports := make(map[any]*dialer.Dialer)
	for node := range nodes {
		if node.CreatedDialer == nil {
			continue
		}
		dialers[node.CreatedDialer] = struct{}{}
		transports[node.CreatedDialer.TransportID()] = node.CreatedDialer
	}
	var err error
	for d := range dialers {
		err = errors.Join(err, d.Close())
	}
	for _, d := range transports {
		d.RetireTransport()
	}
	return err
}

func applyNodeOptions(builders []D.Dialer, options config.NodeOptions) ([]D.Dialer, error) {
	switch options.Multiplex {
	case "", config.MultiplexModeOff:
		return builders, nil
	case config.MultiplexModeSmux, config.MultiplexModeSmuxUDPPassthrough:
		if len(builders) == 0 {
			return nil, fmt.Errorf("cannot apply node options to an empty dialer chain")
		}
		configured := []D.Dialer{builders[0], &smux.SmuxConfig{
			PassThroughUDP: options.Multiplex == config.MultiplexModeSmuxUDPPassthrough,
		}}
		return append(configured, builders[1:]...), nil
	default:
		return nil, fmt.Errorf("unsupported multiplex mode %q", options.Multiplex)
	}
}

func NewDialerSet(option *dialer.GlobalOption, prometheusRegistry prometheus.Registerer, nodes []NodeDescriptor) (*DialerSet, error) {
	s := &DialerSet{
		option:             option,
		prometheusRegistry: prometheusRegistry,
		nodeInfos:          make([]*NodeInfo, 0),
		nodeInfosMap:       make(map[dialer.Property]*NodeInfo),
		nodeToTagMap:       make(map[*dialer.Dialer]string),
	}
	occurrences := make(map[string]map[string]int)
	for _, node := range nodes {
		builders, property, err := parseNodeLink(node.Link)
		if err != nil {
			tag := node.SubscriptionTag
			if tag == "" {
				tag = "local"
			}
			log.Warnf("failed to parse node %d from %q (%T)", node.SourceIndex+1, tag, err)
			continue
		}
		if node.Name != "" {
			property.Name = node.Name
		}
		nodeInfo := &NodeInfo{
			Link: node.Link,
			Property: &dialer.Property{
				Property:        *property,
				SubscriptionTag: node.SubscriptionTag,
			},
			sourceIndex: node.SourceIndex,
		}
		effectiveOptions := node.Defaults
		for _, rule := range node.Rules {
			hit, err := s.filterHit(nodeInfo, rule.Filter)
			if err != nil {
				return nil, fmt.Errorf("apply options to node %q: %w", property.Name, err)
			}
			if hit {
				effectiveOptions.Overlay(rule.Options)
			}
		}
		effectiveOptions.Overlay(node.Options)
		builders, err = applyNodeOptions(builders, effectiveOptions)
		if err != nil {
			return nil, fmt.Errorf("apply options to node %q: %w", property.Name, err)
		}
		nodeInfo.Property.Link = property.Link
		identityLink := node.Link
		if effectiveOptions.Multiplex != "" {
			optionIdentity := "\x1emultiplex=" + string(effectiveOptions.Multiplex)
			nodeInfo.Property.Link += optionIdentity
			identityLink += optionIdentity
		}
		identity := dialer.ComposeStatsIdentity(node.Name, identityLink)
		if occurrences[node.SubscriptionTag] == nil {
			occurrences[node.SubscriptionTag] = make(map[string]int)
		}
		occurrence := occurrences[node.SubscriptionTag][identity]
		occurrences[node.SubscriptionTag][identity]++
		nodeInfo.Property.StatsIdentity = dialer.ComposeStatsIdentity("source", identity, strconv.Itoa(occurrence))
		nodeInfo.Dialers = builders
		s.nodeInfos = append(s.nodeInfos, nodeInfo)
		s.nodeInfosMap[*nodeInfo.Property] = nodeInfo
	}
	return s, nil
}

func normalizeShadowsocksLink(link string) string {
	name, link := common.GetTagFromLinkLikePlaintext(link)
	links := strings.Split(link, "->")
	for i := range links {
		links[i] = normalizeShadowsocksLinkComponent(strings.TrimSpace(links[i]))
	}
	link = strings.Join(links, "->")
	if name != "" {
		link = name + ":" + link
	}
	return link
}

func normalizeShadowsocksLinkComponent(link string) string {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "ss" || u.User == nil {
		return link
	}
	normalized := false
	if plugin := u.Query().Get("plugin"); plugin != "" && !strings.Contains(plugin, ";") {
		query := u.Query()
		query.Set("plugin", plugin+";")
		u.RawQuery = query.Encode()
		normalized = true
	}
	method := u.User.Username()
	password, hasPassword := u.User.Password()
	if hasPassword && strings.HasPrefix(method, "2022-") {
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password)))
		normalized = true
	}
	if !normalized {
		return link
	}
	return u.String()
}

func parseNodeLink(link string) ([]D.Dialer, *D.Property, error) {
	return D.NewFromLink(normalizeShadowsocksLink(link))
}

func ValidateNodeLink(link string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("node parser panicked")
		}
	}()
	_, _, err = parseNodeLink(link)
	if err != nil {
		return errors.New("node parser rejected link")
	}
	return nil
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
	dialers, property, err := parseNodeLink(link)
	if err != nil {
		return errors.New("node parser rejected link")
	}
	node := &NodeInfo{
		Link:     link,
		Property: &dialer.Property{Property: *property},
		Dialers:  dialers,
	}
	created, err := node.createDialerIfNeeded(option, direct.Direct)
	if err != nil {
		return errors.New("node dialer construction failed")
	}
	return closeValidatedDialer(created)
}

func closeValidatedDialer(created *dialer.Dialer) error {
	defer created.RetireTransport()
	return created.Close()
}

func (s *DialerSet) filterHit(nodeInfo *NodeInfo, filters []*config_parser.Function) (hit bool, err error) {
	// Example
	// filter: name(regex:'^.*hk.*$', keyword:'sg') && name(keyword:'disney')
	// filter: !name(regex: 'HK|TW|SG') && name(keyword: disney)
	// filter: subtag(my_sub, regex:^my_, regex:my_)

	// And
	for _, filter := range filters {
		var value string
		keywordSupported := true
		switch filter.Name {
		case FilterInput_Name:
			value = nodeInfo.Property.Name
		case FilterInput_SubscriptionTag:
			value, keywordSupported = nodeInfo.Property.SubscriptionTag, false
		case FilterInput_Link:
			value = nodeInfo.Link
		case FilterInput_Protocol:
			value = nodeInfo.Property.Protocol
		default:
			return false, fmt.Errorf(`unsupported filter input type: "%v"`, filter.Name)
		}

		var subFilterHit bool
		for _, param := range filter.Params {
			switch param.Key {
			case FilterKey_Name_Regex:
				regex, err := regexp2.Compile(param.Val, 0)
				if err != nil {
					return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
				}
				subFilterHit, _ = regex.MatchString(value)
			case FilterKey_Name_Keyword:
				if !keywordSupported {
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
				subFilterHit = strings.Contains(value, param.Val)
			case "":
				subFilterHit = value == param.Val
			default:
				return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
			}
			if subFilterHit {
				break
			}
		}
		if subFilterHit == filter.Not {
			return false, nil
		}
	}
	return true, nil
}

func (s *DialerSet) createNextHopDialer(nodeInfo, nextHopInfo *NodeInfo) (*dialer.Dialer, error) {
	property := *nodeInfo.Property
	property.Name = fmt.Sprintf("%s->%s", nodeInfo.Property.Name, nextHopInfo.Property.Name)
	property.Protocol = fmt.Sprintf("%s->%s", nodeInfo.Property.Protocol, nextHopInfo.Property.Protocol)
	property.Address = fmt.Sprintf("%s->%s", nodeInfo.Property.Address, nextHopInfo.Property.Address)
	effectiveLink := fmt.Sprintf("%s->%s", nodeInfo.Link, nextHopInfo.Link)
	property.Link = fmt.Sprintf("%s->%s", nodeInfo.Property.Link, nextHopInfo.Property.Link)
	sourceIdentity := nodeInfo.Property.StatsIdentity
	if sourceIdentity == "" {
		sourceIdentity = nodeInfo.Property.Link
	}
	nextHopIdentity := nextHopInfo.Property.StatsIdentity
	if nextHopIdentity == "" {
		nextHopIdentity = nextHopInfo.Property.Link
	}
	if nextHopInfo.Property.SubscriptionTag != "" {
		nextHopIdentity = dialer.ComposeStatsIdentity(nextHopInfo.Property.SubscriptionTag, nextHopIdentity)
	}
	property.StatsIdentity = dialer.ComposeStatsIdentity("next-hop", sourceIdentity, nextHopIdentity)

	nextHopNodeInfo, ok := s.nodeInfosMap[property]
	if !ok {
		dialers := make([]D.Dialer, 0, len(nodeInfo.Dialers)+len(nextHopInfo.Dialers))
		dialers = append(dialers, nextHopInfo.Dialers...)
		dialers = append(dialers, nodeInfo.Dialers...)
		nextHopNodeInfo = &NodeInfo{
			Property: &property,
			Dialers:  dialers,
			Link:     effectiveLink,
		}
		s.nodeInfosMap[property] = nextHopNodeInfo
	}
	return nextHopNodeInfo.createDialerIfNeeded(s.option, direct.Direct)
}

func (s *DialerSet) FilterAndAnnotate(filters [][]*config_parser.Function, annotations [][]*config_parser.Param, nextHop string) (dialers []*dialer.Dialer, filterAnnotations []*dialer.Annotation, err error) {
	if len(filters) != len(annotations) {
		return nil, nil, fmt.Errorf("[CODE BUG]: unmatched annotations length: %v filters and %v annotations", len(filters), len(annotations))
	}

	// Find NextHop dialer if specified
	nextHopInfo, err := s.findNextHop(nextHop)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find next_hop '%s': %w", nextHop, err)
	}

	for _, nodeInfo := range s.nodeInfos {
		annotation := &dialer.Annotation{}
		if len(filters) > 0 {
			annotation = nil
			for i, filter := range filters {
				hit, err := s.filterHit(nodeInfo, filter)
				if err != nil {
					return nil, nil, err
				}
				if !hit {
					continue
				}
				annotation, err = dialer.NewAnnotation(annotations[i])
				if err != nil {
					return nil, nil, fmt.Errorf("apply filter annotation: %w", err)
				}
				break
			}
			if annotation == nil {
				continue
			}
		}

		var d *dialer.Dialer
		if nextHopInfo == nil {
			d, err = nodeInfo.createDialerIfNeeded(s.option, direct.Direct)
			if err != nil {
				log.Infof("failed to create dialer for %s: %v", nodeLogID(nodeInfo), err)
				continue
			}
		} else {
			d, err = s.createNextHopDialer(nodeInfo, nextHopInfo)
			if err != nil {
				log.Infof("failed to create dialer for %s via %s: %v", nodeLogID(nodeInfo), nodeLogID(nextHopInfo), err)
				continue
			}
		}
		dialers = append(dialers, d)
		filterAnnotations = append(filterAnnotations, annotation)
	}
	return dialers, filterAnnotations, nil
}

func (s *DialerSet) findNextHop(nextHop string) (*NodeInfo, error) {
	if nextHop == "" {
		return nil, nil
	}
	// Search for the next hop node by name
	for _, nodeInfo := range s.nodeInfos {
		if nodeInfo.Property.Name == nextHop {
			return nodeInfo, nil
		}
	}
	return nil, fmt.Errorf("next_hop node '%s' not found", nextHop)
}
