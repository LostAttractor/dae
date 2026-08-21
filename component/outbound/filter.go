/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/dlclark/regexp2"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	FilterInput_Name            = "name"
	FilterInput_SubscriptionTag = "subtag"
	FilterInput_Link            = "link"
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

func (n *NodeInfo) createDialerIfNeeded(option *dialer.GlobalOption, d netproxy.Dialer) (*dialer.Dialer, error) {
	if n.CreatedDialer == nil {
		for _, descriptor := range n.Dialers {
			var err error
			d, err = descriptor.Dialer(&option.ExtraOption, d)
			if err != nil {
				return nil, err
			}
		}
		n.CreatedDialer = dialer.NewDialer(d, option, n.Property, true)
	}
	return n.CreatedDialer, nil
}

type DialerSet struct {
	option             *dialer.GlobalOption
	prometheusRegistry prometheus.Registerer
	nodeInfos          []*NodeInfo
	nodeInfosMap       map[dialer.Property]*NodeInfo
	nodeToTagMap       map[*dialer.Dialer]string // Only for created dialers
}

func NewDialerSetFromLinks(option *dialer.GlobalOption, prometheusRegistry prometheus.Registerer, tagToNodeList map[string][]string) *DialerSet {
	s := &DialerSet{
		option:             option,
		prometheusRegistry: prometheusRegistry,
		nodeInfos:          make([]*NodeInfo, 0),
		nodeInfosMap:       make(map[dialer.Property]*NodeInfo),
		nodeToTagMap:       make(map[*dialer.Dialer]string),
	}
	for subscriptionTag, nodes := range tagToNodeList {
		for i, node := range nodes {
			d, p, err := parseNodeLink(node)
			if err != nil {
				log.Warnf("failed to parse node %d from %q (%T)", i+1, subscriptionTag, err)
				continue
			}
			nodeInfo := &NodeInfo{
				Link: node,
				Property: &dialer.Property{
					Property:        *p,
					SubscriptionTag: subscriptionTag,
				},
				Dialers:     d,
				sourceIndex: i,
			}
			s.nodeInfos = append(s.nodeInfos, nodeInfo)
			s.nodeInfosMap[*nodeInfo.Property] = nodeInfo
		}
	}
	return s
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

func (s *DialerSet) filterHit(nodeInfo *NodeInfo, filters []*config_parser.Function) (hit bool, err error) {
	if len(filters) == 0 {
		// No filter.
		return true, nil
	}

	// Example
	// filter: name(regex:'^.*hk.*$', keyword:'sg') && name(keyword:'disney')
	// filter: !name(regex: 'HK|TW|SG') && name(keyword: disney)
	// filter: subtag(my_sub, regex:^my_, regex:my_)

	// And
	for _, filter := range filters {
		var subFilterHit bool

		switch filter.Name {
		case FilterInput_Name:
			// Or
		loop:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterKey_Name_Regex:
					regex, err := regexp2.Compile(param.Val, 0)
					if err != nil {
						return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
					}
					matched, _ := regex.MatchString(nodeInfo.Property.Name)
					//logrus.Warnln(param.Val, matched, dialer.Name())
					if matched {
						subFilterHit = true
						break loop
					}
				case FilterKey_Name_Keyword:
					if strings.Contains(nodeInfo.Property.Name, param.Val) {
						subFilterHit = true
						break loop
					}
				case "":
					if nodeInfo.Property.Name == param.Val {
						subFilterHit = true
						break loop
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}
		case FilterInput_SubscriptionTag:
			// Or
		loop2:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterInput_SubscriptionTag_Regex:
					regex, err := regexp2.Compile(param.Val, 0)
					if err != nil {
						return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
					}
					matched, _ := regex.MatchString(nodeInfo.Property.SubscriptionTag)
					if matched {
						subFilterHit = true
						break loop2
					}
					//logrus.Warnln(param.Val, matched, dialer.Name())
				case "":
					// Full
					if nodeInfo.Property.SubscriptionTag == param.Val {
						subFilterHit = true
						break loop2
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}

		default:
			return false, fmt.Errorf(`unsupported filter input type: "%v"`, filter.Name)
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
	property.Link = effectiveLink

	nextHopNodeInfo, ok := s.nodeInfosMap[property]
	if !ok {
		dialers := make([]D.Dialer, 0, len(nodeInfo.Dialers)+len(nextHopInfo.Dialers))
		dialers = append(dialers, nodeInfo.Dialers...)
		dialers = append(dialers, nextHopInfo.Dialers...)
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

nextDialerLoop:
	for _, nodeInfo := range s.nodeInfos {
		if len(filters) == 0 {
			// No filters, create all dialers
			d, err := nodeInfo.createDialerIfNeeded(s.option, direct.Direct)
			if err != nil {
				log.Infof("failed to create dialer for %s: %v", nodeLogID(nodeInfo), err)
				continue
			}
			if nextHopInfo != nil {
				d, err = s.createNextHopDialer(nodeInfo, nextHopInfo)
				if err != nil {
					log.Infof("failed to create dialer for %s via %s: %v", nodeLogID(nodeInfo), nodeLogID(nextHopInfo), err)
					continue
				}
			}
			dialers = append(dialers, d)
			filterAnnotations = append(filterAnnotations, &dialer.Annotation{})
			continue
		}
		// Hit any.
		for j, filter := range filters {
			hit, err := s.filterHit(nodeInfo, filter)
			if err != nil {
				return nil, nil, err
			}
			if hit {
				// Create dialer if it hasn't been created yet
				d, err := nodeInfo.createDialerIfNeeded(s.option, direct.Direct)
				if err != nil {
					log.Infof("failed to create dialer for %s: %v", nodeLogID(nodeInfo), err)
					continue nextDialerLoop
				}
				if nextHopInfo != nil {
					d, err = s.createNextHopDialer(nodeInfo, nextHopInfo)
					if err != nil {
						log.Infof("failed to create dialer for %s via %s: %v", nodeLogID(nodeInfo), nodeLogID(nextHopInfo), err)
						continue nextDialerLoop
					}
				}

				anno, err := dialer.NewAnnotation(annotations[j])
				if err != nil {
					return nil, nil, fmt.Errorf("apply filter annotation: %w", err)
				}
				dialers = append(dialers, d)
				filterAnnotations = append(filterAnnotations, anno)
				continue nextDialerLoop
			}
		}
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
