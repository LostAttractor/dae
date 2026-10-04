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
	"sync"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/transport/smux"
	"github.com/dlclark/regexp2"
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
)

type NodeDescriptor struct {
	Name            string
	Link            string
	SubscriptionTag string
	Defaults        config.NodeOptions
	Rules           []config.NodeOptionRule
	Options         config.NodeOptions
	Required        bool
}

// NodeInfo is one original node. It never represents an expanded chain.
type NodeInfo struct {
	Link     string
	Property *dialer.Property
	Dialers  []D.Builder
	Required bool
}

type PathSpec struct {
	Nodes         []*NodeInfo // Physical order: first proxy to final proxy.
	Annotation    *dialer.Annotation
	Entry         EntryOptions
	IPVersion     int  // Physical entrance family; 0 before variant expansion.
	showIPVersion bool // Display a family suffix only for a split dual-stack path.
}

type DialerSet struct {
	nodeInfos []*NodeInfo
	// Runtime reuse is scoped to one control plane, including late plugin targets.
	pathMu sync.Mutex
	paths  map[string]*dialer.Dialer
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
	for index, node := range nodes {
		builder, property, err := parseNodeLink(node.Link)
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
		if isReservedTargetName(property.Name) {
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
			if err := validateFilters(rule.Filter); err != nil {
				return nil, fmt.Errorf("apply options to node %q: %w", property.Name, err)
			}
			if filterHit(nodeInfo, rule.Filter) {
				effectiveOptions.Overlay(rule.Options)
			}
		}
		effectiveOptions.Overlay(node.Options)
		builders, err := applyNodeOptions(builder, effectiveOptions)
		if err != nil {
			return nil, fmt.Errorf("apply options to node %q: %w", property.Name, err)
		}
		nodeInfo.Property.Link = nodeIdentity(property.Link, effectiveOptions)
		nodeInfo.Dialers = builders
		set.nodeInfos = append(set.nodeInfos, nodeInfo)
	}
	return set, nil
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

func parseNodeLink(link string) (D.Builder, *D.Property, error) {
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
	builder, property, err := parseNodeLink(link)
	if err != nil {
		return errors.New("node parser rejected link")
	}
	node := &NodeInfo{
		Link:     link,
		Property: &dialer.Property{Property: *property},
		Dialers:  []D.Builder{builder},
	}
	created, err := new(DialerSet).BuildPath(NodePath(node), option, "validation")
	if err != nil {
		return errors.New("node dialer construction failed")
	}
	return created.Close()
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

func validateFilters(filters []*config_parser.Function) error {
	for _, filter := range filters {
		switch filter.Name {
		case FilterInput_Name, FilterInput_SubscriptionTag, FilterInput_Link, FilterInput_Protocol:
		default:
			return fmt.Errorf("unsupported filter input type: %q", filter.Name)
		}
		for _, param := range filter.Params {
			switch param.Key {
			case "":
			case FilterKey_Name_Keyword:
				if filter.Name == FilterInput_SubscriptionTag {
					return fmt.Errorf(`unsupported filter key %q in "filter: %v()"`, param.Key, filter.Name)
				}
			case FilterKey_Name_Regex:
				if _, err := regexp2.Compile(param.Val, 0); err != nil {
					return fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
				}
			default:
				return fmt.Errorf(`unsupported filter key %q in "filter: %v()"`, param.Key, filter.Name)
			}
		}
	}
	return nil
}

func filterHit(nodeInfo *NodeInfo, filters []*config_parser.Function) bool {
	for _, filter := range filters {
		var value string
		switch filter.Name {
		case FilterInput_Name:
			value = nodeInfo.Property.Name
		case FilterInput_SubscriptionTag:
			value = nodeInfo.Property.SubscriptionTag
		case FilterInput_Link:
			value = nodeInfo.Link
		case FilterInput_Protocol:
			value = nodeInfo.Property.Protocol
		}
		hit := false
		for _, param := range filter.Params {
			switch param.Key {
			case FilterKey_Name_Regex:
				regex, _ := regexp2.Compile(param.Val, 0)
				hit, _ = regex.MatchString(value)
			case FilterKey_Name_Keyword:
				hit = strings.Contains(value, param.Val)
			default:
				hit = value == param.Val
			}
			if hit {
				break
			}
		}
		if hit == filter.Not {
			return false
		}
	}
	return true
}

func (s *DialerSet) Filter(filters []*config_parser.Function) ([]*NodeInfo, error) {
	if err := validateFilters(filters); err != nil {
		return nil, err
	}
	filtered := make([]*NodeInfo, 0, len(s.nodeInfos))
	for _, node := range s.nodeInfos {
		if filterHit(node, filters) {
			filtered = append(filtered, node)
		}
	}
	return filtered, nil
}

func nodeKey(node *NodeInfo) string {
	var builder strings.Builder
	for _, value := range []string{node.Property.SubscriptionTag, node.Property.Name, node.Property.Link} {
		fmt.Fprintf(&builder, "%d:%s", len(value), value)
	}
	return builder.String()
}

func runtimePathKey(spec *PathSpec, option *dialer.GlobalOption) string {
	var builder strings.Builder
	builder.WriteString(spec.Identity())
	writeRuntimeOptions(&builder, spec, option)
	return builder.String()
}

func writeRuntimeOptions(builder *strings.Builder, spec *PathSpec, option *dialer.GlobalOption) {
	builder.WriteString("|runtime-options|")
	values := []string{
		fmt.Sprintf("%t", option.AllowInsecure),
		option.TlsImplementation,
		option.UtlsImitate,
		option.BandwidthMaxTx,
		option.BandwidthMaxRx,
		fmt.Sprintf("%t", option.TlsFragment),
		option.TlsFragmentLength,
		option.TlsFragmentInterval,
		option.UDPHopInterval.String(),
		strconv.FormatUint(uint64(spec.effectiveMark(option)), 10),
		strconv.FormatBool(option.Mptcp),
		option.DNSResolver,
	}
	for _, value := range values {
		fmt.Fprintf(builder, "%d:%s", len(value), value)
	}
}

// Presentation, group policy and selection annotations do not configure the
// physical path. Probe settings do: different checks need independent workers.
func sharedPathKey(spec *PathSpec, option *dialer.GlobalOption) string {
	var builder strings.Builder
	for _, node := range spec.Nodes {
		link, annotations, _ := strings.Cut(node.Property.Link, "\x1e")
		if link == "" {
			link = node.Link
		}
		if annotations == "multiplex=off" {
			annotations = ""
		}
		if parsed, err := url.Parse(link); err == nil {
			parsed.Fragment, parsed.RawFragment = "", ""
			parsed.RawQuery = parsed.Query().Encode()
			link = parsed.String()
		}
		fmt.Fprintf(&builder, "%d:%s%d:%s", len(link), link, len(annotations), annotations)
	}
	fmt.Fprintf(&builder, "|entry|%d|%d:%s", spec.IPVersion, len(spec.Entry.Interface), spec.Entry.Interface)
	writeRuntimeOptions(&builder, spec, option)
	fmt.Fprintf(&builder, "|checks|%d|%d|", option.CheckInterval, option.CheckIntervalMax)
	for _, value := range option.CheckDnsOptionRaw.Raw {
		fmt.Fprintf(&builder, "%d:%s", len(value), value)
	}
	return builder.String()
}

func pathIdentity(nodes []*NodeInfo) string {
	var builder strings.Builder
	for _, node := range nodes {
		builder.WriteString(nodeKey(node))
	}
	return builder.String()
}

func (p *PathSpec) Identity() string {
	identity := pathIdentity(p.Nodes)
	if p.IPVersion == 0 && !p.Entry.configured() {
		return identity
	}
	mark := "inherit"
	if p.Entry.Mark != nil {
		mark = strconv.FormatUint(uint64(*p.Entry.Mark), 10)
	}
	return fmt.Sprintf("%s|entry|%d|%s|%d:%s", identity, p.IPVersion, mark, len(p.Entry.Interface), p.Entry.Interface)
}

type PathBuildError struct {
	Node *NodeInfo
	Err  error
}

func (e *PathBuildError) Error() string {
	return fmt.Sprintf("build node %q: %v", e.Node.Property.Name, e.Err)
}

func (e *PathBuildError) Unwrap() error { return e.Err }

type pathNodeBuilder struct {
	node    *NodeInfo
	builder D.Builder
}

func (b pathNodeBuilder) Build(option *D.ExtraOption, upstream D.Upstream) (netproxy.Layer, error) {
	layer, err := b.builder.Build(option, upstream)
	if err != nil {
		return netproxy.Layer{}, &PathBuildError{Node: b.node, Err: err}
	}
	return layer, nil
}

func (s *DialerSet) BuildPath(spec *PathSpec, option *dialer.GlobalOption, statsScope string) (*dialer.Dialer, error) {
	if len(spec.Nodes) == 0 {
		return nil, errors.New("cannot build an empty proxy path")
	}
	names := make([]string, 0, len(spec.Nodes))
	protocols := make([]string, 0, len(spec.Nodes))
	addresses := make([]string, 0, len(spec.Nodes))
	hops := make([]dialer.Hop, 0, len(spec.Nodes))
	for index, node := range spec.Nodes {
		protocol := nodeDisplayProtocol(node)
		name := node.Property.Name
		if index == 0 {
			name += spec.entryLabel()
		}
		names = append(names, name)
		protocols = append(protocols, protocol)
		addresses = append(addresses, node.Property.Address)
		hops = append(hops, dialer.Hop{
			ID:       stats.NodeID(nodeKey(node)),
			Name:     node.Property.Name,
			Subtag:   node.Property.SubscriptionTag,
			Protocol: protocol,
			Address:  node.Property.Address,
		})
	}
	terminal := spec.Nodes[len(spec.Nodes)-1]
	property := &dialer.Property{
		Name:            strings.Join(names, " -> "),
		Protocol:        strings.Join(protocols, " -> "),
		Address:         strings.Join(addresses, " -> "),
		Link:            runtimePathKey(spec, option),
		SubscriptionTag: terminal.Property.SubscriptionTag,
		Hops:            hops,
		Egress:          &api.NodeEgress{IPVersion: spec.IPVersion, Mark: spec.effectiveMark(option), Interface: spec.Entry.Interface},
	}
	s.pathMu.Lock()
	defer s.pathMu.Unlock()
	key := sharedPathKey(spec, option)
	if existing := s.paths[key]; existing != nil {
		if member, ok := existing.Share(property, statsScope); ok {
			return member, nil
		}
	}
	builders := make([]D.Builder, 0)
	for _, node := range spec.Nodes {
		for _, builder := range node.Dialers {
			builders = append(builders, pathNodeBuilder{node: node, builder: builder})
		}
	}
	base, err := spec.entryDialer(option)
	if err != nil {
		return nil, err
	}
	runtime, err := D.BuildRuntime(netproxy.Layer{Data: base}, &option.ExtraOption, builders...)
	if err != nil {
		return nil, err
	}
	d := dialer.NewDialer(runtime, option, property, true, statsScope)
	if s.paths == nil {
		s.paths = make(map[string]*dialer.Dialer)
	}
	s.paths[key] = d
	return d, nil
}
