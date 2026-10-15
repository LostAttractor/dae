/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/transport/smux"
	"github.com/daeuniverse/dae/pkg/proxylink"
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

type PathSpec struct {
	Nodes         []*NodeInfo // Physical order: first proxy to final proxy.
	Annotation    *dialer.Annotation
	Entry         EntryOptions
	IPVersion     int  // Physical entrance family; 0 before variant expansion.
	showIPVersion bool // Display a family suffix only for a split dual-stack path.
}

type DialerSet struct {
	nodeInfos []*NodeInfo
	local     PathPool
	shared    *PathPool
}

// PathPool reuses complete physical paths across groups and reloads. The pool
// indexes runtimes; their existing member ownership controls actual retirement.
type PathPool struct {
	mu    sync.Mutex
	paths map[string]*dialer.Dialer
}

func (p *PathPool) prune() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, path := range p.paths {
		if !path.CanShare() {
			delete(p.paths, key)
		}
	}
}

func (s *DialerSet) UsePaths(pool *PathPool) { s.shared = pool }

// GroupPathKey includes presentation and selection annotations as well as the
// physical path. Equivalent transport alone is insufficient to reuse a group.
func GroupPathKey(spec *PathSpec, option *dialer.GlobalOption) string {
	annotation, _ := json.Marshal(spec.Annotation, json.WithMarshalers(json.MarshalFunc(func(value time.Duration) ([]byte, error) {
		return []byte(strconv.FormatInt(int64(value), 10)), nil
	})))
	selection, _ := json.Marshal(spec.selectionReference())
	return fmt.Sprintf("%q/%q/%s/%s", spec.Identity(), sharedPathKey(spec, option), annotation, selection)
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

func normalizeShadowsocksLink(link string) string {
	name, link := proxylink.SplitTag(link)
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
		for _, layer := range node.Dialers {
			identity := ""
			if parsed, ok := layer.(D.ConnectionIdentity); ok {
				identity = parsed.ConnectionIdentity()
			} else {
				// Unknown builders cannot assert transport equivalence. Scope
				// reuse to this immutable node instead of guessing from its URL.
				identity = fmt.Sprintf("%T:%p", layer, node)
			}
			fmt.Fprintf(&builder, "%d:%s", len(identity), identity)
		}
		builder.WriteByte('|')
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

func (spec *PathSpec) selectionReference() *selector.Path {
	selection := &selector.Path{IPVersion: spec.IPVersion, Interface: spec.Entry.Interface, Mark: spec.Entry.Mark}
	for _, node := range spec.Nodes {
		ref := node.Selection
		if ref.Source == "" {
			ref = selector.Node{Source: "local", Name: node.Property.Name, Fingerprint: selector.Fingerprint(node.Link), Exact: node.Property.Name == ""}
		}
		selection.Nodes = append(selection.Nodes, ref)
	}
	return selection.Clone()
}

func (s *DialerSet) BuildPath(spec *PathSpec, option *dialer.GlobalOption, statsScope string) (*dialer.Dialer, error) {
	if len(spec.Nodes) == 0 {
		return nil, errors.New("cannot build an empty proxy path")
	}
	names := make([]string, 0, len(spec.Nodes))
	protocols := make([]string, 0, len(spec.Nodes))
	addresses := make([]string, 0, len(spec.Nodes))
	for index, node := range spec.Nodes {
		protocol := nodeDisplayProtocol(node)
		name := node.Property.Name
		if index == 0 {
			name += spec.entryLabel()
		}
		names = append(names, name)
		protocols = append(protocols, protocol)
		addresses = append(addresses, node.Property.Address)

	}
	terminal := spec.Nodes[len(spec.Nodes)-1]
	property := &dialer.Property{
		Name:            strings.Join(names, " -> "),
		Protocol:        strings.Join(protocols, " -> "),
		Address:         strings.Join(addresses, " -> "),
		Link:            runtimePathKey(spec, option),
		SubscriptionTag: terminal.Property.SubscriptionTag,
		Egress:          &api.NodeEgress{IPVersion: spec.IPVersion, Mark: spec.effectiveMark(option), Interface: spec.Entry.Interface},
		Selection:       spec.selectionReference(),
	}
	pool := s.shared
	if pool == nil {
		pool = &s.local
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	key := sharedPathKey(spec, option)
	if existing := pool.paths[key]; existing != nil {
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
	d, err := dialer.NewRecreatableDialer(func() (*netproxy.Runtime, error) {
		base, err := spec.entryDialer(option)
		if err != nil {
			return nil, err
		}
		return D.BuildRuntime(netproxy.Layer{Data: base}, &option.ExtraOption, builders...)
	}, option, property, statsScope)
	if err != nil {
		return nil, err
	}
	if pool.paths == nil {
		pool.paths = make(map[string]*dialer.Dialer)
	}
	pool.paths[key] = d
	return d, nil
}
