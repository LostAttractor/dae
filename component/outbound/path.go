/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/selector"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PathSpec struct {
	Nodes         []*NodeInfo // Physical order: first proxy to final proxy.
	Annotation    *dialer.Annotation
	Entry         EntryOptions
	IPVersion     int  // Physical entrance family; 0 before variant expansion.
	showIPVersion bool // Display a family suffix only for a split dual-stack path.
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
