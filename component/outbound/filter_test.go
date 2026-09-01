/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	outboundDirect "github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/transport/smux"
)

func TestMain(m *testing.M) {
	outboundDirect.Direct = outboundDirect.NewDirectDialer(outboundDirect.Option{})
	os.Exit(m.Run())
}

type closeableTestDialer struct{ closed atomic.Bool }

func (*closeableTestDialer) Alive() bool    { return true }
func (*closeableTestDialer) Connect() error { return nil }
func (*closeableTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (*closeableTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (d *closeableTestDialer) Close() error {
	d.closed.Store(true)
	return nil
}

func TestNewDialerSetFromLinksParsesSIP002UserinfoForms(t *testing.T) {
	legacyUserinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:legacy-password"))
	shadowsocks2022 := url.URL{
		Scheme: "ss",
		User:   url.UserPassword("2022-blake3-aes-256-gcm", "RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o="),
		Host:   "127.0.0.1:443",
	}
	tests := []struct {
		name        string
		link        string
		credentials string
		address     string
		displayName string
		dialers     int
	}{
		{name: "legacy Base64URL", link: "ss://" + legacyUserinfo + "@127.0.0.1:443", credentials: "aes-256-gcm:legacy-password", address: "127.0.0.1:443", dialers: 1},
		{name: "AEAD 2022 percent-escaped", link: shadowsocks2022.String(), credentials: "2022-blake3-aes-256-gcm:RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o=", address: "127.0.0.1:443", dialers: 1},
		{name: "named AEAD 2022", link: "display-name:" + shadowsocks2022.String(), credentials: "2022-blake3-aes-256-gcm:RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o=", address: "127.0.0.1:443", displayName: "display-name", dialers: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, err := NewDialerSet([]NodeDescriptor{{Link: tt.link, SubscriptionTag: "test"}})
			if err != nil {
				t.Fatal(err)
			}
			if len(set.nodeInfos) != 1 {
				t.Fatalf("parsed %d nodes, want 1", len(set.nodeInfos))
			}
			nodeInfo := set.nodeInfos[0]
			if got := len(nodeInfo.Dialers); got != tt.dialers {
				t.Fatalf("dialers = %d, want %d", got, tt.dialers)
			}
			if got, want := nodeInfo.Property.Address, tt.address; got != want {
				t.Fatalf("address = %q, want %q", got, want)
			}
			if got := nodeInfo.Property.Name; got != tt.displayName {
				t.Fatalf("display name = %q, want %q", got, tt.displayName)
			}
			if nodeInfo.Link != tt.link {
				t.Fatalf("original link = %q, want %q", nodeInfo.Link, tt.link)
			}
			parsed, err := url.Parse(nodeInfo.Property.Link)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := base64.RawURLEncoding.DecodeString(parsed.User.Username())
			if err != nil {
				t.Fatal(err)
			}
			if got := string(credentials); got != tt.credentials {
				t.Fatalf("credentials = %q, want %q", got, tt.credentials)
			}
		})
	}
}

func TestNodeStatsIdentityIsStableAcrossReordering(t *testing.T) {
	nodes := []NodeDescriptor{
		{Name: "alias-a", Link: testShadowsocksLink, Options: config.NodeOptions{Multiplex: config.MultiplexModeOff}},
		{Name: "alias-b", Link: testShadowsocksLink, Options: config.NodeOptions{Multiplex: config.MultiplexModeSmux}},
	}
	identities := func(nodes []NodeDescriptor) map[string]string {
		set, err := NewDialerSet(nodes)
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[string]string, len(set.nodeInfos))
		for _, node := range set.nodeInfos {
			got[node.Property.Name] = NodePath(node).Identity()
		}
		return got
	}

	forward := identities(nodes)
	reversed := identities([]NodeDescriptor{nodes[1], nodes[0]})
	for name, identity := range forward {
		if reversed[name] != identity {
			t.Fatalf("identity for %q changed across reorder: %q != %q", name, identity, reversed[name])
		}
	}
}

func TestValidateNodeLinkRejectsHTMLErrorPage(t *testing.T) {
	if err := ValidateNodeLink(`<a href="https://example.com/help">service unavailable</a>`); err == nil {
		t.Fatal("HTML error page was accepted as a node")
	}
}

func TestValidateNodeLinkAcceptsSIP002PluginWithoutOptions(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:password"))
	link := "ss://" + userinfo + "@127.0.0.1:443/?plugin=v2ray-plugin"
	if err := ValidateNodeLink(link); err != nil {
		t.Fatalf("valid plugin-only link was rejected: %v", err)
	}
}

func TestNodeValidatorRejectsUnsupportedCipher(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("unsupported-cipher:password"))
	link := "ss://" + userinfo + "@127.0.0.1:8388"
	if err := ValidateNodeLink(link); err != nil {
		t.Fatalf("syntax validation unexpectedly failed: %v", err)
	}
	if err := NewNodeValidator(context.Background(), &config.Global{})(link); err == nil {
		t.Fatal("full validation accepted unsupported cipher")
	}
}

func TestNodeValidatorHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	validator := NewNodeValidator(ctx, &config.Global{})
	if err := validator("ss://unused"); !errors.Is(err, context.Canceled) {
		t.Fatalf("validator error = %v, want context cancellation", err)
	}
}

func TestCloseValidatedDialerRetiresTransport(t *testing.T) {
	transport := new(closeableTestDialer)
	created := dialer.NewDialer(
		netproxy.NewRuntime(netproxy.Layer{Data: transport, Resources: []io.Closer{transport}}),
		&dialer.GlobalOption{},
		&dialer.Property{},
		dialer.InitialCheckBlocking,
		"",
	)
	if err := closeValidatedDialer(created); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for !transport.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !transport.closed.Load() {
		t.Fatal("validated transport was not retired")
	}
}

func TestNodeValidatorBoundsPermanentlyBlockedConstruction(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, maxConcurrentNodeValidations)
	validate := func(*dialer.GlobalOption, string) error {
		started <- struct{}{}
		<-release
		return nil
	}
	validator := newNodeValidator(context.Background(), &dialer.GlobalOption{}, validate)
	var blocked sync.WaitGroup
	blocked.Add(maxConcurrentNodeValidations)
	for range maxConcurrentNodeValidations {
		go func() {
			defer blocked.Done()
			_ = validator("blocked")
		}()
	}
	for range maxConcurrentNodeValidations {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("validation worker did not start")
		}
	}

	var unexpected atomic.Int32
	for range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		queued := newNodeValidator(ctx, &dialer.GlobalOption{}, func(*dialer.GlobalOption, string) error {
			unexpected.Add(1)
			return nil
		})
		done := make(chan error, 1)
		go func() { done <- queued("queued") }()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("queued validation error = %v, want cancellation", err)
			}
		case <-time.After(time.Second):
			t.Fatal("queued validation ignored cancellation")
		}
	}
	if got := unexpected.Load(); got != 0 {
		t.Fatalf("started %d validations after all worker slots were blocked", got)
	}

	close(release)
	blocked.Wait()
	if got := len(nodeValidationSlots); got != 0 {
		t.Fatalf("validation slots still occupied after release: %d", got)
	}
}

type recordingBuilder struct {
	name  string
	order *[]string
}

type closeTrackingDialer struct {
	netproxy.Dialer
	closed *atomic.Int32
}

func (d *closeTrackingDialer) Close() error {
	d.closed.Add(1)
	return nil
}

type closeTrackingBuilder struct {
	closed *atomic.Int32
}

func (b *closeTrackingBuilder) Build(_ *D.ExtraOption, upstream D.Upstream) (netproxy.Layer, error) {
	d := &closeTrackingDialer{Dialer: upstream, closed: b.closed}
	return netproxy.Layer{Data: d, Resources: []io.Closer{d}}, nil
}

type failingBuilder struct{}

func (*failingBuilder) Build(_ *D.ExtraOption, _ D.Upstream) (netproxy.Layer, error) {
	return netproxy.Layer{}, errors.New("build failed")
}

func (b *recordingBuilder) Build(_ *D.ExtraOption, upstream D.Upstream) (netproxy.Layer, error) {
	*b.order = append(*b.order, b.name)
	return netproxy.Layer{Data: upstream}, nil
}

func TestBuildPathUsesPhysicalHopOrder(t *testing.T) {
	var order []string
	entry := &NodeInfo{
		Link:     "entry://node",
		Property: &dialer.Property{Property: D.Property{Name: "entry", Link: "entry://node"}},
		Dialers:  []D.Builder{&recordingBuilder{name: "entry", order: &order}},
	}
	exit := &NodeInfo{
		Link:     "exit://node",
		Property: &dialer.Property{Property: D.Property{Name: "exit", Link: "exit://node"}},
		Dialers:  []D.Builder{&recordingBuilder{name: "exit", order: &order}},
	}
	set := new(DialerSet)
	option := new(dialer.GlobalOption)
	d, err := set.BuildPath(&PathSpec{
		Nodes:      []*NodeInfo{entry, exit},
		Annotation: &dialer.Annotation{},
	}, option, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.Close()
	})
	if len(order) != 2 || order[0] != "entry" || order[1] != "exit" {
		t.Fatalf("builder order = %v, want [entry exit]", order)
	}
	if d.Name != "entry -> exit" {
		t.Fatalf("path name = %q, want %q", d.Name, "entry -> exit")
	}
}

func TestBuildPathIdentityIncludesRuntimeOptions(t *testing.T) {
	node := &NodeInfo{
		Link:     "test://node",
		Property: &dialer.Property{Property: D.Property{Name: "node", Link: "test://node"}},
	}
	set := &DialerSet{}
	firstOption := &dialer.GlobalOption{}
	secondOption := &dialer.GlobalOption{}
	secondOption.AllowInsecure = true
	first, err := set.BuildPath(NodePath(node), firstOption, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.BuildPath(NodePath(node), secondOption, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})
	if first.StatsKey() == second.StatsKey() {
		t.Fatalf("runtime option change retained stats identity %q", first.StatsKey())
	}
}

func TestBuildPathCreatesOwnerScopedRuntime(t *testing.T) {
	node := &NodeInfo{
		Link:     "test://node",
		Property: &dialer.Property{Property: D.Property{Name: "node", Link: "test://node"}},
	}
	set := new(DialerSet)
	option := new(dialer.GlobalOption)
	first, err := set.BuildPath(NodePath(node), option, "first-owner")
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.BuildPath(NodePath(node), option, "second-owner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})
	if first.StatsKey() == second.StatsKey() {
		t.Fatal("different owners shared one stats identity")
	}
}

func TestBuildPathClosesPartialRuntimeOnFailure(t *testing.T) {
	var closed atomic.Int32
	node := &NodeInfo{
		Link:     "test://node",
		Property: &dialer.Property{Property: D.Property{Name: "node", Link: "test://node"}},
		Dialers: []D.Builder{
			&closeTrackingBuilder{closed: &closed},
			new(failingBuilder),
		},
	}
	set := &DialerSet{}
	if _, err := set.BuildPath(NodePath(node), &dialer.GlobalOption{}, t.Name()); err == nil {
		t.Fatal("BuildPath succeeded with a failing builder")
	}
	if got := closed.Load(); got != 1 {
		t.Fatalf("partial runtime close count = %d, want 1", got)
	}
}

func TestNewDialerSetLegacyChainErrorPolicy(t *testing.T) {
	for _, chain := range []string{"first://node -> second://node", "first://node->second://node"} {
		if _, err := NewDialerSet([]NodeDescriptor{{Link: chain, Required: true}}); err == nil || !strings.Contains(err.Error(), "legacy share-link proxy chains") {
			t.Fatalf("local chain %q error = %v", chain, err)
		}
	}
	chain := "first://node -> second://node"
	set, err := NewDialerSet([]NodeDescriptor{{Link: chain}})
	if err != nil {
		t.Fatalf("subscription chain returned fatal error: %v", err)
	}
	if len(set.nodeInfos) != 0 {
		t.Fatalf("subscription chain produced %d nodes", len(set.nodeInfos))
	}
}

func TestNewDialerSetRejectsReservedNodeNames(t *testing.T) {
	if _, err := NewDialerSet([]NodeDescriptor{{
		Name: "direct", Link: testShadowsocksLink, Required: true,
	}}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("local reserved-name error = %v", err)
	}

	set, err := NewDialerSet([]NodeDescriptor{{Link: testShadowsocksLink + "#block"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.nodeInfos) != 0 {
		t.Fatalf("reserved subscription node was retained: %d nodes", len(set.nodeInfos))
	}
}

func TestPathBuildErrorRetainsNodeRequirement(t *testing.T) {
	node := &NodeInfo{
		Property: &dialer.Property{Property: D.Property{Name: "optional"}},
		Dialers:  []D.Builder{new(failingBuilder)},
	}
	_, err := new(DialerSet).BuildPath(NodePath(node), &dialer.GlobalOption{}, t.Name())
	var buildErr *PathBuildError
	if !errors.As(err, &buildErr) || buildErr.Node != node || buildErr.Node.Required {
		t.Fatalf("path build error = %#v, want optional node", err)
	}
}

const testShadowsocksLink = "ss://YWVzLTEyOC1nY206cGFzcw@proxy.example.com:443"

func descriptorFilter(name string, params ...*config_parser.Param) []*config_parser.Function {
	return []*config_parser.Function{{Name: name, Params: params}}
}

func nodeOptionBool(value bool) *bool { return &value }

func nodeOptionUint16(value uint16) *uint16 { return &value }

func TestNewDialerSetAppliesSubscriptionOptionsInOrder(t *testing.T) {
	nodes := []NodeDescriptor{{
		Link:            testShadowsocksLink + "#HK-legacy",
		SubscriptionTag: "my_sub",
		Defaults: config.NodeOptions{
			Multiplex:  config.MultiplexModeOff,
			CheckAsync: nodeOptionBool(true),
		},
		Rules: []config.NodeOptionRule{
			{
				Filter: []*config_parser.Function{
					{Name: FilterInput_Protocol, Params: []*config_parser.Param{{Val: "shadowsocks"}}},
					{Name: FilterInput_Name, Params: []*config_parser.Param{{Key: "regex", Val: "^HK"}}},
				},
				Options: config.NodeOptions{
					Multiplex:  config.MultiplexModeSmux,
					CheckAsync: nodeOptionBool(false),
				},
			},
			{
				Filter: descriptorFilter(FilterInput_Name, &config_parser.Param{Val: "HK-legacy"}),
				Options: config.NodeOptions{
					Multiplex:  config.MultiplexModeOff,
					CheckAsync: nodeOptionBool(true),
				},
			},
		},
	}}
	set, err := NewDialerSet(nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.nodeInfos) != 1 {
		t.Fatalf("nodes = %d, want 1", len(set.nodeInfos))
	}
	node := set.nodeInfos[0]
	if len(node.Dialers) != 1 {
		t.Fatalf("dialer layers = %d, want 1", len(node.Dialers))
	}
	if !strings.Contains(node.Property.Link, "multiplex=off") {
		t.Fatalf("node identity does not include effective options: %q", node.Property.Link)
	}
	if !node.CheckAsync || strings.Contains(node.Property.Link, "check_async") {
		t.Fatalf("effective check_async or identity = %+v, %q", node.CheckAsync, node.Property.Link)
	}
}

func TestInlineNodeOptionsOverrideSubscriptionRules(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{{
		Link: testShadowsocksLink + "#HK",
		Rules: []config.NodeOptionRule{{
			Filter: descriptorFilter(FilterInput_Name, &config_parser.Param{Val: "HK"}),
			Options: config.NodeOptions{
				Multiplex:  config.MultiplexModeOff,
				CheckAsync: nodeOptionBool(true),
			},
		}},
		Options: config.NodeOptions{
			Multiplex:  config.MultiplexModeSmuxUDPPassthrough,
			CheckAsync: nodeOptionBool(false),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	node := set.nodeInfos[0]
	if !strings.Contains(node.Property.Link, "multiplex=smux-udp-passthrough") {
		t.Fatalf("node identity does not include effective options: %q", node.Property.Link)
	}
	if len(node.Dialers) != 2 {
		t.Fatalf("dialer layers = %d, want 2", len(node.Dialers))
	}
	smuxConfig, ok := node.Dialers[1].(*smux.SmuxConfig)
	if !ok {
		t.Fatalf("second dialer layer = %T, want *smux.SmuxConfig", node.Dialers[1])
	}
	if !smuxConfig.PassThroughUDP {
		t.Fatal("smux UDP passthrough is disabled")
	}
	if smuxConfig.MaxConnections != smux.DefaultMaxConnections {
		t.Fatalf("smux max connections = %d, want default %d", smuxConfig.MaxConnections, smux.DefaultMaxConnections)
	}
	if node.CheckAsync {
		t.Fatal("inline check_async=false did not override the subscription rule")
	}
	d, err := set.BuildPath(NodePath(node), new(dialer.GlobalOption), t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.Close()
	})
	if got, want := d.Protocol, "shadowsocks(smux/udp-pass)"; got != want {
		t.Fatalf("path protocol = %q, want %q", got, want)
	}
	if d.InitialCheckMode() == dialer.InitialCheckAsync {
		t.Fatal("overridden check_async was applied to the built path")
	}
}

func TestBuildPathEnablesCheckAsyncWhenAnyHopRequestsIt(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{
		{Name: "entry", Link: testShadowsocksLink + "#entry", Options: config.NodeOptions{CheckAsync: nodeOptionBool(true)}},
		{Name: "exit", Link: testShadowsocksLink + "#exit", Options: config.NodeOptions{CheckAsync: nodeOptionBool(false)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := set.BuildPath(&PathSpec{Nodes: set.nodeInfos, Annotation: &dialer.Annotation{}}, new(dialer.GlobalOption), t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.Close()
	})
	if d.InitialCheckMode() != dialer.InitialCheckAsync {
		t.Fatal("a later check_async=false hop disabled an asynchronous path")
	}
}

func TestCheckAsyncDoesNotChangeNodeIdentity(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{
		{Name: "same", Link: testShadowsocksLink, Options: config.NodeOptions{CheckAsync: nodeOptionBool(true)}},
		{Name: "same", Link: testShadowsocksLink, Options: config.NodeOptions{CheckAsync: nodeOptionBool(false)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first, second := NodePath(set.nodeInfos[0]).Identity(), NodePath(set.nodeInfos[1]).Identity(); first != second {
		t.Fatalf("check_async changed node identity: %q != %q", first, second)
	}
}

func TestNodeIdentityIncludesEffectiveOptions(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{
		{Link: testShadowsocksLink + "#HK", Options: config.NodeOptions{Multiplex: config.MultiplexModeOff}},
		{Link: testShadowsocksLink + "#HK", Options: config.NodeOptions{Multiplex: config.MultiplexModeSmux}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.nodeInfos) != 2 {
		t.Fatalf("node identity collapsed distinct options: set contains %d nodes", len(set.nodeInfos))
	}
	if set.nodeInfos[0].Property.Link == set.nodeInfos[1].Property.Link {
		t.Fatalf("effective links are equal: %q", set.nodeInfos[0].Property.Link)
	}
	option := &dialer.GlobalOption{}
	first, err := set.BuildPath(NodePath(set.nodeInfos[0]), option, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.BuildPath(NodePath(set.nodeInfos[1]), option, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})
	if first.StatsKey() == second.StatsKey() {
		t.Fatalf("effective options share stats identity %q", first.StatsKey())
	}
	if got, want := second.Protocol, "shadowsocks(smux)"; got != want {
		t.Fatalf("multiplexed path protocol = %q, want %q", got, want)
	}
}

func TestNodeIdentityIncludesMultiplexConnections(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{
		{Link: testShadowsocksLink + "#HK", Options: config.NodeOptions{
			Multiplex:               config.MultiplexModeSmux,
			MultiplexMaxConnections: nodeOptionUint16(4),
		}},
		{Link: testShadowsocksLink + "#HK", Options: config.NodeOptions{
			Multiplex:               config.MultiplexModeSmux,
			MultiplexMaxConnections: nodeOptionUint16(10),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if set.nodeInfos[0].Property.Link == set.nodeInfos[1].Property.Link {
		t.Fatal("different smux connection limits share a node identity")
	}
	config, ok := set.nodeInfos[1].Dialers[1].(*smux.SmuxConfig)
	if !ok {
		t.Fatalf("second dialer layer = %T, want *smux.SmuxConfig", set.nodeInfos[1].Dialers[1])
	}
	if config.MaxConnections != 10 {
		t.Fatalf("smux max connections = %d, want 10", config.MaxConnections)
	}
}

func TestMultiplexConnectionsRequireSmux(t *testing.T) {
	_, err := NewDialerSet([]NodeDescriptor{{
		Link: testShadowsocksLink,
		Options: config.NodeOptions{
			Multiplex:               config.MultiplexModeOff,
			MultiplexMaxConnections: nodeOptionUint16(4),
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "multiplex_max_connections requires") {
		t.Fatalf("NewDialerSet error = %v, want multiplex_max_connections validation", err)
	}
}

func TestMultiplexConnectionsRejectInvalidProgrammaticValues(t *testing.T) {
	for _, connections := range []uint16{0, smux.MaxConnectionsLimit + 1} {
		_, err := NewDialerSet([]NodeDescriptor{{
			Link: testShadowsocksLink,
			Options: config.NodeOptions{
				Multiplex:               config.MultiplexModeSmux,
				MultiplexMaxConnections: nodeOptionUint16(connections),
			},
		}})
		if err == nil || !strings.Contains(err.Error(), "multiplex_max_connections must be between") {
			t.Fatalf("connections %d: NewDialerSet error = %v, want range validation", connections, err)
		}
	}
}

func TestNodeIdentityIncludesConfiguredName(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{
		{Name: "alias-a", Link: testShadowsocksLink + "#same-link"},
		{Name: "alias-b", Link: testShadowsocksLink + "#same-link"},
	})
	if err != nil {
		t.Fatal(err)
	}
	option := &dialer.GlobalOption{}
	first, err := set.BuildPath(NodePath(set.nodeInfos[0]), option, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.BuildPath(NodePath(set.nodeInfos[1]), option, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})
	if first.StatsKey() == second.StatsKey() {
		t.Fatalf("node aliases share stats identity %q", first.StatsKey())
	}
	if first.Hops[0].ID == second.Hops[0].ID {
		t.Fatalf("node aliases share hop identity %q", first.Hops[0].ID)
	}
}

func TestGroupFilterSupportsDescriptorFields(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{{Link: testShadowsocksLink + "#HK"}})
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := set.Filter([]*config_parser.Function{
		{Name: FilterInput_Protocol, Params: []*config_parser.Param{{Val: "shadowsocks"}}},
		{Name: FilterInput_Link, Params: []*config_parser.Param{{Key: "keyword", Val: "proxy.example.com"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 {
		t.Fatalf("filtered nodes = %d, want 1", len(filtered))
	}
}

func TestGroupFilterRejectsNodeReferenceFunction(t *testing.T) {
	set := new(DialerSet)
	_, err := set.Filter([]*config_parser.Function{{
		Name: "node", Params: []*config_parser.Param{{Val: "HK"}},
	}})
	if err == nil || !strings.Contains(err.Error(), `unsupported filter input type: "node"`) {
		t.Fatalf("node property filter error = %v", err)
	}
}

func TestDescriptorRuleRejectsInvalidRegexp(t *testing.T) {
	_, err := NewDialerSet([]NodeDescriptor{{
		Link: testShadowsocksLink,
		Rules: []config.NodeOptionRule{{
			Filter:  descriptorFilter(FilterInput_Name, &config_parser.Param{Key: "regex", Val: "["}),
			Options: config.NodeOptions{Multiplex: config.MultiplexModeOff},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "bad regexp") {
		t.Fatalf("invalid descriptor regexp error = %v", err)
	}
}

func TestDescriptorRuleRejectsUnsupportedFilterKey(t *testing.T) {
	_, err := NewDialerSet([]NodeDescriptor{{
		Link: testShadowsocksLink,
		Rules: []config.NodeOptionRule{{
			Filter:  descriptorFilter(FilterInput_Name, &config_parser.Param{Key: "unknown", Val: "HK"}),
			Options: config.NodeOptions{Multiplex: config.MultiplexModeOff},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), `unsupported filter key "unknown"`) {
		t.Fatalf("unsupported descriptor filter key error = %v", err)
	}
}
