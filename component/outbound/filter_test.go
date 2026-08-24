/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
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
	"github.com/daeuniverse/outbound/transport/smux"
)

type testNodeDescriptor func(netproxy.Dialer) (netproxy.Dialer, error)

func (f testNodeDescriptor) Dialer(_ *D.ExtraOption, parent netproxy.Dialer) (netproxy.Dialer, error) {
	return f(parent)
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
	secondShadowsocks2022 := url.URL{
		Scheme: "ss",
		User:   url.UserPassword("2022-blake3-aes-128-gcm", "c2Vjb25kLXBhc3N3b3Jk"),
		Host:   "127.0.0.2:8443",
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
		{name: "chained AEAD 2022", link: shadowsocks2022.String() + " -> " + secondShadowsocks2022.String(), credentials: "2022-blake3-aes-128-gcm:c2Vjb25kLXBhc3N3b3Jk", address: "127.0.0.2:8443", dialers: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, err := NewDialerSet(&dialer.GlobalOption{}, nil, []NodeDescriptor{{Link: tt.link, SubscriptionTag: "test"}})
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

func TestDuplicateAndAliasNodesHaveDistinctStatsIdentity(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:password"))
	link := "ss://" + userinfo + "@127.0.0.1:443"
	set, err := NewDialerSet(&dialer.GlobalOption{}, nil, []NodeDescriptor{
		{Link: "alias-a:" + link, SubscriptionTag: "test", SourceIndex: 0},
		{Link: "alias-b:" + link, SubscriptionTag: "test", SourceIndex: 1},
		{Link: "alias-b:" + link, SubscriptionTag: "test", SourceIndex: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })

	dialers, _, err := set.FilterAndAnnotate(nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(dialers) != 3 {
		t.Fatalf("dialers = %d, want 3", len(dialers))
	}
	keys := make(map[string]struct{}, len(dialers))
	ids := make(map[string]struct{}, len(dialers))
	for _, d := range dialers {
		keys[d.StatsKey()] = struct{}{}
		ids[d.StatsID()] = struct{}{}
	}
	if len(keys) != len(dialers) || len(ids) != len(dialers) {
		t.Fatalf("stats identities were merged: keys=%d ids=%d dialers=%d", len(keys), len(ids), len(dialers))
	}
}

func TestNodeStatsIdentityIsStableAcrossReordering(t *testing.T) {
	nodes := []NodeDescriptor{
		{Name: "alias-a", Link: testShadowsocksLink, Options: config.NodeOptions{Multiplex: config.MultiplexModeOff}},
		{Name: "alias-b", Link: testShadowsocksLink, Options: config.NodeOptions{Multiplex: config.MultiplexModeSmux}},
	}
	identities := func(nodes []NodeDescriptor) map[string]string {
		set, err := NewDialerSet(&dialer.GlobalOption{}, nil, nodes)
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[string]string, len(set.nodeInfos))
		for _, node := range set.nodeInfos {
			got[node.Property.Name] = node.Property.StatsIdentity
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

func TestNodeDialerClosesPartiallyConstructedTransport(t *testing.T) {
	transport := new(closeableTestDialer)
	buildErr := errors.New("construction failed")
	node := &NodeInfo{
		Property: &dialer.Property{},
		Dialers: []D.Dialer{
			testNodeDescriptor(func(netproxy.Dialer) (netproxy.Dialer, error) { return transport, nil }),
			testNodeDescriptor(func(netproxy.Dialer) (netproxy.Dialer, error) { return nil, buildErr }),
		},
	}
	if _, err := node.createDialerIfNeeded(&dialer.GlobalOption{}, nil); !errors.Is(err, buildErr) {
		t.Fatalf("createDialerIfNeeded error = %v, want %v", err, buildErr)
	}
	if !transport.closed.Load() {
		t.Fatal("partially constructed transport was not closed")
	}
}

func TestCloseValidatedDialerRetiresTransport(t *testing.T) {
	transport := new(closeableTestDialer)
	created := dialer.NewDialer(
		netproxy.NewRuntime(transport),
		&dialer.GlobalOption{},
		&dialer.Property{},
		true,
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

func (b *recordingBuilder) Dialer(_ *D.ExtraOption, parent netproxy.Dialer) (netproxy.Dialer, error) {
	*b.order = append(*b.order, b.name)
	return parent, nil
}

func TestCreateNextHopDialerBuildsNextHopBeforeSource(t *testing.T) {
	var order []string
	source := &NodeInfo{
		Link:     "source://node",
		Property: &dialer.Property{Property: D.Property{Name: "source", Link: "source://node"}},
		Dialers:  []D.Dialer{&recordingBuilder{name: "source", order: &order}},
	}
	nextHop := &NodeInfo{
		Link:     "next://hop",
		Property: &dialer.Property{Property: D.Property{Name: "next", Link: "next://hop"}},
		Dialers:  []D.Dialer{&recordingBuilder{name: "next", order: &order}},
	}
	set := &DialerSet{
		option:       &dialer.GlobalOption{},
		nodeInfosMap: make(map[dialer.Property]*NodeInfo),
	}
	d, err := set.createNextHopDialer(source, nextHop)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.Close()
		d.RetireTransport()
	})
	if len(order) != 2 || order[0] != "next" || order[1] != "source" {
		t.Fatalf("builder order = %v, want [next source]", order)
	}
}

func TestFilterAndAnnotateBuildsOnlyComposedNextHop(t *testing.T) {
	var order []string
	source := &NodeInfo{
		Link:     "source://node",
		Property: &dialer.Property{Property: D.Property{Name: "source", Link: "source://node"}},
		Dialers:  []D.Dialer{&recordingBuilder{name: "source", order: &order}},
	}
	nextHop := &NodeInfo{
		Link:     "next://hop",
		Property: &dialer.Property{Property: D.Property{Name: "next", Link: "next://hop"}},
		Dialers:  []D.Dialer{&recordingBuilder{name: "next", order: &order}},
	}
	set := &DialerSet{
		option:       &dialer.GlobalOption{},
		nodeInfos:    []*NodeInfo{source, nextHop},
		nodeInfosMap: map[dialer.Property]*NodeInfo{*source.Property: source, *nextHop.Property: nextHop},
	}
	t.Cleanup(func() { _ = set.Close() })

	filters := [][]*config_parser.Function{{{
		Name:   FilterInput_Name,
		Params: []*config_parser.Param{{Val: "source"}},
	}}}
	dialers, _, err := set.FilterAndAnnotate(filters, [][]*config_parser.Param{nil}, "next")
	if err != nil {
		t.Fatal(err)
	}
	if len(dialers) != 1 {
		t.Fatalf("created %d dialers, want 1", len(dialers))
	}
	if source.CreatedDialer != nil {
		t.Fatal("created unused standalone source runtime")
	}
	if len(order) != 2 || order[0] != "next" || order[1] != "source" {
		t.Fatalf("builder order = %v, want [next source]", order)
	}
}

const testShadowsocksLink = "ss://YWVzLTEyOC1nY206cGFzcw@proxy.example.com:443"

func nodeFilter(name string, params ...*config_parser.Param) []*config_parser.Function {
	return []*config_parser.Function{{Name: name, Params: params}}
}

func TestNewDialerSetAppliesSubscriptionOptionsInOrder(t *testing.T) {
	nodes := []NodeDescriptor{{
		Link:            testShadowsocksLink + "#HK-legacy",
		SubscriptionTag: "my_sub",
		Defaults:        config.NodeOptions{Multiplex: config.MultiplexModeOff},
		Rules: []config.NodeOptionRule{
			{
				Filter: []*config_parser.Function{
					{Name: FilterInput_Protocol, Params: []*config_parser.Param{{Val: "shadowsocks"}}},
					{Name: FilterInput_Name, Params: []*config_parser.Param{{Key: "regex", Val: "^HK"}}},
				},
				Options: config.NodeOptions{Multiplex: config.MultiplexModeSmux},
			},
			{
				Filter:  nodeFilter(FilterInput_Name, &config_parser.Param{Val: "HK-legacy"}),
				Options: config.NodeOptions{Multiplex: config.MultiplexModeOff},
			},
		},
	}}
	set, err := NewDialerSet(&dialer.GlobalOption{}, nil, nodes)
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
}

func TestInlineNodeOptionsOverrideSubscriptionRules(t *testing.T) {
	set, err := NewDialerSet(&dialer.GlobalOption{}, nil, []NodeDescriptor{{
		Link: testShadowsocksLink + "#HK",
		Rules: []config.NodeOptionRule{{
			Filter:  nodeFilter(FilterInput_Name, &config_parser.Param{Val: "HK"}),
			Options: config.NodeOptions{Multiplex: config.MultiplexModeOff},
		}},
		Options: config.NodeOptions{Multiplex: config.MultiplexModeSmuxUDPPassthrough},
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
}

func TestMultiplexIsInsertedAfterChainEndpoint(t *testing.T) {
	set, err := NewDialerSet(&dialer.GlobalOption{}, nil, []NodeDescriptor{{
		Link:    testShadowsocksLink + " -> socks5://localhost:1080",
		Options: config.NodeOptions{Multiplex: config.MultiplexModeSmux},
	}})
	if err != nil {
		t.Fatal(err)
	}
	builders := set.nodeInfos[0].Dialers
	if len(builders) != 3 {
		t.Fatalf("dialer layers = %d, want 3", len(builders))
	}
	smuxConfig, ok := builders[1].(*smux.SmuxConfig)
	if !ok {
		t.Fatalf("second dialer layer = %T, want endpoint smux", builders[1])
	}
	if smuxConfig.PassThroughUDP {
		t.Fatal("plain smux unexpectedly enables UDP passthrough")
	}
}

func TestNodeIdentityIncludesEffectiveOptions(t *testing.T) {
	set, err := NewDialerSet(&dialer.GlobalOption{}, nil, []NodeDescriptor{
		{Link: testShadowsocksLink + "#HK", Options: config.NodeOptions{Multiplex: config.MultiplexModeOff}},
		{Link: testShadowsocksLink + "#HK", Options: config.NodeOptions{Multiplex: config.MultiplexModeSmux}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.nodeInfosMap) != 2 {
		t.Fatalf("node identity collapsed distinct options: map contains %d nodes", len(set.nodeInfosMap))
	}
	if set.nodeInfos[0].Property.Link == set.nodeInfos[1].Property.Link {
		t.Fatalf("effective links are equal: %q", set.nodeInfos[0].Property.Link)
	}
}
