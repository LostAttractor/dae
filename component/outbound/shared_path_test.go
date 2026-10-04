// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
)

func TestBuildPathSharesEquivalentRuntime(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{
		{Name: "first", SubscriptionTag: "one", Link: testShadowsocksLink + "#first"},
		{Name: "second", SubscriptionTag: "two", Link: testShadowsocksLink + "#second"},
	})
	if err != nil {
		t.Fatal(err)
	}
	option := &dialer.GlobalOption{SoMarkFromDae: 0x100, CheckInterval: time.Minute}
	first, err := set.BuildPath(NodePath(set.nodeInfos[0]), option, "first-group")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	path := NodePath(set.nodeInfos[1])
	path.Entry.Mark = new(uint32(0x100))
	path.Annotation = &dialer.Annotation{Priority: 2, AddLatency: time.Second}
	otherOption := &dialer.GlobalOption{SoMarkFromDae: 0x100, CheckInterval: time.Minute, CheckTolerance: time.Second}
	second, err := set.BuildPath(path, otherOption, "second-group")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.Dialer != second.Dialer || first == second {
		t.Fatal("equivalent paths did not share a transport through distinct members")
	}
	if first.Name != "first" || second.Name != "second [mark=0x100]" || first.StatsID() == second.StatsID() {
		t.Fatal("sharing lost member presentation or statistics identity")
	}
	_ = first.Close()
	third, err := set.BuildPath(path, otherOption, "third-group")
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if third.Dialer != second.Dialer {
		t.Fatal("closing the registry's first member prevented reuse")
	}
	_ = second.Close()
	_ = third.Close()
	replacement, err := set.BuildPath(path, otherOption, "replacement")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if replacement.Dialer == first.Dialer {
		t.Fatal("new member reused a retired runtime")
	}
}

func TestBuildPathKeepsDifferentRuntimeConfigurationsSeparate(t *testing.T) {
	tests := []struct {
		name   string
		change func(*PathSpec, *dialer.GlobalOption)
	}{
		{"interface", func(p *PathSpec, _ *dialer.GlobalOption) { p.Entry.Interface = "cu" }},
		{"mark", func(p *PathSpec, _ *dialer.GlobalOption) { p.Entry.Mark = new(uint32(7)) }},
		{"family", func(p *PathSpec, _ *dialer.GlobalOption) { p.IPVersion = 6 }},
		{"chain", func(p *PathSpec, _ *dialer.GlobalOption) { p.Nodes = append(p.Nodes, p.Nodes[0]) }},
		{"tls", func(_ *PathSpec, o *dialer.GlobalOption) { o.AllowInsecure = true }},
		{"mptcp", func(_ *PathSpec, o *dialer.GlobalOption) { o.Mptcp = true }},
		{"bootstrap DNS", func(_ *PathSpec, o *dialer.GlobalOption) { o.DNSResolver = "127.0.0.2:53" }},
		{"check DNS", func(_ *PathSpec, o *dialer.GlobalOption) { o.CheckDnsOptionRaw.Raw = []string{"127.0.0.2:53"} }},
		{"check interval", func(_ *PathSpec, o *dialer.GlobalOption) { o.CheckInterval = 2 * time.Minute }},
		{"check backoff", func(_ *PathSpec, o *dialer.GlobalOption) { o.CheckIntervalMax = time.Hour }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set, err := NewDialerSet([]NodeDescriptor{{Link: testShadowsocksLink}})
			if err != nil {
				t.Fatal(err)
			}
			option := &dialer.GlobalOption{CheckInterval: time.Minute}
			first, err := set.BuildPath(NodePath(set.nodeInfos[0]), option, "first")
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			path := NodePath(set.nodeInfos[0])
			otherOption := &dialer.GlobalOption{CheckInterval: time.Minute}
			test.change(path, otherOption)
			second, err := set.BuildPath(path, otherOption, "second")
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if first.Dialer == second.Dialer {
				t.Fatal("different physical/check configuration shared a runtime")
			}
		})
	}
}

func TestBuildPathMultiplexConfigurationAndPlaneIsolation(t *testing.T) {
	descriptors := []NodeDescriptor{
		{Link: testShadowsocksLink},
		{Link: testShadowsocksLink, Options: config.NodeOptions{Multiplex: config.MultiplexModeSmux}},
		{Link: testShadowsocksLink, Options: config.NodeOptions{Multiplex: config.MultiplexModeSmux, MultiplexMaxConnections: new(uint16(8))}},
	}
	set, err := NewDialerSet(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	option := new(dialer.GlobalOption)
	var members []*dialer.Dialer
	for _, node := range set.nodeInfos {
		d, err := set.BuildPath(NodePath(node), option, t.Name())
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		for _, other := range members {
			if d.Dialer == other.Dialer {
				t.Fatal("different multiplex configurations shared a runtime")
			}
		}
		members = append(members, d)
	}
	// A reload prepares its own set before the old plane retires.
	reloaded, err := NewDialerSet(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := reloaded.BuildPath(NodePath(reloaded.nodeInfos[0]), option, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Close()
	if candidate.Dialer == members[0].Dialer || candidate.StatsID() != members[0].StatsID() {
		t.Fatal("reload must isolate runtimes while preserving member statistics identities")
	}
}

func TestBuildPathConcurrentSharing(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{{Link: testShadowsocksLink}})
	if err != nil {
		t.Fatal(err)
	}
	option := new(dialer.GlobalOption)
	const count = 16
	var members [count]*dialer.Dialer
	var workers sync.WaitGroup
	for i := range count {
		workers.Go(func() {
			var err error
			members[i], err = set.BuildPath(NodePath(set.nodeInfos[0]), option, t.Name())
			if err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	for _, member := range members {
		if member == nil {
			t.Fatal("missing member")
		}
		defer member.Close()
		if member.Dialer != members[0].Dialer {
			t.Fatal("concurrent builds created duplicate runtimes")
		}
	}
}

func TestBuildPathSeparatesCredentialsAndPhysicalHopOrder(t *testing.T) {
	set, err := NewDialerSet([]NodeDescriptor{
		{Link: "socks5://user:first@127.0.0.1:1080"},
		{Link: "socks5://user:second@127.0.0.1:1080"},
		{Link: "socks5://user:first@127.0.0.1:1081"},
		{Link: "http://user:first@127.0.0.1:1080"},
	})
	if err != nil {
		t.Fatal(err)
	}
	paths := []*PathSpec{
		NodePath(set.nodeInfos[0]), NodePath(set.nodeInfos[1]),
		NodePath(set.nodeInfos[2]), NodePath(set.nodeInfos[3]),
		{Nodes: []*NodeInfo{set.nodeInfos[0], set.nodeInfos[2]}},
		{Nodes: []*NodeInfo{set.nodeInfos[2], set.nodeInfos[0]}},
	}
	var members []*dialer.Dialer
	for _, path := range paths {
		member, err := set.BuildPath(path, new(dialer.GlobalOption), t.Name())
		if err != nil {
			t.Fatal(err)
		}
		defer member.Close()
		for _, previous := range members {
			if previous.Dialer == member.Dialer {
				t.Fatal("different credentials, protocols, endpoints or hop order shared a transport")
			}
		}
		members = append(members, member)
	}
}
