// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"fmt"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"testing"
)

func BenchmarkSubscriptionOptions(b *testing.B) {
	rules := []config.NodeOptionRule{{Filter: []*config_parser.Function{{Name: "name", Params: []*config_parser.Param{{Key: "regex", Val: "^node-(?:[0-9]+)$"}}}}}}
	nodes := make([]NodeDescriptor, 1000)
	for i := range nodes {
		nodes[i] = NodeDescriptor{Name: fmt.Sprintf("node-%d", i), Link: "socks5://127.0.0.1:1080", Rules: rules}
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NewDialerSet(nodes); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRepeatedRoutableExpansion(b *testing.B) {
	set := &DialerSet{}
	for i := range 32 {
		set.nodeInfos = append(set.nodeInfos, testNode(fmt.Sprintf("node%d", i), "all"))
	}
	groups := []config.Group{{Name: "proxy", Policy: randomPolicy(), Paths: []*config_parser.ProxyPath{proxyPath(subtagStage("all"), subtagStage("all"))}}}
	b.ReportAllocs()
	for b.Loop() {
		compiler, err := NewGroupCompiler(set, groups, []string{"proxy"})
		if err != nil {
			b.Fatal(err)
		}
		for range 2 {
			if _, err := compiler.ExpandRoutable(&groups[0]); err != nil {
				b.Fatal(err)
			}
		}
	}
}
