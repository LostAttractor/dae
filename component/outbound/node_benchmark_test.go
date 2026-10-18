// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/dae/pkg/outbound/dialer"
)

// Local synthetic links exercise construction without connecting to a server.
// Preparation includes subscription validation and one selected physical path;
// DNS family discovery and connectivity checks are outside these measurements.
func BenchmarkNodePreparation(b *testing.B) {
	for _, node := range []struct{ name, link string }{
		{"socks", "socks5://user:password@127.0.0.1:9#bench"},
		{"shadowsocks", "ss://aes-256-gcm:password@127.0.0.1:9#bench"},
		{"trojan", "trojan://password@127.0.0.1:9?sni=bench.test#bench"},
		{"hysteria2", "hysteria2://password@127.0.0.1:9?sni=bench.test#bench"},
	} {
		b.Run(node.name, func(b *testing.B) {
			option := dialer.NewGlobalOption(new(config.Global))
			b.Run("parse", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, _, err := D.NewFromLink(node.link); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("validate", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if err := validateNodeDialer(option, node.link); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("prepare", func(b *testing.B) {
				validate := NewNodeValidator(b.Context(), new(config.Global))
				descriptors := []NodeDescriptor{{Link: node.link, Required: true}}
				b.ReportAllocs()
				for b.Loop() {
					if err := validate(node.link); err != nil {
						b.Fatal(err)
					}
					set, err := NewDialerSet(descriptors)
					if err != nil {
						b.Fatal(err)
					}
					client, err := set.BuildPath(NodePath(set.nodeInfos[0]), option, "benchmark")
					if err != nil {
						b.Fatal(err)
					}
					if err := client.Close(); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
