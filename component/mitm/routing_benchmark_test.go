// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"fmt"
	"testing"

	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/plugin"
)

// One plugin may contain many independently scoped modules. Measure plan
// construction and the worst-case lookup separately from HTTP and socket I/O.
func BenchmarkHTTPScopes(b *testing.B) {
	for _, size := range []int{1, 64, 256} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			plan := plugin.Plan{}
			for i := range size {
				plan.Scopes = append(plan.Scopes, plugin.HTTPScope{Scope: testScope(fmt.Sprintf("module%d.example", i))})
			}
			instance := Instance{Plugin: &testPlugin{plan: plan}}
			options := Options{Authority: &localca.Authority{}}
			b.Run("build", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					host, err := New(options, instance)
					if err != nil {
						b.Fatal(err)
					}
					host.forceCancel()
				}
			})
			host, err := New(options, instance)
			if err != nil {
				b.Fatal(err)
			}
			defer host.forceCancel()
			b.Run("miss", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if host.Match("outside.test", 443) != HTTPBypass {
						b.Fatal("unexpected match")
					}
				}
			})
		})
	}
}
