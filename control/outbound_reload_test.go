// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
)

func TestReloadReusesGroupsAndSharesUnchangedPaths(t *testing.T) {
	runtime := NewRuntime()
	build := func(policy string) (*outboundBuilder, context.CancelFunc) {
		t.Helper()
		conf := outboundUsageConfig(t, `global {}
node { one: 'socks5://127.0.0.1:1080' two: 'socks5://127.0.0.1:1081' }
group { stable { node(one) policy: selector } changed { node(one) policy: `+policy+` } }
routing { dport(80) -> stable fallback: changed }`)
		ctx, cancel := context.WithCancel(t.Context())
		core := &controlPlaneCore{closed: ctx, bpf: &BPFState{Runtime: runtime}}
		builder, err := core.buildOutbounds(t.Context(), outboundUsageNodes(conf), conf.Group, &conf.Routing, &conf.Global, consts.OutboundBlock)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); _ = builder.close() })
		return builder, cancel
	}
	find := func(b *outboundBuilder, name string) *outbound.DialerGroup { return b.outbounds[b.nameToID[name]] }
	first, stopFirst := build("fixed(0)")
	stable, changed := find(first, "stable"), find(first, "changed")
	next, _ := build("random")
	if find(next, "stable") != stable || find(next, "changed") == changed {
		t.Fatal("reload did not preserve precisely the unchanged groups")
	}
	if !changed.Dialers[0].SharesRuntime(find(next, "changed").Dialers[0]) {
		t.Fatal("policy change reconstructed an unchanged transport")
	}
	abandoned, _ := build("random")
	if err := abandoned.close(); err != nil {
		t.Fatal(err)
	}
	stopFirst()
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	if err := stable.SetSelection(stable.Dialers[0].StatsID()); err != nil {
		t.Fatalf("retirement closed the reused selector: %v", err)
	}
	if release, err := stable.Dialers[0].Retain(); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	// A live projection still receives updates after the old core stopped.
	detach, err := stable.ObserveConnectivity(func(_ bool, _ *common.NetworkType) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	detach()
	if err := next.close(); err != nil {
		t.Fatal(err)
	}
	if stable.Dialers[0].CanShare() {
		t.Fatal("last group release kept an unused path alive")
	}
}
