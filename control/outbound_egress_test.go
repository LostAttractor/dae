// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
)

func TestMaterializeEntryFamiliesAndDefaultPolicy(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("dual-stack materialization requires local IPv6: %v", err)
	}
	_ = probe.Close()
	conf := outboundUsageConfig(t, `global {}
node { entry: 'socks5://localhost:1080' }
group {
 automatic { node(entry) }
 v4 { filter: name(entry) && ipversion(4) [mark: 0, interface: lo] }
 fixed { node(entry)
         policy: fixed(1) }
}
routing {
 dport(1) -> entry
 dport(2) -> automatic
 dport(3) -> v4
 fallback: fixed
}`)
	core := &controlPlaneCore{closed: t.Context()}
	b, err := core.buildOutbounds(t.Context(), outboundUsageNodes(conf), conf.Group, &conf.Routing, &conf.Global, consts.OutboundBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDialerGroups(b.outbounds)
	for _, group := range b.outbounds {
		if group.TargetKind == outbound.TargetKindBuiltin {
			continue
		}
		want := 2
		if group.Name == "v4" {
			want = 1
		}
		if len(group.Dialers) != want {
			t.Fatalf("%s: candidates = %d, want %d", group.Name, len(group.Dialers), want)
		}
		if group.Name == "automatic" && group.DisplayPolicy() != "min_moving_avg" {
			t.Fatalf("implicit family policy = %q", group.DisplayPolicy())
		}
		if group.Name == "fixed" && group.DisplayPolicy() != "fixed" {
			t.Fatal("explicit policy was replaced")
		}
		if group.Name == "v4" {
			entry := group.Dialers[0].Egress
			if entry.IPVersion != 4 || entry.Mark != 0 || entry.Interface != "lo" {
				t.Fatalf("entry metadata = %+v", entry)
			}
		} else if group.Dialers[0].Egress.IPVersion != 4 || group.Dialers[1].Egress.IPVersion != 6 || group.Dialers[0].StatsID() == group.Dialers[1].StatsID() {
			t.Fatal("family order or independent identity lost")
		}
	}
}
