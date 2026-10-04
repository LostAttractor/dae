// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
)

func TestMaterializedGroupsShareEquivalentPaths(t *testing.T) {
	conf := outboundUsageConfig(t, `global {}
node { shared: 'socks5://127.0.0.1:1080' }
group {
 automatic { node(shared) [priority: 1] policy: min_moving_avg }
 manual { node(shared) policy: selector check_tolerance: 10ms }
 different_check { node(shared) policy: fixed(0) check_interval: 7s }
}
routing {
 dport(1) -> manual
 dport(2) -> different_check
 fallback: automatic
}`)
	core := &controlPlaneCore{closed: t.Context()}
	builder, err := core.buildOutbounds(t.Context(), outboundUsageNodes(conf), conf.Group, &conf.Routing, &conf.Global, consts.OutboundBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDialerGroups(builder.outbounds)
	groups := make(map[string]*outbound.DialerGroup)
	for _, group := range builder.outbounds {
		groups[group.Name] = group
	}
	automatic, manual, different := groups["automatic"].Dialers[0], groups["manual"].Dialers[0], groups["different_check"].Dialers[0]
	if automatic.Dialer != manual.Dialer || automatic.Dialer == different.Dialer {
		t.Fatal("materialization did not use effective transport and probe configuration")
	}
	if automatic.StatsID() == manual.StatsID() || groups["manual"].Selection() != manual.StatsID() {
		t.Fatal("sharing changed group-scoped candidate identity or selector choice")
	}
	if annotation, _ := groups["automatic"].DialerAnnotation(automatic); annotation.Priority != 1 {
		t.Fatal("automatic group's priority was lost")
	}
	if annotation, _ := groups["manual"].DialerAnnotation(manual); annotation.Priority != 0 {
		t.Fatal("automatic group's priority leaked to manual group")
	}
	_ = groups["automatic"].Close()
	release, err := manual.Retain()
	if err != nil {
		t.Fatalf("closing one group retired another group's path: %v", err)
	}
	release()
}
