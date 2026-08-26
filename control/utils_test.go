/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestDirectDialerForMarkCachesOverrides(t *testing.T) {
	c := &ControlPlane{soMarkFromDae: 7}
	if got := c.directDialerForMark(consts.OutboundUserDefinedMin, 8); got != nil {
		t.Fatal("non-direct outbound received a marked direct dialer")
	}
	if got := c.directDialerForMark(consts.OutboundDirect, 7); got != nil {
		t.Fatal("global mark unnecessarily replaced the configured direct dialer")
	}
	first := c.directDialerForMark(consts.OutboundDirect, 8)
	second := c.directDialerForMark(consts.OutboundDirect, 8)
	if first == nil || first != second {
		t.Fatal("marked direct dialer was not cached")
	}
}

func TestRoutingLogFieldsOmitUnavailableMetadata(t *testing.T) {
	if fields := routingLogFields(new(bpfRoutingResult), ""); len(fields) != 0 {
		t.Fatalf("zero routing metadata = %#v, want empty", fields)
	}

	result := &bpfRoutingResult{
		Pid:  42,
		Dscp: 4,
		Mac:  [6]uint8{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
	}
	copy(result.Pname[:], "curl")
	fields := routeLogFields(result, "lan0", "tcp4", "192.0.2.1:1234", "example.com:443")
	if len(fields) != 9 || fields["pid"] != uint32(42) || fields["pname"] != "curl" ||
		fields["interface"] != "lan0" || fields["dscp"] != uint8(4) || fields["mac"] != "02:42:ac:11:00:02" {
		t.Fatalf("routing metadata = %#v", fields)
	}
	if fields["action"] != "forward" || fields["network"] != "tcp4" ||
		fields["source"] != "192.0.2.1:1234" || fields["destination"] != "example.com:443" {
		t.Fatalf("route fields = %#v", fields)
	}
	if _, ok := fields["ifindex"]; ok {
		t.Fatal("routing metadata exposed a numeric ifindex")
	}
}
