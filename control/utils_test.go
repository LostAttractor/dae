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
