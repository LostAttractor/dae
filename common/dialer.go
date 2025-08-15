/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func ShowDuration(d time.Duration) string {
	return d.Truncate(time.Millisecond).String()
}

func LatencyString(realLatency, latencyOffset time.Duration) string {
	var offsetSign string = "+"
	if latencyOffset < 0 {
		offsetSign = "-"
	}

	var offsetPart string = ""
	if latencyOffset != 0 {
		offsetPart = "(" + offsetSign + ShowDuration(latencyOffset.Abs()) + "=" + ShowDuration(realLatency+latencyOffset) + ")"
	}

	return ShowDuration(realLatency) + offsetPart
}

type NetworkType struct {
	L4Proto   consts.L4ProtoStr
	IpVersion consts.IpVersionStr
}

func (t *NetworkType) String() string {
	return string(t.L4Proto) + string(t.IpVersion)
}

// networkTypeToIndex 将网络类型映射到集合索引
// collections:
// 0: TCP4 DNS
// 1: TCP6 DNS
// 2: UDP4 DNS
// 3: UDP6 DNS
func NetworkTypeToIndex(typ *NetworkType) int {
	switch typ.L4Proto {
	case consts.L4ProtoStr_TCP:
		switch typ.IpVersion {
		case consts.IpVersionStr_4:
			return 0
		case consts.IpVersionStr_6:
			return 1
		}
	case consts.L4ProtoStr_UDP:
		// UDP share the DNS check result.
		switch typ.IpVersion {
		case consts.IpVersionStr_4:
			return 2
		case consts.IpVersionStr_6:
			return 3
		}
	}
	panic("invalid network type")
}

func IndexToNetworkType(index int) *NetworkType {
	switch index {
	case 0:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
		}
	case 1:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
		}
	case 2:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_4,
		}
	case 3:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_6,
		}
	}
	panic("invalid network type")
}
