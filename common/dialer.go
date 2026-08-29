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

type NetworkIndex int

const NetworkInvalid NetworkIndex = -1

const (
	NetworkTCP4 NetworkIndex = iota
	NetworkTCP6
	NetworkUDP4
	NetworkUDP6
)

const NetworkTypeCount = 4

func (t *NetworkType) String() string {
	return string(t.L4Proto) + string(t.IpVersion)
}

// Index returns the canonical array and metrics index for this network type.
func (typ *NetworkType) Index() NetworkIndex {
	switch typ.L4Proto {
	case consts.L4ProtoStr_TCP:
		switch typ.IpVersion {
		case consts.IpVersionStr_4:
			return NetworkTCP4
		case consts.IpVersionStr_6:
			return NetworkTCP6
		}
	case consts.L4ProtoStr_UDP:
		switch typ.IpVersion {
		case consts.IpVersionStr_4:
			return NetworkUDP4
		case consts.IpVersionStr_6:
			return NetworkUDP6
		}
	}
	panic("invalid network type")
}

func (index NetworkIndex) Valid() bool {
	return index >= NetworkTCP4 && index <= NetworkUDP6
}

func (index NetworkIndex) String() string {
	return index.NetworkType().String()
}

func (index NetworkIndex) NetworkType() *NetworkType {
	switch index {
	case NetworkTCP4:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
		}
	case NetworkTCP6:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
		}
	case NetworkUDP4:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_4,
		}
	case NetworkUDP6:
		return &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_6,
		}
	}
	panic("invalid network type")
}
