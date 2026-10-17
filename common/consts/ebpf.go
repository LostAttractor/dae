/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/internal/routingabi"
)

const (
	BpfPinRoot = "/sys/fs/bpf"

	TaskCommLen = 16
)

type MatchType uint8

const (
	MatchType_DomainSet   MatchType = routingabi.MatchTypeDomainSet
	MatchType_IpSet       MatchType = routingabi.MatchTypeIpSet
	MatchType_SourceIpSet MatchType = routingabi.MatchTypeSourceIpSet
	MatchType_Port        MatchType = routingabi.MatchTypePort
	MatchType_SourcePort  MatchType = routingabi.MatchTypeSourcePort
	MatchType_L4Proto     MatchType = routingabi.MatchTypeL4Proto
	MatchType_IpVersion   MatchType = routingabi.MatchTypeIpVersion
	MatchType_Mac         MatchType = routingabi.MatchTypeMac
	MatchType_ProcessName MatchType = routingabi.MatchTypeProcessName
	MatchType_IfIndex     MatchType = routingabi.MatchTypeIfIndex
	MatchType_Dscp        MatchType = routingabi.MatchTypeDscp
	MatchType_Fallback    MatchType = routingabi.MatchTypeFallback
	MatchType_HTTPClient  MatchType = routingabi.MatchTypeHTTPClient
	MatchType_MustRules   MatchType = routingabi.MatchTypeHTTPClient + 1
	MatchType_Upstream    MatchType = routingabi.MatchTypeHTTPClient + 2
	MatchType_QType       MatchType = routingabi.MatchTypeHTTPClient + 3
)

type OutboundIndex uint8

// MatchAction is the instruction action, independent of routing outbound IDs.
type MatchAction uint8

const (
	MatchActionRoute           MatchAction = routingabi.MatchActionRoute
	MatchActionOr              MatchAction = routingabi.MatchActionOr
	MatchActionAnd             MatchAction = routingabi.MatchActionAnd
	MatchActionMust            MatchAction = routingabi.MatchActionMust
	MatchActionBump            MatchAction = routingabi.MatchActionBump
	MatchActionCapture         MatchAction = routingabi.MatchActionCapture
	MatchActionFlowEnd         MatchAction = routingabi.MatchActionFlowEnd
	MatchActionConditionalJump MatchAction = routingabi.MatchActionConditionalJump
	MatchActionMatch           MatchAction = routingabi.MatchActionMatch
	MatchActionMiss            MatchAction = routingabi.MatchActionMiss
)

const (
	OutboundDirect              OutboundIndex = routingabi.OUTBOUND_DIRECT
	OutboundBlock               OutboundIndex = routingabi.OUTBOUND_BLOCK
	OutboundUserDefinedMin      OutboundIndex = routingabi.OUTBOUND_USER_DEFINED_MIN
	OutboundMustRules           OutboundIndex = routingabi.OUTBOUND_MUST_RULES
	OutboundControlPlaneRouting OutboundIndex = routingabi.OUTBOUND_CONTROL_PLANE_ROUTING
	OutboundLogicalOr           OutboundIndex = routingabi.OUTBOUND_LOGICAL_OR
	OutboundLogicalAnd          OutboundIndex = routingabi.OUTBOUND_LOGICAL_AND
	OutboundLogicalMask         OutboundIndex = routingabi.OUTBOUND_LOGICAL_OR
	OutboundUserDefinedMax                    = OutboundMustRules - 1
)

func (i OutboundIndex) String() string {
	switch i {
	case OutboundMustRules:
		return "must_rules"
	case OutboundDirect:
		return "direct"
	case OutboundBlock:
		return "block"
	case OutboundControlPlaneRouting:
		return "bump"
	case OutboundLogicalOr:
		return "<OR>"
	case OutboundLogicalAnd:
		return "<AND>"
	default:
		return "<index: " + strconv.Itoa(int(i)) + ">"
	}
}

func (i OutboundIndex) IsReserved() bool {
	return !strings.HasPrefix(i.String(), "<index: ")
}

var (
	MaxMatchSetLen_ = ""
	MaxMatchSetLen  = 32 * 32
)

// A policy assumption, independent of response caching and DNSSEC validity.
const DefaultDNSRetentionWindow = 7 * 24 * time.Hour

func init() {
	if MaxMatchSetLen_ != "" {
		i, err := strconv.Atoi(MaxMatchSetLen_)
		if err != nil {
			panic(err)
		}
		MaxMatchSetLen = i
	}
	if MaxMatchSetLen < 32 || MaxMatchSetLen > 65536 || MaxMatchSetLen%32 != 0 {
		panic("MaxMatchSetLen must be a multiple of 32 in [32, 65536]: " + strconv.Itoa(MaxMatchSetLen))
	}
}

type L4ProtoType uint8

const (
	L4ProtoType_TCP L4ProtoType = routingabi.L4ProtoTypeTCP
	L4ProtoType_UDP L4ProtoType = routingabi.L4ProtoTypeUDP
	L4ProtoType_uTP L4ProtoType = routingabi.L4ProtoTypeUTP
	L4ProtoType_X   L4ProtoType = routingabi.L4ProtoTypeX
)

type IpVersionType uint8

const (
	IpVersion_4 IpVersionType = routingabi.IpVersionType4
	IpVersion_6 IpVersionType = routingabi.IpVersionType6
	IpVersion_X IpVersionType = routingabi.IpVersionTypeX
)

func IpVersionFromAddr(addr netip.Addr) (ipversion IpVersionType) {
	switch {
	case addr.Is4() || addr.Is4In6():
		ipversion = IpVersion_4
	case addr.Is6():
		ipversion = IpVersion_6
	default:
		ipversion = IpVersion_X
	}
	return
}

func (v IpVersionType) ToIpVersionStr() IpVersionStr {
	switch v {
	case IpVersion_4:
		return IpVersionStr_4
	case IpVersion_6:
		return IpVersionStr_6
	}
	panic("unsupported ipversion")
}

const (
	TproxyMark      uint32 = routingabi.TPROXY_MARK
	LoopbackIfIndex        = 1
)

const (
	LinkHdrLen_None     uint32 = 0
	LinkHdrLen_Ethernet uint32 = 14
)
