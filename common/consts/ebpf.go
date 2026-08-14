/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import (
	"net/netip"
	"strconv"
	"strings"

	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

const (
	BpfPinRoot = "/sys/fs/bpf"

	TaskCommLen = 16
)

type ParamKey uint32

const (
	ZeroKey ParamKey = iota
	BigEndianTproxyPortKey
	DisableL4TxChecksumKey
	DisableL4RxChecksumKey
	ControlPlanePidKey
	ControlPlaneNatDirectKey
	ControlPlaneDnsRoutingKey

	OneKey ParamKey = 1
)

type DisableL4ChecksumPolicy uint32

const (
	DisableL4ChecksumPolicy_EnableL4Checksum DisableL4ChecksumPolicy = iota
	DisableL4ChecksumPolicy_Restore
	DisableL4ChecksumPolicy_SetZero
)

type MatchType uint8

const (
	MatchType_DomainSet MatchType = iota
	MatchType_IpSet
	MatchType_SourceIpSet
	MatchType_Port
	MatchType_SourcePort
	MatchType_L4Proto
	MatchType_IpVersion
	MatchType_Mac
	MatchType_ProcessName
	MatchType_IfIndex
	MatchType_Dscp
	MatchType_Fallback
	MatchType_MustRules

	MatchType_Upstream
	MatchType_QType
)

type OutboundIndex uint8

const (
	OutboundDirect OutboundIndex = iota
	OutboundBlock

	OutboundUserDefinedMin

	OutboundMustRules           OutboundIndex = 0xFC
	OutboundControlPlaneRouting OutboundIndex = 0xFD
	OutboundLogicalOr           OutboundIndex = 0xFE
	OutboundLogicalAnd          OutboundIndex = 0xFF
	OutboundLogicalMask         OutboundIndex = 0xFE

	OutboundUserDefinedMax = OutboundMustRules - 1
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

// Domain registry sizing and lifetime (see control/domain_registry.go).
// The kernel-side domain maps are created with a fixed max_entries
// (MAX_DOMAIN_ROUTING_NUM in control/kern/tproxy.c); the userspace registry
// mirrors their occupancy and never lets them overflow. The userspace
// registry itself is larger and allowed to exceed its soft limit while its
// entries are still alive, so that sniff verification keeps working.
var (
	// MinDomainTTL is the lower bound (seconds) for both the lifetime of an
	// IP->domain-rules mapping in the kernel maps and the eviction-priority
	// deadline of its userspace registration. Many apps ignore the DNS TTL
	// and keep using a cached answer for a long time, so short DNS TTLs need
	// a wide floor for domain routing and sniff verification to keep working.
	// The userspace deadline does not bound validity: it only orders
	// reclamation when the registry exceeds DomainRegistryMaxSize.
	MinDomainTTL = 7 * 24 * 3600
	// DomainRegistryMaxSize is the soft limit of userspace registrations.
	// Entries past their TTL are reclaimed on the update path once this size
	// is exceeded; live entries are never evicted (the registry may grow
	// beyond the limit).
	DomainRegistryMaxSize = 4 * 65536
)

func init() {
	if MaxMatchSetLen_ != "" {
		i, err := strconv.Atoi(MaxMatchSetLen_)
		if err != nil {
			panic(err)
		}
		MaxMatchSetLen = i
	}
	if MaxMatchSetLen%32 != 0 {
		panic("MaxMatchSetLen should be a multiple of 32: " + strconv.Itoa(MaxMatchSetLen))
	}
}

type L4ProtoType uint8

const (
	L4ProtoType_TCP L4ProtoType = 0b001
	L4ProtoType_UDP L4ProtoType = 0b010
	L4ProtoType_uTP L4ProtoType = 0b100
	L4ProtoType_X   L4ProtoType = 0b111
)

type IpVersionType uint8

const (
	IpVersion_4 IpVersionType = 0b01
	IpVersion_6 IpVersionType = 0b10
	IpVersion_X IpVersionType = 0b11
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

var MinimumKernelVersion = internal.Version{6, 13, 0}

var (
	TproxyMark       uint32 = 0x08000000
	TproxyMarkString string = "0x08000000" // Should be aligned with nftables
	Recognize        uint16 = 0x2017
	LoopbackIfIndex         = 1
)

const (
	LinkHdrLen_None     uint32 = 0
	LinkHdrLen_Ethernet uint32 = 14
)
