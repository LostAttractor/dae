/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import (
	"strconv"
	"strings"
	"time"
)

type DnsRequestOutboundIndex int16

const (
	DnsRequestOutboundIndex_Reject      DnsRequestOutboundIndex = 0xFC
	DnsRequestOutboundIndex_AsIs        DnsRequestOutboundIndex = 0xFD
	DnsRequestOutboundIndex_LogicalOr   DnsRequestOutboundIndex = 0xFE
	DnsRequestOutboundIndex_LogicalAnd  DnsRequestOutboundIndex = 0xFF
	DnsRequestOutboundIndex_LogicalMask DnsRequestOutboundIndex = 0xFE

	DnsRequestOutboundIndex_UserDefinedMax = DnsRequestOutboundIndex_Reject - 1

	DefaultDNSRetryInterval  = 5 * time.Second
	DefaultDNSRetryCount     = 3
	DefaultDNSTimeout        = DefaultDNSRetryInterval * DefaultDNSRetryCount
	MaxDnsLookupDepth        = 3
	MaxDnsFlightParticipants = 128
	// DnsDuplicateWaitTimeout makes early duplicate waiters release their
	// flight slot one retry interval before a single upstream exchange expires.
	DnsDuplicateWaitTimeout = DefaultDNSTimeout - DefaultDNSRetryInterval
	// DnsStateSweepInterval bounds how long expired cache and domain-registry
	// state can linger while otherwise idle.
	DnsStateSweepInterval = time.Minute

	// MaxDnsMessageSize is the largest DNS message the upstream receive
	// buffer must hold. EDNS(0) (RFC 6891) lets a requestor advertise a UDP
	// payload size of up to 65535, and 4096 is a common advertisement; a
	// link-MTU-sized buffer would silently truncate such datagrams.
	MaxDnsMessageSize = 1<<16 - 1
)

func (i DnsRequestOutboundIndex) String() string {
	switch i {
	case DnsRequestOutboundIndex_Reject:
		return "reject"
	case DnsRequestOutboundIndex_AsIs:
		return "asis"
	case DnsRequestOutboundIndex_LogicalOr:
		return "<OR>"
	case DnsRequestOutboundIndex_LogicalAnd:
		return "<AND>"
	default:
		return "<index: " + strconv.Itoa(int(i)) + ">"
	}
}

type DnsResponseOutboundIndex uint8

const (
	DnsResponseOutboundIndex_Accept      DnsResponseOutboundIndex = 0xFC
	DnsResponseOutboundIndex_Reject      DnsResponseOutboundIndex = 0xFD
	DnsResponseOutboundIndex_LogicalOr   DnsResponseOutboundIndex = 0xFE
	DnsResponseOutboundIndex_LogicalAnd  DnsResponseOutboundIndex = 0xFF
	DnsResponseOutboundIndex_LogicalMask DnsResponseOutboundIndex = 0xFE

	DnsResponseOutboundIndex_UserDefinedMax = DnsResponseOutboundIndex_Accept - 1
)

func (i DnsResponseOutboundIndex) String() string {
	switch i {
	case DnsResponseOutboundIndex_Accept:
		return "accept"
	case DnsResponseOutboundIndex_Reject:
		return "reject"
	case DnsResponseOutboundIndex_LogicalOr:
		return "<OR>"
	case DnsResponseOutboundIndex_LogicalAnd:
		return "<AND>"
	default:
		return "<index: " + strconv.Itoa(int(i)) + ">"
	}
}

func (i DnsResponseOutboundIndex) IsReserved() bool {
	return !strings.HasPrefix(i.String(), "<index: ")
}
