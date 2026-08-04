/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

type RoutingDomainKey string

const (
	RoutingDomainKey_Full    RoutingDomainKey = "full"
	RoutingDomainKey_Keyword RoutingDomainKey = "keyword"
	RoutingDomainKey_Suffix  RoutingDomainKey = "suffix"
	RoutingDomainKey_Regex   RoutingDomainKey = "regex"

	Function_Domain      = "domain"
	Function_DestIp      = "dip"
	Function_SourceIp    = "sip"
	Function_DestPort    = "dport"
	Function_SourcePort  = "sport"
	Function_L4Proto     = "l4proto"
	Function_IpVersion   = "ipversion"
	Function_Mac         = "mac"
	Function_ProcessName = "pname"
	Function_Dscp        = "dscp"
	Function_IfIndex     = "ifindex"
	Function_IfName      = "ifname"

	Function_QName    = "qname"
	Function_QType    = "qtype"
	Function_Upstream = "upstream"

	Function_Ip = "ip"

	OutboundParam_Mark             = "mark"
	OutboundParam_SkipWhileNoalive = "skip_while_noalive"
)
