/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef DAE_ROUTING_ABI_H
#define DAE_ROUTING_ABI_H

/* Numeric routing ABI. This header has no dependencies on map layouts or
 * translation-unit macros. Go constants are generated from these enums.
 */
enum routing_limits {
	MAX_INTERFACE_NUM = 256,
	/* 4096 selectors plus 4096 dynamic device overrides. */
	MAX_HTTP_CLIENT_ENTRIES = 8192,
};

enum http_client_kind {
	HTTP_CLIENT_ALL = 0,
	HTTP_CLIENT_MAC_OVERRIDE = 1,
	HTTP_CLIENT_MAC = 2,
	HTTP_CLIENT_IPV4 = 4,
	HTTP_CLIENT_IPV6 = 6,
};

enum http_client_layout {
	HTTP_CLIENT_KIND_BITS = 32,
	HTTP_CLIENT_MAC_BITS = 48,
	HTTP_CLIENT_MAPPED_PREFIX_BITS = 96,
	HTTP_CLIENT_KEY_BITS = HTTP_CLIENT_KIND_BITS + 128,
};

enum api_client_link_type {
	API_CLIENT_LINK_ETHERNET = 1,
	API_CLIENT_LINK_IP = 2,
};

enum handoff_constants {
	HANDOFF_LIFETIME_SECONDS = 30,
	TPROXY_MARK = 0x08000000,
};

enum outbound_index {
	OUTBOUND_DIRECT = 0,
	OUTBOUND_BLOCK = 1,
	OUTBOUND_USER_DEFINED_MIN = 2,
	OUTBOUND_MUST_RULES = 0xFC,
	OUTBOUND_CONTROL_PLANE_ROUTING = 0xFD,
	OUTBOUND_LOGICAL_OR = 0xFE,
	OUTBOUND_LOGICAL_AND = 0xFF,
};

enum outbound_connectivity_state {
	OUTBOUND_CONNECTIVITY_ALIVE = 0,
	OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT = 1,
	OUTBOUND_CONNECTIVITY_NOALIVE_BLOCK = 2,
	OUTBOUND_CONNECTIVITY_NOALIVE_TRY_SNIFF = 3,
};

enum capture_flags {
	CAPTURE_HTTP = 1,
	CAPTURE_DESTINATION = 2,
	CAPTURE_HTTP_REQUEST = 4,
	CAPTURE_DNS = 8,
};

enum route_result_bits {
	ROUTE_RESULT_MARK_SHIFT = 8,
	ROUTE_RESULT_MUST_SHIFT = 40,
	ROUTE_RESULT_SKIPPED_NOALIVE = 1ULL << 41,
	ROUTE_RESULT_CAPTURE_SHIFT = 42,
};

enum match_flags {
	MATCH_FLAG_NOT = 1,
	MATCH_FLAG_MUST = 2,
	MATCH_FLAG_SKIP_NOALIVE = 4,
	MATCH_CAPTURE_SHIFT = 3,
	MATCH_FLAG_BYPASS = 1 << 6,
};

enum __attribute__((packed)) MatchType {
	MatchType_DomainSet,
	MatchType_IpSet,
	MatchType_SourceIpSet,
	MatchType_Port,
	MatchType_SourcePort,
	MatchType_L4Proto,
	MatchType_IpVersion,
	MatchType_Mac,
	MatchType_ProcessName,
	MatchType_IfIndex,
	MatchType_Dscp,
	MatchType_Fallback,
	MatchType_HTTPClient,
};

enum L4ProtoType {
	L4ProtoType_TCP = 1,
	L4ProtoType_UDP = 2,
	L4ProtoType_uTP = 4,
	L4ProtoType_X = 7,
};

enum IpVersionType {
	IpVersionType_4 = 1,
	IpVersionType_6 = 2,
	IpVersionType_X = 3,
};

enum __attribute__((packed)) MatchAction {
	MatchAction_Route,
	MatchAction_Or,
	MatchAction_And,
	MatchAction_Must,
	MatchAction_Bump,
	MatchAction_Capture,
	MatchAction_FlowEnd,
	/* On a definite miss, jump past the conditional block. */
	MatchAction_ConditionalJump,
	/* Userspace-only boolean terminals; never uploaded to routing_map. */
	MatchAction_Match,
	MatchAction_Miss,
};

#endif /* DAE_ROUTING_ABI_H */
