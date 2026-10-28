/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef DAE_ROUTING_ABI_H
#define DAE_ROUTING_ABI_H

/* Numeric routing ABI. Go constants use the same build-time capacities as BPF. */
#if !defined(MAX_MATCH_SET_LEN) || MAX_MATCH_SET_LEN < 32 || \
	MAX_MATCH_SET_LEN > 65536 || MAX_MATCH_SET_LEN % 32
#error "MAX_MATCH_SET_LEN must be a multiple of 32 in [32, 65536]"
#endif

enum routing_limits {
	ROUTING_MAX_MATCH_SET_LEN = MAX_MATCH_SET_LEN,
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
	OUTBOUND_USER_DEFINED_MAX = 0xFC,
	OUTBOUND_CONTROL_PLANE_ROUTING = 0xFD,
	OUTBOUND_LOGICAL_OR = 0xFE,
	OUTBOUND_LOGICAL_AND = 0xFF,
};

/* Userspace issues fallback tokens other than 0 and FALLBACK_TOKEN_RESERVED,
 * so flow state can keep a token in a field it shares with a marker. */
enum fallback_token {
	FALLBACK_TOKEN_RESERVED = 1,
};

enum outbound_connectivity_state {
	OUTBOUND_CONNECTIVITY_ALIVE = 0,
	OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT = 1,
	OUTBOUND_CONNECTIVITY_NOALIVE_BLOCK = 2,
	OUTBOUND_CONNECTIVITY_NOALIVE_USERSPACE = 3,
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
