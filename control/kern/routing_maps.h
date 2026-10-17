/* SPDX-License-Identifier: AGPL-3.0-only */
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

#ifndef DAE_ROUTING_MAPS_H
#define DAE_ROUTING_MAPS_H

#include "routing_abi.h"

/* Predicate/profile map layouts shared with the Go compiler.
 * Included after the kernel headers and capacity limits in tproxy.c.
 */

// Array of LPM tries:
struct lpm_key {
	struct bpf_lpm_trie_key_hdr trie_key;
	__be32 data[4];
};

struct map_lpm_type {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_LPM_SIZE);
	__uint(key_size, sizeof(struct lpm_key));
	__uint(value_size, sizeof(__u32));
} unused_lpm_type SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, MAX_LPM_NUM);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, struct map_lpm_type);
} lpm_array_map SEC(".maps");

/* One namespace for each predicate kind keeps IPv4, IPv6 and MAC disjoint. */
struct http_client_key {
	__u32 prefixlen;
	__u32 kind;
	__u8 address[16];
};

struct http_client_decision {
	__u32 order;
	__u32 allow;
};

struct http_client_map {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_HTTP_CLIENT_ENTRIES);
	__type(key, struct http_client_key);
	__type(value, struct http_client_decision);
} unused_http_clients SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, struct http_client_map);
} http_clients_map SEC(".maps");

struct port_range {
	__u16 port_start;
	__u16 port_end;
};

/*
 * Rule is like as following:
 *
 * domain(geosite:cn, suffix: google.com) && l4proto(tcp) -> my_group
 *
 * pseudocode: domain(geosite:cn || suffix:google.com) && l4proto(tcp) ->
 * my_group
 *
 * A match_set can be: IP set geosite:cn, suffix google.com, tcp proto
 */

struct match_set {
	union {
		__u8 __value[16]; // Placeholder for bpf2go.

		__u32 index;
		struct port_range port_range;
		enum L4ProtoType l4proto_type;
		enum IpVersionType ip_version;
		__u32 pname[TASK_COMM_LEN / 4];
		__u32 ifindex;
		__u8 dscp;
	};
	/* OR: distance to clause tail; AND: distance to next rule;
	 * ConditionalJump: distance past the body; AND in its entry skips it too.
	 * Terminal actions: packet mark. All jumps are strictly forward.
	 */
	__u32 mark;
	enum MatchType type;
	__u8 outbound; // User-defined value range is [0, 252].
	__u8 flags;
	enum MatchAction action;
};

#define MATCH_CAPTURE_FLAGS(m) (((m)->flags >> MATCH_CAPTURE_SHIFT) & 0x07)

_Static_assert(sizeof(struct match_set) == 24, "match_set ABI must remain compact");
_Static_assert(__builtin_offsetof(struct match_set, action) == 23,
	       "match_set action ABI offset");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct match_set);
	__uint(max_entries, MAX_MATCH_SET_LEN);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_map SEC(".maps");

/* Each packet holds one profile value for its entire rule walk. Hash updates
 * replace length and steps together; never copy this value onto the BPF stack.
 * A uint16 index covers every physical rule allowed by MAX_MATCH_SET_LEN.
 */
struct routing_profile {
	__u32 length;
	__u16 steps[MAX_MATCH_SET_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); /* ifindex */
	__type(value, __u32); /* stable policy ID */
	__uint(max_entries, MAX_INTERFACE_NUM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} routing_interface_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); /* stable profile ID */
	__type(value, struct routing_profile);
	__uint(max_entries, MAX_INTERFACE_NUM + 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} routing_profile_map SEC(".maps");

struct domain_routing {
	__u32 bump[MAX_MATCH_SET_LEN / 32];
	__u32 routing[MAX_MATCH_SET_LEN / 32];
};

// domain_routing_map is fully managed by user space (control plane). Keep both
// bitmaps in one value so readers observe an atomic aggregate update. Use
// BPF_MAP_TYPE_HASH (not LRU) so the kernel never silently evicts entries;
// entries are inserted/removed only with the corresponding registry state.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32[4]);
	__type(value, struct domain_routing);
	__uint(max_entries, MAX_DOMAIN_ROUTING_NUM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	/// NOTICE: No persistence.
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_routing_map SEC(".maps");
// Previously about 21.63 MB was preallocated; memory now grows with occupancy.

#endif /* DAE_ROUTING_MAPS_H */
