// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

// +build ignore

// Disable implicit CO-RE from vmlinux.h to bypass bad relocation.
// Note: Previously misattributed to GCC 15 DTE. The actual root cause is that
// pahole fails to parse DWARF5 debug info correctly, which strips UAPI structs
// from the generated BTF.
// Workaround for implicit CO-RE: compile kernel with CONFIG_DEBUG_INFO_DWARF4=y.
// However, it is highly recommended to keep this macro defined, as it still
// significantly improves overall compatibility across different environments.
#define BPF_NO_PRESERVE_ACCESS_INDEX 1

#include "headers/errno-base.h"
#include "headers/if_ether_defs.h"
#include "headers/pkt_cls_defs.h"
#include "headers/socket_defs.h"
#include "headers/upai_in6_defs.h"
#include "vmlinux_include.h"

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"

extern void *bpf_cast_to_kern_ctx(void *ctx) __ksym;

#include "bridge.h"
#include "routing_abi.h"

// #define __DEBUG_ROUTING
// #define __PRINT_ROUTING_RESULT
// #define __DEBUG
// #define __UNROLL_ROUTE_LOOP

#ifndef __DEBUG
#undef bpf_printk
#define bpf_printk(...) ((void)0)
#endif
// #define likely(x) x
// #define unlikely(x) x
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#define IPV6_BYTE_LENGTH 16
#define TASK_COMM_LEN 16

#define PACKET_HOST 0
#define PACKET_OTHERHOST 3

#define NOWHERE_IFINDEX 0
#define BPF_F_CURRENT_NETNS (-1L)
#define CLOCK_MONOTONIC 1

/* Internal layout and metadata limits are not workload tuning parameters. */
#define MAX_LPM_SIZE 2048000
#define MAX_API_CLIENT_NUM 1024

#define MAX_LPM_NUM (MAX_MATCH_SET_LEN + 8)

/* Build-time capacities and their defaults are supplied by Make. */
#if MAX_DST_MAPPING_NUM < 1 || MAX_DST_MAPPING_NUM_UDP < 1 || \
    MAX_UDP_ROUTING_CACHE_NUM < 1 || MAX_DOMAIN_ROUTING_NUM < 1
#error "BPF map capacities must be positive"
#endif
#define MAX_ARG_LEN 128

#define UTP_MAX_EXTENSIONS 4
#define IPV6_MAX_EXTENSIONS 8

#define ipv6_optlen(p) (((p)+1) << 3)

#define UDP_CONN_STATE_TIMEOUT_S 300
/* Unanswered inbound flows live within an answer's latency; this only bounds
 * how fast a flood can cycle them. */
#define UDP_INBOUND_PENDING_NUM 16384
#define NSEC_PER_SEC 1000000000ULL
#define UDP_ROUTING_CACHE_TTL_NS (60ULL * 1000 * 1000 * 1000)

#define NDP_REDIRECT 137

/* cb[0] of a reply dae relays back from the dae0 pair, until the reply path. */
#define DAE_REPLY_MARK 0xdae0dae0

// Param keys:
static const __u32 zero_key;

// Outbound Connectivity Map:

struct outbound_connectivity_query {
	__u8 outbound;
	__u8 l4proto;
	__u8 ipversion;
};

struct outbound_connectivity {
	__u32 state; // enum outbound_connectivity_state
	/* Token stamped on the group's direct fallback flows; zero when no
	 * connection policy can end the fallback generation. */
	__u32 fallback;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct outbound_connectivity_query);
	__type(value, struct outbound_connectivity);
	__uint(max_entries, 256 * 2 * 2); // outbound * l4proto * ipversion
} outbound_connectivity_map SEC(".maps");

/* Runtime-private live leases are shared by its configuration generations.
 * Userspace deletes a token when its generation ends; degraded flows stamped
 * with it are then interrupted like flows of a changed device route. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 256 * 2 * 2 * 2); // both generations during a reload
} fallback_lease_map SEC(".maps");

/* Persist issuance, not liveness: a restarted runtime cannot revive old grants. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} fallback_sequence_map SEC(".maps");

// Sockmap:
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, __u32); // 0 is tcp, 1 is udp.
	__type(value, __u64); // fd of socket.
	__uint(max_entries, 2);
} listen_socket_map SEC(".maps");

union ip6 {
	__u8 u6_addr8[16];
	__be16 u6_addr16[8];
	__be32 u6_addr32[4];
	__be64 u6_addr64[2];
};

struct redirect_tuple {
	union ip6 sip;
	union ip6 dip;
};

/* Explicit padding: entries are compared as whole words. */
struct redirect_entry {
	__u32 ifindex;
	__u8 smac[6];
	__u8 dmac[6];
	__u8 from_wan;
	__u8 padding[3];
};

_Static_assert(sizeof(struct redirect_entry) == 20, "redirect entry has no implicit padding");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct redirect_tuple);
	__type(value, struct redirect_entry);
	__uint(max_entries, 65536);
} redirect_track SEC(".maps");
// 7.86 MB

struct ip_port {
	union ip6 ip;
	__be16 port;
	/* ip6's 8-byte alignment makes this a 24-byte hash key. Lookups compare
	 * every byte, but implicit C padding is not guaranteed to be initialized
	 * and can differ from userspace's zero-filled keys. Keep the tail explicit
	 * so aggregate initializers that set only ip and port also zero these bytes.
	 */
	__u8 pad[6];
};

struct tuples_key {
	union ip6 sip;
	union ip6 dip;
	__u16 sport;
	__u16 dport;
	__u8 l4proto;
};

struct tuples {
	struct tuples_key five;
	__u8 dscp;
};

/* The destination is deliberately absent: one source owns one decision. */
struct udp_routing_cache_key {
	union ip6 sip;
	__u16 sport;
	__u16 padding;
};

enum source_origin {
	SOURCE_UNKNOWN = 0,
	SOURCE_LOCAL = 1,
	SOURCE_LAN = 2,
};

struct udp_binding {
	__u64 route_epoch;
	__u8 mac[6];
	__u8 source_origin;
	__u8 padding;
};

_Static_assert(sizeof(struct udp_binding) == 16, "UDP binding ABI size");

/* Shared by TCP tuples and UDP source decisions, with no alignment holes.
 * Process-name predicates use the socket owner storage, not this result.
 * Preserve first-packet metadata: interfaces, DSCP and policies can change
 * mid-lifetime. generation identifies the published rules; route_epoch is
 * the independent per-device connection policy epoch.
 */
struct routing_result {
	__u64 route_epoch;
	__u32 mark;
	__u32 ifindex;
	__u32 profile_id;
	__u8 mac[6];
	__u8 outbound;
	__u8 must;
	__u8 capture_flags;
	__u8 protocol;
	__u8 dscp;
	__u8 source_origin;
	__u32 physinif;
	__u32 generation;
};

struct dns_reply {
	struct tuples_key tuple;
	struct redirect_entry path;
	__u32 padding;
};

struct dns_handoff {
	struct dns_reply reply;
	struct routing_result result;
	__u8 pname[TASK_COMM_LEN];
};

struct dns_cookie {
	struct bpf_spin_lock lock;
	__u32 padding;
	__u64 value;
};

_Static_assert(sizeof(struct dns_reply) == 64, "DNS reply ABI size");
_Static_assert(sizeof(struct dns_handoff) == 120, "DNS handoff ABI size");

/* Runtime retains these maps across generations; evicted cookies are never reused. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct dns_cookie);
	__uint(max_entries, 1);
} dns_cookie_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct dns_handoff);
	__uint(max_entries, 65536);
} dns_handoff_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct dns_reply);
	__uint(max_entries, 65536);
} dns_reply_map SEC(".maps");

static __always_inline __u64 next_dns_cookie(void)
{
	struct dns_cookie *counter = bpf_map_lookup_elem(&dns_cookie_map, &zero_key);
	__u64 cookie = 0;

	if (!counter)
		return 0;
	bpf_spin_lock(&counter->lock);
	if (counter->value < 0x7fffffffffffffffULL)
		cookie = ++counter->value;
	bpf_spin_unlock(&counter->lock);
	return cookie;
}

/* Properties of a kernel-forwarded TCP flow, fixed by its SYN's decision. SYN
 * identity keeps a retransmission's decision apart from tuple reuse. */
struct tcp_flow_state {
	__u64 route_epoch;
	__u32 mark;
	__u32 fallback;
	__be32 syn_seq;
	__u32 padding;
};

/* Bounded setup mailbox. TCP consumes its entry at accept; UDP snapshots it.
 * Unconsumed entries expire logically and are reclaimed by the LRU. pname is
 * the sending local process, so userspace re-evaluates pname() rules alike. */
struct routing_handoff {
	struct routing_result result;
	__u32 expires;
	__be32 syn_seq;
	__u8 pname[TASK_COMM_LEN];
};

_Static_assert(sizeof(struct tcp_flow_state) == 24, "TCP flow ABI size");
_Static_assert(sizeof(struct outbound_connectivity) == 8, "outbound connectivity ABI size");
_Static_assert(sizeof(struct routing_handoff) == 64, "routing handoff ABI size");

/* cached_until == 0 marks a closing lifetime; fallback contains only a lease. */
struct udp_routing_cache_value {
	struct routing_result result;
	__u64 cached_until;
	struct bpf_timer timer;
	struct bpf_spin_lock lock;
	__u32 fallback;
};

/* Zeroed timer/lock bytes for insertion, without a timer in a per-CPU map. */
struct udp_routing_scratch {
	struct routing_result result;
	__u64 cached_until;
	__u8 zero[sizeof(struct bpf_timer) + sizeof(struct bpf_spin_lock)];
	__u32 fallback;
};

_Static_assert(sizeof(struct routing_result) == 40, "routing result ABI size");
_Static_assert(__builtin_offsetof(struct routing_result, generation) == 36,
	       "routing generation ABI offset");
_Static_assert(sizeof(struct udp_routing_cache_key) == 24, "UDP source key ABI size");
_Static_assert(sizeof(struct udp_routing_cache_value) == 72, "UDP cache value ABI size");
_Static_assert(__builtin_offsetof(struct udp_routing_cache_value, cached_until) == 40,
	       "UDP cache expiry ABI offset");
_Static_assert(sizeof(struct udp_routing_scratch) == sizeof(struct udp_routing_cache_value) &&
	       __builtin_offsetof(struct udp_routing_scratch, fallback) ==
	       __builtin_offsetof(struct udp_routing_cache_value, fallback),
	       "UDP insertion layout mismatch");

struct device_route_state {
	__u64 epoch;
	__u32 updating;
	__u32 padding;
};

struct device_route_table {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, ETH_ALEN);
	__type(value, struct device_route_state);
	__uint(max_entries, 65536);
};

/* Userspace replaces the table to publish device states together. The slot
 * stays empty until a device has a state, so packets skip the table. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, struct device_route_table);
} device_routes_map SEC(".maps");

/* The management API is a local service, outside device forwarding policy. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ip_port);
	__type(value, __u8);
	__uint(max_entries, 1024);
} route_exempt_map SEC(".maps");

static __always_inline struct device_route_state *device_route(const __u8 *mac)
{
	void *table = bpf_map_lookup_elem(&device_routes_map, &zero_key);

	return table ? bpf_map_lookup_elem(table, mac) : NULL;
}

struct l4_hdr {
	union {
		struct tcphdr tcph;
		struct udphdr udph;
		struct icmp6hdr icmp6h;
	};
};

struct l3_hdr {
	union {
		struct iphdr iph;
		struct ipv6hdr ipv6h;
	};
};

struct dae_param {
	__u32 control_plane_pid;
	__u32 dae0_ifindex;
	__u32 dae0peer_ifindex;
	__u8 dae0peer_mac[6];
	__u8 has_bpf_get_current_task;
	__u8 padding;
};

volatile const struct dae_param PARAM = {};
volatile const __s32 proxy_netns_id = BPF_F_CURRENT_NETNS;

/* Updated only when publishing a control plane; zero disables observation. */
volatile __be16 api_port;
volatile __u32 default_routing_profile;
/* Fixed before this generation's programs are attached. */
volatile __u32 routing_generation;
/* Published per generation; only terminal unexpected exit uses this policy. */
volatile __u32 unexpected_exit_behavior = OUTBOUND_DIRECT;

/* Exemptions are TCP to API addresses on the API port, published together
 * with api_port. */
static __always_inline bool route_exempt(const struct tuples_key *five)
{
	__be16 port = api_port;
	struct ip_port destination = { .ip = five->dip, .port = five->dport };

	return five->l4proto == IPPROTO_TCP && port && five->dport == port &&
	       bpf_map_lookup_elem(&route_exempt_map, &destination);
}

struct api_client {
	__u64 observed_at;
	__u8 mac[6];
	__u8 link_type; /* enum api_client_link_type */
	__u32 ifindex;
	__u32 physinif;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuples_key);
	__type(value, struct api_client);
	__uint(max_entries, MAX_API_CLIENT_NUM);
} api_client_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuples_key);
	__type(value, struct routing_handoff);
	__uint(max_entries, 16384);
} routing_tuples_map SEC(".maps");

/* Socket references, not cached ownership: close removes them in the kernel.
 * A full index only costs a namespace lookup; it never rejects a connection. */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct tuples_key);
	__type(value, __u64);
	__uint(max_entries, 65536);
} tcp_proxy_socket_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuples_key);
	__type(value, struct tcp_flow_state);
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_flow_map SEC(".maps");

/* Share gates across pinned program generations during link replacement. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_handshake_gate_map SEC(".maps");

/* Kernel owns direct and pending decisions. Timers reclaim idle entries;
 * LRU eviction must never silently change the route of an active source. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct udp_routing_cache_key);
	__type(value, struct udp_routing_cache_value);
	__uint(max_entries, MAX_UDP_ROUTING_CACHE_NUM);
} udp_routing_cache_map SEC(".maps");

/* Userspace owns established/pending relay lifetimes. These entries survive
 * kernel decision expiry and are removed only with their endpoint. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct udp_routing_cache_key);
	__type(value, struct udp_binding);
	__uint(max_entries, MAX_UDP_ROUTING_CACHE_NUM);
} udp_bindings_map SEC(".maps");

#include "routing_maps.h"

struct pid_pname {
	__u32 pid;
	char pname[TASK_COMM_LEN];
};

/* Owner of a local socket, living and dying with the socket itself, kernel
 * sockets such as MPTCP subflows included. The pin keeps other processes'
 * owners across a restart. */
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct pid_pname);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} socket_owner_map SEC(".maps");

struct udp_conn_state {
	/* Coarse monotonic second of the latest packet in either direction. The
	 * timer reclaims the state once it has been idle for the timeout. */
	__u32 last_seen;
	/* Low bits of the routing generation whose program runs the timer. */
	__u16 generation;
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	// For traffic from lan that go through wan ingress, dae parse them in lan egress
	bool is_wan_ingress_direction;

	struct bpf_timer timer;
};

_Static_assert(sizeof(struct udp_conn_state) == 24, "UDP conn state size");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DST_MAPPING_NUM_UDP);
	__type(key, struct tuples_key);
	__type(value, struct udp_conn_state);
} udp_conn_state_map SEC(".maps");
// 16.78 MB

/* Inbound flows that nobody has answered yet, keyed like their state, with
 * the coarse second of their latest datagram. Any remote can start one with
 * a spoofed source, so they wait here instead of in udp_conn_state_map: a
 * flood only cycles this LRU and never keeps other flows from their state. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, UDP_INBOUND_PENDING_NUM);
	__type(key, struct tuples_key);
	__type(value, __u32);
} udp_inbound_pending_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} exited_map SEC(".maps");

/* Registration outlives individual program generations, never the daemon. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} daemon_identity_map SEC(".maps");

static __always_inline bool daemon_pid_registered(__u32 pid)
{
	__u64 *registered = bpf_map_lookup_elem(&daemon_identity_map, &zero_key);

	return pid && registered && *(volatile __u64 *)registered == pid;
}

static __always_inline void unregister_daemon(__u32 pid)
{
	__u64 *registered = bpf_map_lookup_elem(&daemon_identity_map, &zero_key);

	if (pid && registered)
		__sync_val_compare_and_swap(registered, pid, 0);
}

static __always_inline __u8 daemon_status(void)
{
	__u8 *exited = bpf_map_lookup_elem(&exited_map, &zero_key);

	return exited ? *exited : DAEMON_STARTING;
}

static __always_inline bool daemon_offline(void)
{
	return daemon_status() != DAEMON_ONLINE;
}

// Functions:

static __always_inline __u8 ipv4_get_dscp(const struct iphdr *iph)
{
	return (iph->tos & 0xfc) >> 2;
}

static __always_inline __u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h)
{
	return (ipv6h->priority << 2) | (ipv6h->flow_lbl[0] >> 6);
}

static __always_inline void
get_tuples(const struct __sk_buff *skb, struct tuples *tuples,
	   const struct l3_hdr *l3h, const struct l4_hdr *l4h, __u8 l4proto)
{
	__builtin_memset(tuples, 0, sizeof(*tuples));
	tuples->five.l4proto = l4proto;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		tuples->five.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.sip.u6_addr32[3] = l3h->iph.saddr;

		tuples->five.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.dip.u6_addr32[3] = l3h->iph.daddr;

		tuples->dscp = ipv4_get_dscp(&l3h->iph);

	} else {
		__builtin_memcpy(&tuples->five.dip, &l3h->ipv6h.daddr,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&tuples->five.sip, &l3h->ipv6h.saddr,
				 IPV6_BYTE_LENGTH);

		tuples->dscp = ipv6_get_dscp(&l3h->ipv6h);
	}
	if (l4proto == IPPROTO_TCP) {
		tuples->five.sport = l4h->tcph.source;
		tuples->five.dport = l4h->tcph.dest;
	} else {
		tuples->five.sport = l4h->udph.source;
		tuples->five.dport = l4h->udph.dest;
	}
}

static __always_inline bool is_extension_header(__u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_DSTOPTS:
	case IPPROTO_AH:
		return true;
	default:
		return false;
	}
}

enum fragment_state {
	FRAGMENT_NONE,
	FRAGMENT_FIRST,
	FRAGMENT_NONFIRST,
};

struct ipv6_ext_ctx {
	const struct __sk_buff *skb;
	__u32 *offset;
	__u32 packet_end;
	__u8 *nexthdr;
	int result;
	bool seen_ah;
	bool seen_fragment;
	enum fragment_state fragment_state;
};

static int ipv6_ext_step(struct ipv6_ext_ctx *ctx)
{
	__u8 current_nexthdr = *ctx->nexthdr;

	if (*ctx->nexthdr == IPPROTO_NONE)
		return 1;

	if (!is_extension_header(*ctx->nexthdr))
		return 1;

	if (*ctx->offset >= ctx->packet_end) {
		ctx->result = -EFAULT;
		return 1;
	}

	int ret = bpf_skb_load_bytes(ctx->skb, *ctx->offset, ctx->nexthdr,
					 sizeof(*ctx->nexthdr));
	if (ret) {
		bpf_printk("not a valid IPv6 packet");
		ctx->result = -EFAULT;
		return 1;
	}
	if (current_nexthdr == IPPROTO_FRAGMENT) {
		__be16 be_frag_off;

		if (ctx->seen_fragment) {
			ctx->result = -EINVAL;
			return 1;
		}
		ctx->seen_fragment = true;
		if (*ctx->offset + sizeof(struct frag_hdr) > ctx->packet_end) {
			ctx->result = -EINVAL;
			return 1;
		}
		ret = bpf_skb_load_bytes(ctx->skb, *ctx->offset + 2, &be_frag_off,
					 sizeof(be_frag_off));
		if (ret) {
			ctx->result = -EFAULT;
			return 1;
		}
		__u16 frag_off = bpf_ntohs(be_frag_off);

		if (frag_off & 0xfff8)
			ctx->fragment_state = FRAGMENT_NONFIRST;
		else if (frag_off & 0x0001)
			ctx->fragment_state = FRAGMENT_FIRST;
		if (frag_off & 0x0006) {
			ctx->result = -EINVAL;
			return 1;
		}
		if ((frag_off & 0x0001) &&
		    ((ctx->packet_end - *ctx->offset - sizeof(struct frag_hdr)) & 7)) {
			ctx->result = -EINVAL;
			return 1;
		}
		/* Non-first fragments do not contain a usable transport header. */
		if (frag_off & 0xfff8) {
			ctx->result = 1;
			return 1;
		}
		*ctx->offset += 8;
		return 0;
	}

	__u8 hdr_ext_len = 0;

	if (*ctx->offset + 2 > ctx->packet_end) {
		ctx->result = -EFAULT;
		return 1;
	}
	ret = bpf_skb_load_bytes(ctx->skb, *ctx->offset + 1, &hdr_ext_len,
				 sizeof(hdr_ext_len));
	if (ret) {
		bpf_printk("not a valid IPv6 packet");
		ctx->result = -EFAULT;
		return 1;
	}

	__u32 extension_len = current_nexthdr == IPPROTO_AH ?
		(hdr_ext_len + 2) * 4 : ipv6_optlen(hdr_ext_len);
	if (current_nexthdr == IPPROTO_AH) {
		if (hdr_ext_len < 1) {
			ctx->result = -EINVAL;
			return 1;
		}
		ctx->seen_ah = true;
	}

	if (*ctx->offset + extension_len > ctx->packet_end) {
		ctx->result = -EFAULT;
		return 1;
	}
	*ctx->offset += extension_len;
	return 0;
}

static __always_inline int
parse_transport(const struct __sk_buff *skb, __u32 link_h_len,
		struct ethhdr *ethh, struct l3_hdr *l3h,
		struct l4_hdr *l4h, __u8 *l4proto,
		__u32 *offset, __u32 *packet_end,
		enum fragment_state *fragment_state)
{
	*fragment_state = FRAGMENT_NONE;
	*packet_end = skb->len;
	if (link_h_len == ETH_HLEN) {
		int ret = bpf_skb_load_bytes(skb, *offset, ethh,
					 sizeof(struct ethhdr));
		if (ret) {
			bpf_printk("not ethernet packet");
			return 1;
		}
		// Skip ethhdr for next hdr.
		*offset += sizeof(struct ethhdr);
	} else {
		__builtin_memset(ethh, 0, sizeof(struct ethhdr));
		ethh->h_proto = skb->protocol;
	}

	*l4proto = 0;
	__builtin_memset(l3h, 0, sizeof(struct l3_hdr));
	__builtin_memset(l4h, 0, sizeof(struct l4_hdr));

	// bpf_printk("parse_transport: h_proto: %u ? %u %u", ethh->h_proto,
	//						bpf_htons(ETH_P_IP), bpf_htons(ETH_P_IPV6));
	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		__u32 l3_offset = *offset;
		int ret = bpf_skb_load_bytes(skb, *offset, l3h,
					 sizeof(struct iphdr));
		if (ret)
			return -EFAULT;
		__u32 ip_header_len = l3h->iph.ihl * 4;
		__u32 packet_len = bpf_ntohs(l3h->iph.tot_len);
		__u16 frag_off = bpf_ntohs(l3h->iph.frag_off);

		/* BIG TCP uses tot_len=0 before GSO segmentation. Only kernel GSO
		 * metadata permits this encoding; an on-wire zero length is invalid.
		 */
		if (!packet_len && skb->gso_size &&
		    skb->len > l3_offset + 0xffff &&
		    l3h->iph.protocol == IPPROTO_TCP && !(frag_off & 0x3fff))
			packet_len = skb->len - l3_offset;

		if (l3h->iph.version != 4 || l3h->iph.ihl < 5 ||
		    packet_len < ip_header_len || l3_offset + packet_len > skb->len)
			return -EINVAL;
		*packet_end = l3_offset + packet_len;

		*l4proto = l3h->iph.protocol;
		if (frag_off & 0x1fff)
			*fragment_state = FRAGMENT_NONFIRST;
		else if (frag_off & 0x2000)
			*fragment_state = FRAGMENT_FIRST;
		if ((frag_off & 0x8000) ||
		    ((frag_off & 0x4000) && (frag_off & 0x3fff)))
			return -EINVAL;
		if ((frag_off & 0x2000) && ((packet_len - ip_header_len) & 7))
			return -EINVAL;
		if (frag_off & 0x1fff)
			return 1;
		// Skip ipv4hdr and options for next hdr.
		*offset += ip_header_len;
	} else if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		__u32 l3_offset = *offset;
		int ret = bpf_skb_load_bytes(skb, *offset, l3h,
					 sizeof(struct ipv6hdr));
		if (ret) {
			bpf_printk("not a valid IPv6 packet");
			return -EFAULT;
		}
		__u32 payload_offset = l3_offset + sizeof(struct ipv6hdr);
		__u32 payload_len = bpf_ntohs(l3h->ipv6h.payload_len);
		__u32 ip_packet_end = payload_offset + payload_len;
		bool big_tcp = !payload_len && skb->gso_size &&
			skb->len > payload_offset + 0xffff;

		if (big_tcp) {
			ip_packet_end = skb->len;
			/* BIG TCP may carry the kernel's eight-byte Jumbo Payload HBH
			 * header, or have it removed before reaching this hook.
			 */
			if (l3h->ipv6h.nexthdr == IPPROTO_HOPOPTS) {
				struct hop_jumbo_hdr jumbo;

				if (bpf_skb_load_bytes(skb, payload_offset, &jumbo,
						       sizeof(jumbo)) ||
				    jumbo.nexthdr != IPPROTO_TCP || jumbo.hdrlen != 0 ||
				    jumbo.tlv_type != 0xc2 || jumbo.tlv_len != 4 ||
				    bpf_ntohl(jumbo.jumbo_payload_len) != skb->len - payload_offset)
					return -EINVAL;
			}
		}

		if (l3h->ipv6h.version != 6 || ip_packet_end > skb->len)
			return -EINVAL;
		*packet_end = ip_packet_end;

		*offset = payload_offset;
		__u8 nexthdr = l3h->ipv6h.nexthdr;

		// Skip all extension headers.
		struct ipv6_ext_ctx ext_ctx = {
			.skb = skb,
			.offset = offset,
			.packet_end = ip_packet_end,
			.nexthdr = &nexthdr,
			.result = 0,
			.seen_ah = false,
			.seen_fragment = false,
			.fragment_state = FRAGMENT_NONE,
		};

		bpf_repeat(IPV6_MAX_EXTENSIONS) {
			if (ipv6_ext_step(&ext_ctx))
				break;
		}
		*fragment_state = ext_ctx.fragment_state;
		if (big_tcp && (nexthdr != IPPROTO_TCP ||
				ext_ctx.seen_fragment || ext_ctx.seen_ah))
			return -EINVAL;
		if (ext_ctx.result)
			return ext_ctx.result;
		if (ext_ctx.seen_ah && ext_ctx.fragment_state == FRAGMENT_NONE)
			return 1;

		if (is_extension_header(nexthdr)) {
			bpf_printk("Unexpected hdr or exceeds IPV6_MAX_EXTENSIONS limit");
			return -E2BIG;
		}

		*l4proto = nexthdr;
	} else {
		return 1;
	}

	int ret;

	switch (*l4proto) {
	case IPPROTO_TCP:
		if (*offset + sizeof(struct tcphdr) > *packet_end)
			return -EFAULT;
		ret = bpf_skb_load_bytes(skb, *offset, l4h,
					 sizeof(struct tcphdr));
		if (ret) {
			// Not a complete tcphdr.
			return -EFAULT;
		}
		if (l4h->tcph.doff < 5 ||
		    *offset + l4h->tcph.doff * 4 > *packet_end)
			return -EINVAL;
		*offset += l4h->tcph.doff * 4;
		break;
	case IPPROTO_UDP:
		if (*offset + sizeof(struct udphdr) > *packet_end)
			return -EFAULT;
		ret = bpf_skb_load_bytes(skb, *offset, l4h,
					 sizeof(struct udphdr));
		if (ret) {
			// Not a complete udphdr.
			return -EFAULT;
		}
		if (bpf_ntohs(l4h->udph.len) < sizeof(struct udphdr))
			return -EINVAL;
		*offset += sizeof(struct udphdr);
		break;
	case IPPROTO_ICMPV6:
		if (ethh->h_proto != bpf_htons(ETH_P_IPV6))
			return 1;
		if (*offset + sizeof(struct icmp6hdr) > *packet_end)
			return -EFAULT;
		ret = bpf_skb_load_bytes(skb, *offset, l4h,
					 sizeof(struct icmp6hdr));
		if (ret) {
			// Not a complete icmp6hdr.
			return -EFAULT;
		}
		break;
	default:
		return 1;
	}
	return 0;
}

// Only work for first packet of a new connection.
static __always_inline bool
is_utp(const struct __sk_buff *skb, __u8 l4proto, __u32 offset,
       __u32 packet_end)
{
	if (l4proto != IPPROTO_UDP || offset > packet_end ||
	    packet_end - offset < 160)
		return false;

	__u8 header[2];
	int ret = bpf_skb_load_bytes(skb, offset, header, sizeof(header));

	if (ret)
		return false;

	__u8 typ = header[0] >> 4;
	__u8 version = header[0] & 0x0F;

	if (version != 1 || typ > 4)
		return false;

	__u8 extension = header[1];

	u32 timestamp_difference_microseconds;

	ret = bpf_skb_load_bytes(skb, offset + 64,
				 &timestamp_difference_microseconds,
				 sizeof(timestamp_difference_microseconds));
	if (ret)
		return false;
	if (timestamp_difference_microseconds != 0)
		return false; // This should be 0 for a new connection.

	offset += 160;

	for (int i = 0; i < UTP_MAX_EXTENSIONS; i++) {
		if (extension == 0)
			return true;
		if (extension > 0x04)
			return false;
		if (offset > packet_end || packet_end - offset < sizeof(header))
			return false;

		ret = bpf_skb_load_bytes(skb, offset, header, sizeof(header));
		if (ret)
			return false;

		__u32 extension_len = header[1] + sizeof(header);

		if (extension_len > packet_end - offset)
			return false;
		extension = header[0];
		offset += extension_len;
	}
	return false;
}

#include "routing.h"

/* Reuse per-CPU ingress storage for pointer-free routing input and state,
 * leaving stack space for predicate lookups and independently verified actions.
 */
struct ingress_scratch {
	struct tuples tuples;
	struct udp_routing_scratch route;
	struct dns_handoff dns;
	struct route_params params;
	struct route_state state;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ingress_scratch);
	__uint(max_entries, 1);
} ingress_scratch_map SEC(".maps");

static __always_inline void fill_udp_routing_cache_key(
	struct udp_routing_cache_key *key, const struct tuples *tuples)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->sip = tuples->five.sip;
	key->sport = tuples->five.sport;
}

static int expire_udp_route(void *map, struct udp_routing_cache_key *key,
			    struct udp_routing_cache_value *value)
{
	__u64 now = bpf_ktime_get_ns();
	__u64 remaining = 0;

	bpf_spin_lock(&value->lock);
	/* A closing element is deleted too. Its closer deletes by its own key,
	 * which misses the element once it is reused for another source. */
	if (value->cached_until > now)
		remaining = value->cached_until - now;
	else
		value->cached_until = 0;
	bpf_spin_unlock(&value->lock);
	if (remaining)
		bpf_timer_start(&value->timer, remaining, 0);
	else
		bpf_map_delete_elem(&udp_routing_cache_map, key);
	return 0;
}

/* A degraded direct decision lives until its fallback generation ends. */
static __always_inline bool fallback_live(__u32 fallback)
{
	if (!fallback)
		return true;
	if (fallback == FALLBACK_TOKEN_RESERVED)
		return false;
	__u8 *lease = bpf_map_lookup_elem(&fallback_lease_map, &fallback);

	return lease && *lease == FALLBACK_LEASE_LIVE;
}

/* Apply an unavailable user-defined group's no-connectivity behavior in the
 * kernel. Returns nonzero to drop. A direct fallback stores the token of the
 * group's fallback generation in *fallback, for the flow state, so the group's
 * connection policy can interrupt it without a userspace relay. An ended
 * generation awaits its replacement's publication, e.g. while a reload hands
 * over; userspace degrades the flow meanwhile. */
static __always_inline int degrade_unavailable(struct routing_result *result,
					       __u16 protocol, __u8 l4proto, __u32 *fallback)
{
	if (result->outbound < OUTBOUND_USER_DEFINED_MIN ||
	    result->outbound > OUTBOUND_USER_DEFINED_MAX)
		return 0;
	struct outbound_connectivity_query q = {
		.outbound = result->outbound,
		.ipversion = protocol == bpf_htons(ETH_P_IP) ? 4 : 6,
		.l4proto = l4proto,
	};
	struct outbound_connectivity *connectivity =
		bpf_map_lookup_elem(&outbound_connectivity_map, &q);

	if (!connectivity || daemon_offline())
		return -1;
	if (connectivity->state == OUTBOUND_CONNECTIVITY_NOALIVE_BLOCK)
		return -1;
	if (connectivity->state == OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT &&
	    fallback_live(connectivity->fallback)) {
		result->outbound = OUTBOUND_DIRECT;
		*fallback = connectivity->fallback;
	}
	return 0;
}

static __always_inline bool udp_source_matches(__u8 origin, const __u8 *mac,
					       const struct udp_binding *source)
{
	return origin == source->source_origin &&
		(origin == SOURCE_LOCAL ||
		 (origin == SOURCE_LAN && !__builtin_memcmp(mac, source->mac, ETH_ALEN)));
}

/* 1 = hit, 0 = new lifetime, -1 = source mismatch or lifetime already ending. */
static __noinline int read_udp_route(struct udp_routing_cache_key *key,
				     struct routing_result *result,
				     const struct udp_binding *source)
{
	struct udp_routing_cache_value *value =
		bpf_map_lookup_elem(&udp_routing_cache_map, key);
	__u64 now = bpf_ktime_get_ns();
	bool expired;

	if (!value)
		return 0;
	struct device_route_state *device = device_route(value->result.mac);

	if (device && device->updating)
		return -1;
	/* Read once outside the lock: an ending lifetime is not a stale one to
	 * close, because its element may already hold another source's route. */
	__u32 fallback = *(volatile __u32 *)&value->fallback;

	if (!*(volatile __u64 *)&value->cached_until)
		return -1;
	bool stale = (device && device->epoch != value->result.route_epoch) ||
		value->result.generation != routing_generation ||
		!fallback_live(fallback);

	bpf_spin_lock(&value->lock);
	if (!value->cached_until) {
		bpf_spin_unlock(&value->lock);
		return -1;
	}
	expired = stale || value->cached_until <= now;
	if (expired) {
		value->cached_until = 0;
	} else {
		if (source &&
		    !udp_source_matches(value->result.source_origin, value->result.mac, source)) {
			bpf_spin_unlock(&value->lock);
			return -1;
		}
		value->cached_until = now + UDP_ROUTING_CACHE_TTL_NS;
		*result = value->result;
	}
	bpf_spin_unlock(&value->lock);
	if (expired) {
		bpf_map_delete_elem(&udp_routing_cache_map, key);
		return 0;
	}
	return 1;
}

static __noinline int save_udp_route(struct udp_routing_cache_key *key,
				     struct routing_result *result, __u32 fallback)
{
	struct ingress_scratch *scratch =
		bpf_map_lookup_elem(&ingress_scratch_map, &zero_key);

	if (!scratch)
		return -1;
	struct udp_routing_scratch *value = &scratch->route;

	/* result can be value->result; only the timer/lock bytes need clearing. */
	__builtin_memset(value->zero, 0, sizeof(value->zero));
	value->result = *result;
	value->cached_until = bpf_ktime_get_ns() + UDP_ROUTING_CACHE_TTL_NS;
	value->fallback = fallback;
	int ret = bpf_map_update_elem(&udp_routing_cache_map, key, value, BPF_NOEXIST);

	if (ret && ret != -EEXIST)
		return -1;
	if (!ret) {
		struct udp_routing_cache_value *stored =
			bpf_map_lookup_elem(&udp_routing_cache_map, key);

		if (!stored)
			return -1;
		if (bpf_timer_init(&stored->timer, &udp_routing_cache_map, CLOCK_MONOTONIC) ||
		    bpf_timer_set_callback(&stored->timer, expire_udp_route) ||
		    bpf_timer_start(&stored->timer, UDP_ROUTING_CACHE_TTL_NS, 0)) {
			bpf_map_delete_elem(&udp_routing_cache_map, key);
			return -1;
		}
	}
	struct udp_binding source = { .source_origin = result->source_origin };

	__builtin_memcpy(source.mac, result->mac, sizeof(source.mac));
	/* Concurrent first packets can only adopt a decision from the same trusted source. */
	return read_udp_route(key, result, &source) == 1 ? 0 : -1;
}

static __always_inline bool redirect_entry_changed(const struct redirect_entry *stored,
						   const struct redirect_entry *entry)
{
	const __u32 *a = (const void *)stored, *b = (const void *)entry;

	if (!stored)
		return true;
	for (int i = 0; i < sizeof(*entry) / sizeof(__u32); i++)
		if (a[i] != b[i])
			return true;
	return false;
}

static __always_inline int prep_redirect_to_control_plane(
	struct __sk_buff *skb, bool from_wan, __u32 link_h_len,
	struct tuples *tuples, struct ethhdr *ethh, struct dns_handoff *dns)
{
	if (daemon_offline())
		return -1;
	/* Redirect from L3 dev to L2 dev, e.g. wg/ipip/ppp/tun -> netkit */
	if (!link_h_len) {
		__u16 l3proto = skb->protocol;

		if (bpf_skb_change_head(skb, sizeof(struct ethhdr), 0) ||
		    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
					&l3proto, sizeof(l3proto), 0))
			return -1;
	}

	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
				(void *)&PARAM.dae0peer_mac,
				sizeof(ethh->h_dest), 0))
		return -1;

	struct redirect_tuple redirect_tuple = {};

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		redirect_tuple.sip.u6_addr32[3] = tuples->five.sip.u6_addr32[3];
		redirect_tuple.dip.u6_addr32[3] = tuples->five.dip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple.sip, &tuples->five.sip,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple.dip, &tuples->five.dip,
				 IPV6_BYTE_LENGTH);
	}
	struct redirect_entry redirect_entry = {};

	redirect_entry.ifindex = skb->ifindex;
	redirect_entry.from_wan = from_wan;
	__builtin_memcpy(redirect_entry.smac, ethh->h_source,
			 sizeof(ethh->h_source));
	__builtin_memcpy(redirect_entry.dmac, ethh->h_dest,
			 sizeof(ethh->h_dest));
	__u64 cookie = 0;

	if (dns) {
		dns->reply.path = redirect_entry;
		cookie = next_dns_cookie();
		if (!cookie || bpf_map_update_elem(&dns_handoff_map, &cookie, dns, BPF_NOEXIST))
			return -1;
	}
	/* Plain DNS must not change a concurrent association's return path. */
	if (!dns || dns->result.must) {
		/* Avoid replacing the LRU node on every packet when the return path is unchanged. */
		if (redirect_entry_changed(bpf_map_lookup_elem(&redirect_track, &redirect_tuple),
					   &redirect_entry) &&
		    bpf_map_update_elem(&redirect_track, &redirect_tuple,
					&redirect_entry, BPF_ANY))
			return -1;
	}

	skb->cb[0] = dns ? DNS_METADATA_MARK : TPROXY_MARK;
	skb->cb[1] = cookie;
	skb->cb[2] = cookie >> 32;
	return 0;
}

static __always_inline __u32 udp_conn_now(void)
{
	return bpf_ktime_get_coarse_ns() / NSEC_PER_SEC;
}

/* last_seen truncates to whole seconds, so only an idle count above the
 * timeout guarantees a full timeout without packets. */
static __always_inline __u64 udp_conn_state_wait(__s32 idle)
{
	return (UDP_CONN_STATE_TIMEOUT_S + 1 - (idle > 0 ? idle : 0)) * NSEC_PER_SEC;
}

static int expire_udp_conn_state(void *map, struct tuples_key *key,
				 struct udp_conn_state *state)
{
	/* Signed: a packet on another CPU may store a later second than now. */
	__s32 idle = udp_conn_now() - *(volatile __u32 *)&state->last_seen;

	if (idle > UDP_CONN_STATE_TIMEOUT_S)
		bpf_map_delete_elem(&udp_conn_state_map, key);
	else
		bpf_timer_start(&state->timer, udp_conn_state_wait(idle), 0);
	return 0;
}

static __always_inline void copy_reversed_tuples(struct tuples_key *key,
						 struct tuples_key *dst)
{
	__builtin_memset(dst, 0, sizeof(*dst));
	dst->dip = key->sip;
	dst->sip = key->dip;
	dst->sport = key->dport;
	dst->dport = key->sport;
	dst->l4proto = key->l4proto;
}

/* Packets only note the second they were seen in; the timer itself checks
 * idleness when it expires. */
static __always_inline struct udp_conn_state *touch_udp_conn_state(struct tuples_key *key)
{
	struct udp_conn_state *state = bpf_map_lookup_elem(&udp_conn_state_map, key);
	__u32 now;

	if (!state)
		return NULL;
	now = udp_conn_now();
	if (*(volatile __u32 *)&state->last_seen != now)
		*(volatile __u32 *)&state->last_seen = now;
	/* The timer holds the program that set its callback. Hand it to the
	 * current generation, so long-lived flows do not keep retired ones. The
	 * creator may not have initialized the timer yet: retry on later packets. */
	if (state->generation != (__u16)routing_generation &&
	    !bpf_timer_set_callback(&state->timer, expire_udp_conn_state))
		state->generation = routing_generation;
	return state;
}

static __always_inline struct udp_conn_state *
new_udp_conn_state(struct tuples_key *key, bool is_wan_ingress_direction)
{
	struct udp_conn_state new_state = {
		.last_seen = udp_conn_now(),
		.generation = routing_generation,
		.is_wan_ingress_direction = is_wan_ingress_direction,
	};
	struct udp_conn_state *state;
	int ret = bpf_map_update_elem(&udp_conn_state_map, key, &new_state, BPF_NOEXIST);

	/* A concurrent first packet won and owns the direction. Its element can be
	 * reused for another key meanwhile, like that of any lookup. */
	if (ret == -EEXIST)
		return touch_udp_conn_state(key);
	if (unlikely(ret))
		return NULL;

	state = bpf_map_lookup_elem(&udp_conn_state_map, key);
	if (unlikely(!state))
		return NULL;
	/* A state without a running timer would never be reclaimed. */
	if (bpf_timer_init(&state->timer, &udp_conn_state_map, CLOCK_MONOTONIC) ||
	    bpf_timer_set_callback(&state->timer, expire_udp_conn_state) ||
	    bpf_timer_start(&state->timer, udp_conn_state_wait(0), 0)) {
		bpf_map_delete_elem(&udp_conn_state_map, key);
		return NULL;
	}
	return state;
}

static __always_inline struct udp_conn_state *
track_udp_conn_state(struct tuples_key *key, bool is_wan_ingress_direction)
{
	struct udp_conn_state *state = touch_udp_conn_state(key);

	return state ? state : new_udp_conn_state(key, is_wan_ingress_direction);
}

static __always_inline __u32 fill_socket_tuple(struct bpf_sock_tuple *tuple,
					       const struct tuples_key *five, __be16 protocol)
{
	if (protocol == bpf_htons(ETH_P_IP)) {
		tuple->ipv4.saddr = five->sip.u6_addr32[3];
		tuple->ipv4.daddr = five->dip.u6_addr32[3];
		tuple->ipv4.sport = five->sport;
		tuple->ipv4.dport = five->dport;
		return sizeof(tuple->ipv4);
	}
	__builtin_memcpy(tuple->ipv6.saddr, &five->sip, IPV6_BYTE_LENGTH);
	__builtin_memcpy(tuple->ipv6.daddr, &five->dip, IPV6_BYTE_LENGTH);
	tuple->ipv6.sport = five->sport;
	tuple->ipv6.dport = five->dport;
	return sizeof(tuple->ipv6);
}

/* Whether an inbound packet reaches a local socket other than dae's. dae's
 * own flows never consult their state, since WAN egress passes dae's packets
 * first. */
static __always_inline bool
udp_to_local_socket(struct __sk_buff *skb, const struct tuples_key *five)
{
	struct bpf_sock_tuple tuple = {};
	__u32 size = fill_socket_tuple(&tuple, five, skb->protocol);
	struct bpf_sock *sk = bpf_sk_lookup_udp(skb, &tuple, size, BPF_F_CURRENT_NETNS, 0);
	struct pid_pname *owner;
	bool local;

	if (!sk)
		return false;
	owner = bpf_sk_storage_get(&socket_owner_map, sk, 0, 0);
	local = !owner || !daemon_pid_registered(owner->pid);
	bpf_sk_release(sk);
	return local;
}

/* A datagram without state on the reply path may start an inbound flow. It
 * waits for its answer, refreshed by further datagrams. */
static __always_inline void note_inbound_udp(const struct tuples_key *key)
{
	__u32 now = udp_conn_now();
	__u32 *seen = bpf_map_lookup_elem(&udp_inbound_pending_map, key);

	if (!seen)
		bpf_map_update_elem(&udp_inbound_pending_map, key, &now, BPF_ANY);
	else if (*(volatile __u32 *)seen != now)
		*(volatile __u32 *)seen = now;
}

/* Absent from kernels without conntrack. The low bits of _nfct hold the
 * packet's ip_conntrack_info. */
struct sk_buff___dae_ct {
	unsigned long _nfct;
} __attribute__((preserve_access_index));

#define NFCT_INFO_MASK 7
#define NFCT_ESTABLISHED_REPLY 3 /* IP_CT_ESTABLISHED_REPLY */

/* Whether conntrack saw the flow of a local packet start at the remote end.
 * WAN ingress, before NAT, misses a local socket that NAT redirects inbound
 * flows to; its replies leave WAN egress after reverse NAT, still without
 * state. dae's relayed replies start outbound state, so their flows never
 * get here. */
static __always_inline bool answers_inbound_flow(struct __sk_buff *ctx)
{
	struct sk_buff___dae_ct *skb;

	if (!bpf_core_field_exists(struct sk_buff___dae_ct, _nfct))
		return false;
	skb = bpf_cast_to_kern_ctx(ctx);
	return (skb->_nfct & NFCT_INFO_MASK) == NFCT_ESTABLISHED_REPLY;
}

/* Whether a packet without state answers an inbound flow, whose replies leave
 * directly: one that started on the reply path within the idle timeout, or
 * one that conntrack saw start at the remote end. An answered flow keeps its
 * state; the pending entry ages out of its LRU. */
static __always_inline bool answers_inbound_udp(struct __sk_buff *skb, bool is_wan,
						const struct tuples_key *key)
{
	__u32 *seen = bpf_map_lookup_elem(&udp_inbound_pending_map, key);

	/* Signed: a datagram on another CPU may store a later second than now. */
	if (seen && (__s32)(udp_conn_now() - *(volatile __u32 *)seen) <= UDP_CONN_STATE_TIMEOUT_S)
		return true;
	return is_wan && answers_inbound_flow(skb);
}

static __always_inline struct pid_pname *socket_owner(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;

	if (sk)
		sk = bpf_sk_fullsock(sk);
	return sk ? bpf_sk_storage_get(&socket_owner_map, sk, 0, 0) : NULL;
}

/* LAN packets and forwarded packets carry no local socket, hence no owner. */
static __always_inline bool pid_is_control_plane(struct __sk_buff *skb,
						 struct pid_pname **pid_pname)
{
	*pid_pname = socket_owner(skb);
	return *pid_pname && daemon_pid_registered((*pid_pname)->pid);
}

static __always_inline int save_tcp_flow(struct tuples_key *key,
					 const struct routing_result *result, __u32 fallback,
					 const struct tcphdr *tcp)
{
	struct tcp_flow_state flow = {
		.route_epoch = result->route_epoch,
		.mark = result->mark,
		.fallback = fallback,
		.syn_seq = tcp->seq,
	};

	if (result->outbound != OUTBOUND_DIRECT || result->capture_flags)
		return -1;
	return bpf_map_update_elem(&tcp_flow_map, key, &flow, BPF_ANY);
}

static __always_inline bool tcp_socket_live(struct bpf_sock *sk)
{
	bool live = sk->state != BPF_TCP_LISTEN && sk->state != BPF_TCP_TIME_WAIT &&
		sk->state != BPF_TCP_CLOSE;

	bpf_sk_release(sk);
	return live;
}

/* Separate subprograms keep the verifier's full-socket and sock-common types
 * from sharing a state load after the compiler merges their branches. */
static __noinline bool
tcp_proxy_socket_lookup(struct __sk_buff *skb, const struct tuples_key *key)
{
	struct bpf_sock_tuple tuple = {};
	__u32 size = fill_socket_tuple(&tuple, key, skb->protocol);
	struct bpf_sock *sk = bpf_skc_lookup_tcp(skb, &tuple, size, proxy_netns_id, 0);

	return sk ? tcp_socket_live(sk) : false;
}

/* The accepted socket, not the consumed handoff, owns the active proxy lifetime. */
static __noinline bool
tcp_proxy_socket_live(struct __sk_buff *skb, const struct tuples_key *key)
{
	struct bpf_sock *sk = bpf_map_lookup_elem(&tcp_proxy_socket_map, key);

	if (sk && tcp_socket_live(sk))
		return true;
	return tcp_proxy_socket_lookup(skb, key);
}

/* A nonblocking gate allows map helpers while serializing tuple replacement.
 * Colliding handshakes retry through TCP; established packets never take it. */
static __always_inline __u64 *tcp_handshake_gate(struct tuples_key *key)
{
	const __u32 *words = (const void *)key;
	__u32 hash = 2166136261U;

#pragma unroll
	for (int i = 0; i < sizeof(*key) / sizeof(*words); i++)
		hash = (hash ^ words[i]) * 16777619U;
	hash &= 1023;
	__u64 *gate = bpf_map_lookup_elem(&tcp_handshake_gate_map, &hash);

	return gate && __sync_val_compare_and_swap(gate, 0, 1) == 0 ? gate : NULL;
}

static __always_inline void tcp_handshake_release(__u64 *gate)
{
	__sync_val_compare_and_swap(gate, 1, 0);
}

static __always_inline bool tcp_handoff_live(struct tuples_key *key, __be32 syn_seq,
					     __u64 route_epoch, bool syn)
{
	struct routing_handoff *pending = bpf_map_lookup_elem(&routing_tuples_map, key);
	__u32 now = bpf_ktime_get_ns() / NSEC_PER_SEC;

	return pending && (__s32)(pending->expires - now) > 0 &&
	       (!syn || (pending->syn_seq == syn_seq &&
			 pending->result.route_epoch == route_epoch));
}

enum tcp_packet_action {
	TCP_PACKET_ROUTE,
	TCP_PACKET_NATIVE,
	TCP_PACKET_PROXY,
};

/* tcp_flow_map holds only the properties of kernel-forwarded flows: a SYN
 * that dae routes creates or replaces them, the sender's RST removes them.
 * Proxy ownership is the setup handoff and then dae's socket, which live and
 * end with dae; a packet that neither owns is native and keeps its own mark.
 * LRU eviction thus drops a flow's mark and revocation, never its connection.
 * All SYN, SYN-ACK and RST callers hold the tuple gate. */
static __noinline int
tcp_packet_action(struct __sk_buff *skb, struct tuples_key *key,
		  const struct tcphdr *tcp, __u64 route_epoch)
{
	struct tcp_flow_state *saved = bpf_map_lookup_elem(&tcp_flow_map, key);
	struct tcp_flow_state flow = {};
	bool valid = false;

	if (saved) {
		flow = *saved;
		valid = flow.route_epoch == route_epoch && fallback_live(flow.fallback);
	}
	if (tcp->syn && !tcp->ack) {
		if (saved && flow.syn_seq == tcp->seq) {
			if (!valid)
				return TCP_PACKET_PROXY;
			skb->mark = flow.mark;
			return TCP_PACKET_NATIVE;
		}
		int ret = bpf_map_delete_elem(&tcp_flow_map, key);

		if (ret && ret != -ENOENT)
			return -1;
		if (tcp_handoff_live(key, tcp->seq, route_epoch, true))
			return TCP_PACKET_PROXY;
		if (daemon_status() == DAEMON_OFFLINE) {
			if (unexpected_exit_behavior != OUTBOUND_DIRECT)
				return -1;
			__builtin_memset(&flow, 0, sizeof(flow));
			flow.route_epoch = route_epoch;
			flow.mark = skb->mark;
			flow.syn_seq = tcp->seq;
			if (bpf_map_update_elem(&tcp_flow_map, key, &flow, BPF_ANY))
				return -1;
			bpf_map_delete_elem(&routing_tuples_map, key);
			return TCP_PACKET_NATIVE;
		}
		return TCP_PACKET_ROUTE;
	}
	if (saved) {
		/* Revoked properties end the flow: the listener resets it. */
		if (!valid)
			return TCP_PACKET_PROXY;
		skb->mark = flow.mark;
		if (tcp->rst)
			bpf_map_delete_elem(&tcp_flow_map, key);
		return TCP_PACKET_NATIVE;
	}
	if (tcp_handoff_live(key, 0, 0, false) || tcp_proxy_socket_live(skb, key))
		return TCP_PACKET_PROXY;
	return TCP_PACKET_NATIVE;
}

static __always_inline int publish_handoff(struct tuples_key *key,
					   const struct routing_result *result,
					   const struct pid_pname *pid_pname, __be32 syn_seq)
{
	struct routing_handoff handoff = {
		.result = *result,
		.expires = bpf_ktime_get_ns() / 1000000000ULL + HANDOFF_LIFETIME_SECONDS,
		.syn_seq = syn_seq,
	};

	if (pid_pname)
		__builtin_memcpy(handoff.pname, pid_pname->pname, sizeof(handoff.pname));
	return bpf_map_update_elem(&routing_tuples_map, key, &handoff, BPF_ANY);
}

static __always_inline void fill_route_params(
	struct route_params *params, struct __sk_buff *skb, bool is_wan,
	const struct ethhdr *ethh, const struct l4_hdr *l4h,
	const struct tuples *tuples, const struct pid_pname *pid_pname,
	__u8 l4proto, __u32 payload_offset, __u32 packet_end,
	__be16 protocol, __u32 ifindex)
{
	__builtin_memset(params, 0, sizeof(*params));
	params->sport = l4h->udph.source;
	params->dport = l4h->udph.dest;
	params->l4proto_type = l4proto == IPPROTO_TCP ? L4ProtoType_TCP : L4ProtoType_UDP;
	if (l4proto == IPPROTO_UDP && is_utp(skb, l4proto, payload_offset, packet_end))
		params->l4proto_type |= L4ProtoType_uTP;
	params->ipversion_type =
		protocol == bpf_htons(ETH_P_IP) ? IpVersionType_4 : IpVersionType_6;
	params->has_pname = !!pid_pname;
	if (pid_pname)
		__builtin_memcpy(params->pname, pid_pname->pname, sizeof(params->pname));
	params->dscp = tuples->dscp;
	params->ifindex = ifindex;
	params->physinif = is_wan ? 0 : skb_bridge_physinif(skb);
	__builtin_memcpy(params->mac, ethh->h_source, sizeof(params->mac));
	__builtin_memcpy(params->saddr, tuples->five.sip.u6_addr32, sizeof(params->saddr));
	__builtin_memcpy(params->daddr, tuples->five.dip.u6_addr32, sizeof(params->daddr));
	params->isdns = tuples->five.dport == bpf_htons(53);
}

/* Decode policy only; packet metadata and lifetime ownership stay with callers. */
static __always_inline void decode_route_result(struct routing_result *result,
						__s64 encoded)
{
	result->outbound = encoded;
	result->mark = encoded >> ROUTE_RESULT_MARK_SHIFT;
	result->must = (encoded >> ROUTE_RESULT_MUST_SHIFT) & 1;
	result->capture_flags = encoded >> ROUTE_RESULT_CAPTURE_SHIFT;
}

static __always_inline void fill_route_metadata(struct routing_result *result,
						const struct route_params *params,
						__u32 generation, __u64 route_epoch, bool is_wan)
{
	/* WAN egress excludes forwarded traffic; a missing LAN L3 MAC is not local. */
	result->source_origin = is_wan ? SOURCE_LOCAL : SOURCE_LAN;
	result->generation = generation;
	result->route_epoch = route_epoch;
	result->profile_id = params->profile_id;
	result->protocol = params->l4proto_type;
	result->dscp = params->dscp;
	result->ifindex = params->ifindex;
	result->physinif = params->physinif;
	__builtin_memcpy(result->mac, params->mac, sizeof(result->mac));
}

static __always_inline int do_tproxy_first_fragment(
	struct __sk_buff *skb, bool is_wan, struct ethhdr *ethh,
	struct l3_hdr *l3h, struct l4_hdr *l4h, __u8 l4proto,
	__u32 payload_offset, __u32 packet_end, int parse_ret)
{
	__u32 generation = routing_generation;

	if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
		return l4proto && !is_extension_header(l4proto) ? TCX_NEXT : TCX_DROP;
	if (parse_ret)
		return TCX_DROP;
	struct ingress_scratch *scratch = bpf_map_lookup_elem(&ingress_scratch_map, &zero_key);

	if (!scratch)
		return TCX_DROP;
	struct tuples *tuples = &scratch->tuples;

	get_tuples(skb, tuples, l3h, l4h, l4proto);
	struct pid_pname *pid_pname = NULL;

	if (is_wan && pid_is_control_plane(skb, &pid_pname))
		return TCX_NEXT;
	struct device_route_state *device = device_route(ethh->h_source);
	__u64 route_epoch = device ? device->epoch : 0;

	if (device && device->updating)
		return TCX_DROP;
	if (l4proto == IPPROTO_UDP) {
		struct udp_conn_state *conn_state =
			bpf_map_lookup_elem(&udp_conn_state_map, &tuples->five);

		if (!conn_state && answers_inbound_udp(skb, is_wan, &tuples->five))
			conn_state = new_udp_conn_state(&tuples->five, true);
		if (conn_state && conn_state->is_wan_ingress_direction) {
			if (skb->mark)
				return TCX_DROP;
			goto direct;
		}
	}

	if (l4proto == IPPROTO_TCP) {
		int action = tcp_packet_action(skb, &tuples->five, &l4h->tcph, route_epoch);

		/* Fragments can neither carry a mark nor split across proxy paths. */
		if (action < 0 || action == TCP_PACKET_PROXY || skb->mark)
			return TCX_DROP;
		if (action == TCP_PACKET_NATIVE)
			goto direct;
	}
	struct udp_routing_cache_key udp_key = {};

	if (l4proto == IPPROTO_UDP) {
		struct routing_result *saved = &scratch->route.result;

		fill_udp_routing_cache_key(&udp_key, tuples);
		if (bpf_map_lookup_elem(&udp_bindings_map, &udp_key))
			return TCX_DROP;
		struct udp_binding source = { .source_origin = is_wan ? SOURCE_LOCAL : SOURCE_LAN };

		__builtin_memcpy(source.mac, ethh->h_source, sizeof(source.mac));
		int hit = read_udp_route(&udp_key, saved, &source);

		if (hit < 0 ||
		    (hit && (saved->outbound != OUTBOUND_DIRECT ||
			     saved->mark || saved->capture_flags)))
			return TCX_DROP;
		if (hit)
			goto direct;
	}
	/* Later fragments cannot prove an offline lifetime; do not admit a new
	 * fragmented UDP source using rules that crash mode has bypassed. */
	if (daemon_status() == DAEMON_OFFLINE)
		return TCX_DROP;

	struct route_params *params = &scratch->params;

	fill_route_params(params, skb, is_wan, ethh, l4h, tuples, pid_pname,
			  l4proto, payload_offset, packet_end, skb->protocol, skb->ifindex);

	__s64 route_result = route(params, &scratch->state);

	if (route_result < 0 ||
	    ((route_result & ROUTE_RESULT_SKIPPED_NOALIVE) &&
	     daemon_offline() != scratch->state.offline) ||
	    (route_result >> ROUTE_RESULT_CAPTURE_SHIFT))
		return TCX_DROP;
	struct routing_result decoded = {};
	__u32 fallback = 0;

	decode_route_result(&decoded, route_result);
	if (degrade_unavailable(&decoded, skb->protocol, l4proto, &fallback))
		return TCX_DROP;
	if (decoded.outbound == OUTBOUND_DIRECT) {
		if (!fallback_live(fallback) || decoded.mark || skb->mark)
			return TCX_DROP;
		struct routing_result *result = &scratch->route.result;

		__builtin_memset(result, 0, sizeof(*result));
		result->outbound = OUTBOUND_DIRECT;
		fill_route_metadata(result, params, generation, route_epoch, is_wan);
		if (l4proto == IPPROTO_UDP) {
			if (save_udp_route(&udp_key, result, fallback) ||
			    result->outbound != OUTBOUND_DIRECT)
				return TCX_DROP;
		} else {
			if (save_tcp_flow(&tuples->five, result, fallback, &l4h->tcph))
				return TCX_DROP;
			bpf_map_delete_elem(&routing_tuples_map, &tuples->five);
		}
		goto direct;
	}

	/* Proxying only the first fragment would split the datagram across paths. */
	return TCX_DROP;

direct:
	device = device_route(ethh->h_source);
	if (device && (device->updating || device->epoch != route_epoch))
		return TCX_DROP;
	if (l4proto == IPPROTO_UDP && !track_udp_conn_state(&tuples->five, false))
		return TCX_DROP;
	skb->mark = 0;
	return TCX_NEXT;
}

static __always_inline void observe_api_client(
	struct __sk_buff *skb, const struct tuples_key *key, const struct ethhdr *ethh,
	u32 link_h_len)
{
	struct api_client client = {
		.observed_at = bpf_ktime_get_ns(),
		.ifindex = skb->ifindex,
		.physinif = skb_bridge_physinif(skb),
		.link_type = link_h_len == ETH_HLEN ? API_CLIENT_LINK_ETHERNET : API_CLIENT_LINK_IP,
	};

	if (link_h_len == ETH_HLEN)
		__builtin_memcpy(client.mac, ethh->h_source, sizeof(client.mac));
	/* Userspace verifies this packet's MAC against its scoped L3 neighbor. */
	bpf_map_update_elem(&api_client_map, key, &client, BPF_ANY);
}

// Routing and redirect the packet back.
static __always_inline int do_tproxy_unfragmented(
	struct __sk_buff *skb, bool is_wan, u32 link_h_len,
	struct ethhdr *ethh, struct l3_hdr *l3h, struct l4_hdr *l4h,
	__u8 l4proto, __u32 offset, __u32 packet_end, int parse_ret)
{
	__u32 generation = routing_generation;

	if (parse_ret)
		return TCX_NEXT;
	if (l4proto == IPPROTO_ICMPV6)
		return TCX_NEXT;

	// Prepare five tuples.
	struct ingress_scratch *scratch = bpf_map_lookup_elem(&ingress_scratch_map, &zero_key);

	if (!scratch)
		return TCX_DROP;
	struct tuples *tuples = &scratch->tuples;

	get_tuples(skb, tuples, l3h, l4h, l4proto);

	// Preserve these scalars before helpers can invalidate the verifier's skb knowledge.
	u16 protocol = skb->protocol;
	u32 ifindex = skb->ifindex;

	/* Observe the actual LAN ingress before direct TCP's established-flow
	 * shortcut. This keeps HTTP keep-alive requests fresh without depending
	 * on the L3 route device, ARP device, or bridge/bond topology.
	 */
	if (!is_wan && l4proto == IPPROTO_TCP &&
	    api_port && tuples->five.dport == api_port)
		observe_api_client(skb, &tuples->five, ethh, link_h_len);

	struct pid_pname *pid_pname = NULL;

	if (is_wan && pid_is_control_plane(skb, &pid_pname)) {
		// From control plane. Direct.
		return TCX_NEXT;
	}

	bool isdns = tuples->five.dport == bpf_htons(53);

	struct device_route_state *device = device_route(ethh->h_source);
	bool exempt = route_exempt(&tuples->five);

	if (exempt)
		device = NULL;
	if (device && device->updating)
		return TCX_DROP;
	__u64 route_epoch = device ? device->epoch : 0;

	struct tuples_key *routing_tuples_key = &tuples->five;
	struct dns_handoff *dns = NULL;

	if (l4proto == IPPROTO_TCP) {
		int action = tcp_packet_action(skb, routing_tuples_key, &l4h->tcph, route_epoch);

		if (action < 0)
			return TCX_DROP;
		if (action == TCP_PACKET_NATIVE)
			return TCX_NEXT;
		if (action == TCP_PACKET_PROXY)
			goto control_plane;
	}

	bool crashed = l4proto == IPPROTO_UDP && daemon_status() == DAEMON_OFFLINE;

	if (l4proto == IPPROTO_UDP) {
		struct tuples_key *five = &tuples->five;
		struct udp_conn_state *conn_state = touch_udp_conn_state(five);

		if (!conn_state)
			conn_state = new_udp_conn_state(five,
							answers_inbound_udp(skb, is_wan, five));
		if (!conn_state)
			return TCX_DROP;
		if (conn_state->is_wan_ingress_direction) {
			// Replay (outbound) of an inbound flow
			// => direct.
			return TCX_NEXT;
		}
	}

	struct routing_result *routing_result = &scratch->route.result;
	__u32 fallback = 0;

	__builtin_memset(routing_result, 0, sizeof(*routing_result));
	struct udp_routing_cache_key udp_key = {};

	if (l4proto == IPPROTO_UDP)
		fill_udp_routing_cache_key(&udp_key, tuples);
	/* Online DNS is per-destination. Crash bypass must not let an old proxy
	 * source escape its binding merely by sending to a DNS destination. */
	if (l4proto == IPPROTO_UDP && (!isdns || crashed)) {
		struct udp_binding *binding = bpf_map_lookup_elem(&udp_bindings_map, &udp_key);
		struct udp_binding source = { .source_origin = is_wan ? SOURCE_LOCAL : SOURCE_LAN };

		__builtin_memcpy(source.mac, ethh->h_source, sizeof(source.mac));
		if (binding) {
			/* Its endpoint releases the old source before a new lifetime starts. */
			if (binding->route_epoch != route_epoch ||
			    !udp_source_matches(binding->source_origin, binding->mac, &source))
				return TCX_DROP;
			goto control_plane;
		}
		int hit = read_udp_route(&udp_key, routing_result, &source);

		if (hit < 0)
			return TCX_DROP;
		if (hit)
			goto selected;
	}

	struct route_params *params = &scratch->params;

	fill_route_params(params, skb, is_wan, ethh, l4h, tuples, pid_pname,
			  l4proto, offset, packet_end, protocol, ifindex);

	if (crashed) {
		if (unexpected_exit_behavior != OUTBOUND_DIRECT)
			return TCX_DROP;
		routing_result->outbound = OUTBOUND_DIRECT;
		routing_result->mark = skb->mark;
		fill_route_metadata(routing_result, params, generation, route_epoch, is_wan);
		if (l4proto == IPPROTO_UDP && save_udp_route(&udp_key, routing_result, 0))
			return TCX_DROP;
		goto selected;
	}

	__s64 route_ret = route(params, &scratch->state);

	if (route_ret < 0 ||
	    ((route_ret & ROUTE_RESULT_SKIPPED_NOALIVE) &&
	     daemon_offline() != scratch->state.offline))
		return TCX_DROP;
	decode_route_result(routing_result, route_ret);
	fill_route_metadata(routing_result, params, generation, route_epoch, is_wan);

	if (routing_result->outbound == OUTBOUND_BLOCK)
		return TCX_DROP;
	if (!routing_result->capture_flags &&
	    degrade_unavailable(routing_result, protocol, l4proto, &fallback))
		return TCX_DROP;
	if (l4proto == IPPROTO_UDP && (!isdns || routing_result->must)) {
		bool dns_must = isdns && routing_result->must;

		if (dns_must) {
			struct udp_binding *binding =
				bpf_map_lookup_elem(&udp_bindings_map, &udp_key);
			struct udp_binding source = {
				.source_origin = routing_result->source_origin,
			};

			__builtin_memcpy(source.mac, routing_result->mac, sizeof(source.mac));
			/* A live endpoint can outlast its initial routing-cache entry. */
			if (binding &&
			    (binding->route_epoch != route_epoch ||
			     !udp_source_matches(binding->source_origin, binding->mac, &source)))
				return TCX_DROP;
		}
		if (save_udp_route(&udp_key, routing_result, fallback))
			return TCX_DROP;
		/* Adopt the source's existing outbound/mark, but do not let its
		 * non-DNS decision admit this explicitly bypassed packet to DNS plugins.
		 * This is per-packet: the cached source decision stays unchanged. */
		if (dns_must)
			routing_result->must = 1;
	}

selected:
	/* A membership commit may have raced route evaluation. */
	device = device_route(ethh->h_source);
	if (device && (device->updating || device->epoch != route_epoch) && !exempt)
		return TCX_DROP;
	if (routing_result->outbound == OUTBOUND_DIRECT && !routing_result->capture_flags) {
		if (!fallback_live(fallback))
			return TCX_DROP;
		if (l4proto == IPPROTO_TCP &&
		    save_tcp_flow(routing_tuples_key, routing_result, fallback, &l4h->tcph))
			return TCX_DROP;
		if (l4proto == IPPROTO_TCP)
			bpf_map_delete_elem(&routing_tuples_map, routing_tuples_key);
		goto direct;
	}
	if (daemon_offline())
		return TCX_DROP;
	if (l4proto == IPPROTO_UDP && isdns) {
		dns = &scratch->dns;
		__builtin_memset(dns, 0, sizeof(*dns));
		dns->reply.tuple = tuples->five;
		dns->result = *routing_result;
		if (pid_pname)
			__builtin_memcpy(dns->pname, pid_pname->pname, sizeof(dns->pname));
	} else if (publish_handoff(routing_tuples_key, routing_result, pid_pname,
				   l4proto == IPPROTO_TCP ? l4h->tcph.seq : 0)) {
		return TCX_DROP;
	}

control_plane:
	// Assign to control plane.
	if (prep_redirect_to_control_plane(skb, is_wan, link_h_len, tuples,
					   ethh, dns))
		return TCX_DROP;
	return bpf_redirect(PARAM.dae0_ifindex, 0);

direct:
	skb->mark = routing_result->mark;
	return TCX_NEXT;
}

static __always_inline int do_tproxy(struct __sk_buff *skb, bool is_wan,
				     u32 link_h_len)
{
	struct ethhdr ethh;
	struct l3_hdr l3h;
	struct l4_hdr l4h;
	__u8 l4proto;
	__u32 offset = 0;
	__u32 packet_end;
	enum fragment_state fragment_state;
	int ret = parse_transport(skb, link_h_len, &ethh, &l3h, &l4h,
				  &l4proto, &offset, &packet_end,
				  &fragment_state);

	if (ret < 0)
		return TCX_DROP;
	if (fragment_state != FRAGMENT_NONE) {
		struct device_route_state *device = device_route(ethh.h_source);

		if (device && device->updating)
			return TCX_DROP;
	}
	if (fragment_state == FRAGMENT_NONFIRST)
		return daemon_offline() ? TCX_DROP : TCX_NEXT;
	__u64 *gate = NULL;

	if (!ret && l4proto == IPPROTO_TCP && l4h.tcph.syn &&
	    (l4h.tcph.rst || l4h.tcph.fin))
		return TCX_DROP;
	if (!ret && l4proto == IPPROTO_TCP && (l4h.tcph.syn || l4h.tcph.rst)) {
		struct ingress_scratch *scratch =
			bpf_map_lookup_elem(&ingress_scratch_map, &zero_key);

		if (!scratch)
			return TCX_DROP;
		get_tuples(skb, &scratch->tuples, &l3h, &l4h, l4proto);
		gate = tcp_handshake_gate(&scratch->tuples.five);
		if (!gate)
			return TCX_DROP;
	}
	if (fragment_state == FRAGMENT_FIRST)
		ret = do_tproxy_first_fragment(skb, is_wan, &ethh, &l3h,
					       &l4h, l4proto, offset, packet_end, ret);
	else
		ret = do_tproxy_unfragmented(skb, is_wan, link_h_len, &ethh, &l3h,
					     &l4h, l4proto, offset, packet_end, ret);
	if (gate)
		tcp_handshake_release(gate);
	return ret;
}

/* Return traffic toward LAN hosts (lan_egress) or local sockets (wan_ingress),
 * before NAT and the firewall on WAN ingress. */
static __always_inline int do_reply_path(struct __sk_buff *skb, u32 link_h_len,
					 bool wan)
{
	struct ethhdr ethh;
	struct l3_hdr l3h;
	struct l4_hdr l4h;
	__u8 l4proto;
	__u32 offset = 0;
	__u32 packet_end;
	enum fragment_state fragment_state;

	int ret = parse_transport(skb, link_h_len, &ethh, &l3h, &l4h,
				  &l4proto, &offset, &packet_end,
				  &fragment_state);
	if (ret < 0) {
		bpf_printk("parse_transport: %d", ret);
		return TCX_DROP;
	}
	if (fragment_state == FRAGMENT_NONFIRST)
		return TCX_NEXT;
	if (ret)
		return TCX_NEXT;

	if (!wan && skb->ingress_ifindex == NOWHERE_IFINDEX &&
	    l4proto == IPPROTO_ICMPV6 &&
	    l4h.icmp6h.icmp6_type == NDP_REDIRECT) {
		// Only drop NDP_REDIRECT packets from localhost on LAN egress.
		return TCX_DROP;
	}

	// Update UDP Conntrack
	if (l4proto == IPPROTO_UDP) {
		struct tuples tuples;
		struct tuples_key reversed_tuples_key;

		get_tuples(skb, &tuples, &l3h, &l4h, l4proto);
		copy_reversed_tuples(&tuples.five, &reversed_tuples_key);
		struct udp_routing_cache_key source = {
			.sip = tuples.five.dip,
			.sport = tuples.five.dport,
		};
		struct routing_result ignored;

		/* Replies renew only current-generation caches, releasing retired timer programs. */
		read_udp_route(&source, &ignored, NULL);

		/* A packet without state may start an inbound flow, whose replies
		 * leave directly; its state waits for the answer. On WAN ingress,
		 * only a local socket can answer: NAT and forwarded flows get their
		 * state on LAN egress, and WAN egress recognizes replies of local
		 * sockets behind NAT. dae's relayed replies belong to proxied
		 * associations and start outbound state. */
		bool relayed = skb->cb[0] == DAE_REPLY_MARK;

		if (relayed)
			skb->cb[0] = 0;
		if (touch_udp_conn_state(&reversed_tuples_key))
			return TCX_NEXT;
		if (relayed && !new_udp_conn_state(&reversed_tuples_key, false))
			return TCX_DROP;
		if (!relayed && (!wan || udp_to_local_socket(skb, &tuples.five)))
			note_inbound_udp(&reversed_tuples_key);
	}

	return TCX_NEXT;
}

SEC("tc/lan_egress_l2")
int lan_egress_l2(struct __sk_buff *skb)
{
	return do_reply_path(skb, ETH_HLEN, false);
}

SEC("tc/lan_egress_l3")
int lan_egress_l3(struct __sk_buff *skb)
{
	return do_reply_path(skb, 0, false);
}

SEC("tc/lan_ingress_l2")
int lan_ingress_l2(struct __sk_buff *skb)
{
	return do_tproxy(skb, false, ETH_HLEN);
}

SEC("tc/lan_ingress_l3")
int lan_ingress_l3(struct __sk_buff *skb)
{
	return do_tproxy(skb, false, 0);
}

SEC("tc/wan_ingress_l2")
int tproxy_wan_ingress_l2(struct __sk_buff *skb)
{
	return do_reply_path(skb, ETH_HLEN, true);
}

SEC("tc/wan_ingress_l3")
int tproxy_wan_ingress_l3(struct __sk_buff *skb)
{
	return do_reply_path(skb, 0, true);
}

// We cannot modify the dest address here.
// So we redirect to dae0, using ingress path in dae0peer.
static __always_inline int do_tproxy_wan_egress(struct __sk_buff *skb, u32 link_h_len)
{
	// Skip packets not from localhost.
	if (skb->ingress_ifindex != NOWHERE_IFINDEX)
		return TCX_NEXT;

	return do_tproxy(skb, true, link_h_len);
}

SEC("tc/wan_egress_l2")
int tproxy_wan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, ETH_HLEN);
}

SEC("tc/wan_egress_l3")
int tproxy_wan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, 0);
}

// Proxy traffic. Attached at Netkit primary or veth peer TCX ingress.
SEC("netkit/primary")
int tproxy_dae0peer_ingress(struct __sk_buff *skb)
{
	// Only packets redirected from wan_egress or lan_ingress have this cb mark.
	__u32 mark = skb->cb[0];
	__u64 cookie = (__u64)skb->cb[2] << 32 | skb->cb[1];

	if (mark != TPROXY_MARK && mark != DNS_METADATA_MARK)
		return TC_ACT_SHOT;
	if (mark == DNS_METADATA_MARK &&
	    (!cookie || cookie >> 63 ||
	     bpf_skb_set_tstamp(skb, cookie, BPF_SKB_TSTAMP_UNSPEC)))
		return TC_ACT_SHOT;
	skb->cb[0] = 0;
	skb->cb[1] = 0;
	skb->cb[2] = 0;

	/*
   * ip rule add fwmark 0x8000000/0x8000000 table 2023
   * ip route add local default dev lo table 2023
   * ip -6 rule add fwmark 0x8000000/0x8000000 table 2023
   * ip -6 route add local default dev lo table 2023

   * ip rule del fwmark 0x8000000/0x8000000 table 2023
   * ip route del local default dev lo table 2023
   * ip -6 rule del fwmark 0x8000000/0x8000000 table 2023
   * ip -6 route del local default dev lo table 2023
	 */
	// TODO: Redirect directly to lo?
	skb->mark = mark;
	if (bpf_skb_change_type(skb, PACKET_HOST))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

/* Move the cookie into the trusted cb channel before qdisc interprets SCM_TXTIME. */
SEC("tc/dae0peer_egress")
int tproxy_dae0peer_egress(struct __sk_buff *skb)
{
	if (skb->mark != DNS_REPLY_MARK) {
		skb->cb[0] = DAE_REPLY_MARK;
		return TCX_NEXT;
	}
	/* Read tstamp_type first so the verifier permits delivery timestamp access. */
	__u8 type = *(volatile __u8 *)&skb->tstamp_type;
	__u64 cookie = skb->tstamp;

	if (type != BPF_SKB_TSTAMP_DELIVERY_MONO || !cookie || cookie >> 63)
		return TCX_DROP;
	skb->cb[0] = DNS_REPLY_MARK;
	skb->cb[1] = cookie;
	skb->cb[2] = cookie >> 32;
	if (bpf_skb_set_tstamp(skb, 0, BPF_SKB_TSTAMP_UNSPEC))
		return TCX_DROP;
	skb->mark = 0;
	return TCX_NEXT;
}

static __always_inline bool dns_reply_matches(struct __sk_buff *skb,
					      const struct dns_reply *reply)
{
	struct ethhdr ethh;
	struct l3_hdr l3h;
	struct l4_hdr l4h;
	struct tuples tuples;
	__u8 protocol;
	__u32 offset = 0, packet_end;
	enum fragment_state fragment;
	int ret = parse_transport(skb, ETH_HLEN, &ethh, &l3h, &l4h, &protocol,
				  &offset, &packet_end, &fragment);

	if (ret < 0 || (ret && fragment != FRAGMENT_NONFIRST) ||
	    (skb->protocol != bpf_htons(ETH_P_IP) && skb->protocol != bpf_htons(ETH_P_IPV6)))
		return false;
	/* The ingress parser stops at a non-first IPv6 fragment header; read its next protocol. */
	if (fragment == FRAGMENT_NONFIRST && skb->protocol == bpf_htons(ETH_P_IPV6) &&
	    bpf_skb_load_bytes(skb, offset, &protocol, sizeof(protocol)))
		return false;
	if (protocol != IPPROTO_UDP || reply->tuple.l4proto != IPPROTO_UDP)
		return false;
	get_tuples(skb, &tuples, &l3h, &l4h, protocol);
	if (__builtin_memcmp(&tuples.five.sip, &reply->tuple.dip, sizeof(union ip6)) ||
	    __builtin_memcmp(&tuples.five.dip, &reply->tuple.sip, sizeof(union ip6)))
		return false;
	if (fragment == FRAGMENT_NONFIRST)
		return true;
	if (tuples.five.sport != reply->tuple.dport || tuples.five.dport != reply->tuple.sport)
		return false;
	__u32 payload = bpf_ntohs(l4h.udph.len) - sizeof(struct udphdr);

	return fragment == FRAGMENT_FIRST ? payload >= packet_end - offset :
		payload == packet_end - offset;
}

// Reply traffic. Attached at Netkit peer or veth host TCX ingress.
SEC("netkit/peer")
int tproxy_dae0_ingress(struct __sk_buff *skb)
{
	struct redirect_entry *redirect_entry;

	if (skb->cb[0] == DNS_REPLY_MARK) {
		__u64 cookie = (__u64)skb->cb[2] << 32 | skb->cb[1];

		if (!cookie || cookie >> 63)
			return TC_ACT_SHOT;
		struct dns_reply *reply = bpf_map_lookup_elem(&dns_reply_map, &cookie);

		if (!reply || !dns_reply_matches(skb, reply))
			return TC_ACT_SHOT;
		redirect_entry = &reply->path;
		goto redirect;
	}
	if (skb->cb[0] != DAE_REPLY_MARK)
		return TC_ACT_SHOT;
	// reverse the tuple!
	struct redirect_tuple redirect_tuple = {};

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		bpf_skb_load_bytes(skb,
				   ETH_HLEN + offsetof(struct iphdr, daddr),
				   &redirect_tuple.sip.u6_addr32[3],
				   sizeof(redirect_tuple.sip.u6_addr32[3]));
		bpf_skb_load_bytes(skb,
				   ETH_HLEN + offsetof(struct iphdr, saddr),
				   &redirect_tuple.dip.u6_addr32[3],
				   sizeof(redirect_tuple.dip.u6_addr32[3]));
	} else {
		bpf_skb_load_bytes(skb,
				   ETH_HLEN + offsetof(struct ipv6hdr, daddr),
				   &redirect_tuple.sip,
				   sizeof(redirect_tuple.sip));
		bpf_skb_load_bytes(skb,
				   ETH_HLEN + offsetof(struct ipv6hdr, saddr),
				   &redirect_tuple.dip,
				   sizeof(redirect_tuple.dip));
	}
	redirect_entry = bpf_map_lookup_elem(&redirect_track, &redirect_tuple);

	if (!redirect_entry)
		return TC_ACT_OK;

redirect:
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
				redirect_entry->dmac, sizeof(redirect_entry->dmac), 0) ||
	    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
				redirect_entry->smac, sizeof(redirect_entry->smac), 0))
		return TC_ACT_SHOT;
	__u32 type = redirect_entry->from_wan ? PACKET_HOST : PACKET_OTHERHOST;

	if (bpf_skb_change_type(skb, type))
		return TC_ACT_SHOT;
	__u64 flags = redirect_entry->from_wan ? BPF_F_INGRESS : 0;

	skb->cb[0] = DAE_REPLY_MARK;
	skb->cb[1] = 0;
	skb->cb[2] = 0;
	return bpf_redirect(redirect_entry->ifindex, flags);
}

SEC("sk_lookup")
int tproxy_sk_lookup(struct bpf_sk_lookup *ctx)
{
	__u32 key;
	struct bpf_sock *sk;
	long ret;

	if (ctx->ingress_ifindex != PARAM.dae0peer_ifindex)
		return SK_PASS;
	if (ctx->family != AF_INET && ctx->family != AF_INET6)
		return SK_PASS;

	if (ctx->protocol == IPPROTO_TCP)
		key = 0;
	else if (ctx->protocol == IPPROTO_UDP)
		key = 1;
	else
		return SK_PASS;

	sk = bpf_map_lookup_elem(&listen_socket_map, &key);
	if (!sk)
		return SK_DROP;

	ret = bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE |
				     BPF_SK_LOOKUP_F_NO_REUSEPORT);
	bpf_sk_release(sk);
	return ret ? SK_DROP : SK_PASS;
}

struct get_real_comm_ctx {
	char *arg_buf;
	u8 l;
};

static int __noinline get_real_comm_step(__u32 index,
					 struct get_real_comm_ctx *ctx)
{
	/*
	* For string like: /usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth1
	* We extract "sddm-helper" from it.
	*/
	if (index >= MAX_ARG_LEN) // always false, just to make verifier happy
		return 1;
	if (unlikely(ctx->arg_buf[index] == '/'))
		ctx->l = index + 1;
	if (unlikely(ctx->arg_buf[index] == ' ' ||
		     ctx->arg_buf[index] == '\0')) {
		// Write to dst.
		ctx->arg_buf[index] = '\0';
		return 1;
	}
	return 0;
}

/// Parse command line arguments to get the real command name and tgid.
static __always_inline int get_pid_pname(struct pid_pname *pid_pname)
{
	int ret;

	if (!PARAM.has_bpf_get_current_task) {
		// Fallback to bpf_get_current_comm when bpf_get_current_task is
		// unavailable; process names may be truncated or less accurate.
		pid_pname->pid = bpf_get_current_pid_tgid() >> 32;
		if (bpf_get_current_comm(&pid_pname->pname,
					 sizeof(pid_pname->pname)))
			pid_pname->pname[0] = '\0';
		return 0;
	}

	// Get pointer to args string.
	struct task_struct *task = (void *)bpf_get_current_task();
	char *args = (void *)BPF_CORE_READ(task, mm, arg_start);

	// Read args to buffer.
	char arg_buf[MAX_ARG_LEN]; // Allocate it out of ctx to pass CO-RE
	struct get_real_comm_ctx ctx = {};

	ctx.arg_buf = arg_buf;
	ret = bpf_core_read_user_str(arg_buf, MAX_ARG_LEN, args);
	if (unlikely(ret < 0)) {
		bpf_printk(
			"failed to read process name: bpf_core_read_user_str: %d",
			ret);
		return ret;
	}

	// Find range of command name.
	int index;

	bpf_for(index, 0, MAX_ARG_LEN) {
		if (get_real_comm_step(index, &ctx))
			break;
	}

	__u32 offset = ctx.l;

	for (__u32 i = 0; i < TASK_COMM_LEN; i++) {
		__u32 arg_index = offset + i;

		/* Keep the checked scalar as the stack index. Otherwise LLVM can
		 * hoist arg_buf + offset and the verifier loses the bound on it.
		 */
		barrier_var(arg_index);
		if (arg_index >= MAX_ARG_LEN) {
			pid_pname->pname[i] = '\0';
			break;
		}
		char c = arg_buf[arg_index];

		pid_pname->pname[i] = c;
		if (c == '\0')
			break;
	}

	// Pupulate tgid
	ret = bpf_core_read(&pid_pname->pid, sizeof(pid_pname->pid),
			    &task->tgid);
	if (unlikely(ret < 0)) {
		bpf_printk("failed to read pid: %d", ret);
		return ret;
	}
	return 0;
}

static __always_inline void current_owner(struct pid_pname *owner)
{
	if (get_pid_pname(owner)) {
		/* Keep the pid: dae's own packets must never loop back to dae. */
		__builtin_memset(owner, 0, sizeof(*owner));
		owner->pid = bpf_get_current_pid_tgid() >> 32;
	}
}

SEC("cgroup/sock_create")
int tproxy_wan_cg_sock_create(struct bpf_sock *sk)
{
	struct pid_pname owner = {};

	current_owner(&owner);
	bpf_sk_storage_get(&socket_owner_map, sk, &owner, BPF_SK_STORAGE_GET_F_CREATE);
	return 1;
}

/* Own sockets that skipped sock_create: those opened before the hooks were
 * attached, and kernel sockets. An MPTCP subflow belongs to its connection,
 * also when a kworker connects an MP_JOIN subflow. */
static __always_inline void own_socket(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	struct pid_pname *connection = NULL;
	struct pid_pname owner = {};

	if (bpf_sk_storage_get(&socket_owner_map, sk, 0, 0))
		return;
	if (bpf_core_type_exists(struct mptcp_sock)) {
		struct mptcp_sock *msk = bpf_skc_to_mptcp_sock(sk);

		if (msk)
			connection = bpf_sk_storage_get(&socket_owner_map, msk, 0, 0);
	}
	if (connection)
		owner = *connection;
	else
		current_owner(&owner);
	bpf_sk_storage_get(&socket_owner_map, sk, &owner, BPF_SK_STORAGE_GET_F_CREATE);
}

SEC("cgroup/connect4")
int tproxy_wan_cg_connect4(struct bpf_sock_addr *ctx)
{
	own_socket(ctx);
	return 1;
}

SEC("cgroup/connect6")
int tproxy_wan_cg_connect6(struct bpf_sock_addr *ctx)
{
	own_socket(ctx);
	return 1;
}

SEC("cgroup/sendmsg4")
int tproxy_wan_cg_sendmsg4(struct bpf_sock_addr *ctx)
{
	own_socket(ctx);
	return 1;
}

SEC("cgroup/sendmsg6")
int tproxy_wan_cg_sendmsg6(struct bpf_sock_addr *ctx)
{
	own_socket(ctx);
	return 1;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	/* Get PID and TID of exiting thread/process. */
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;
	__u32 tid = id;

	/* Ignore thread exits. */
	if (pid != tid)
		return 0;

	unregister_daemon(pid);
	if (pid == PARAM.control_plane_pid) {
		__u8 exited = DAEMON_OFFLINE;

		bpf_map_update_elem(&exited_map, &zero_key, &exited, BPF_ANY);
	}
	return 0;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
