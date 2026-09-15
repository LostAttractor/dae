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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "headers/vmlinux.h"
#pragma clang diagnostic pop

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"

// #define __DEBUG_ROUTING
// #define __PRINT_ROUTING_RESULT
// #define __PRINT_SETUP_PROCESS_CONNNECTION
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
#define CLOCK_MONOTONIC 1

#define MAX_INTERFACE_NUM 256
#ifndef MAX_MATCH_SET_LEN
#define MAX_MATCH_SET_LEN \
	(32 * 32) // Should be sync with common/consts/ebpf.go.
#endif
#if MAX_MATCH_SET_LEN > 65536
#error "routing profile indices require MAX_MATCH_SET_LEN <= 65536"
#endif
#define MAX_LPM_SIZE 2048000
#define MAX_LPM_NUM (MAX_MATCH_SET_LEN + 8)
#define MAX_DST_MAPPING_NUM (65536 * 4)
#define MAX_DST_MAPPING_NUM_UDP (65536 * 2)
#define MAX_UDP_ROUTING_CACHE_NUM 65536
#define MAX_COOKIE_PID_PNAME_MAPPING_NUM 65536
#define MAX_API_CLIENT_NUM 1024
#define MAX_DOMAIN_ROUTING_NUM 65536
#define MAX_ARG_LEN 128

#define UTP_MAX_EXTENSIONS 4
#define IPV6_MAX_EXTENSIONS 8

#define ipv6_optlen(p) (((p)+1) << 3)

#define OUTBOUND_DIRECT 0
#define OUTBOUND_BLOCK 1
#define OUTBOUND_MUST_RULES 0xFC
#define OUTBOUND_CONTROL_PLANE_ROUTING 0xFD

#define ROUTE_RESULT_SKIPPED_NOALIVE 0x20000000000ULL
#define ROUTE_RESULT_CAPTURE_SHIFT 42
#define CAPTURE_HTTP 1
#define CAPTURE_DESTINATION 2
#define CAPTURE_HTTP_REQUEST 4

#define TPROXY_MARK 0x8000000

#define TIMEOUT_UDP_CONN_STATE 3e11 /* 300s */
#define UDP_ROUTING_CACHE_TTL_NS (60ULL * 1000 * 1000 * 1000)

#define NDP_REDIRECT 137

// Param keys:
static const __u32 zero_key;
static const __u32 one_key = 1;

// Outbound Connectivity Map:

struct outbound_connectivity_query {
	__u8 outbound;
	__u8 l4proto;
	__u8 ipversion;
};

enum outbound_connectivity_state {
	/* WARNING: explicit values must stay in sync with connectivity.go. */
	OUTBOUND_CONNECTIVITY_ALIVE = 0,
	OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT = 1,
	OUTBOUND_CONNECTIVITY_NOALIVE_BLOCK = 2,
	OUTBOUND_CONNECTIVITY_NOALIVE_TRY_SNIFF = 3,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct outbound_connectivity_query);
	__type(value, __u32); // enum outbound_connectivity_state
	__uint(max_entries, 256 * 2 * 2); // outbound * l4proto * ipversion
} outbound_connectivity_map SEC(".maps");

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

struct redirect_entry {
	__u32 ifindex;
	__u8 smac[6];
	__u8 dmac[6];
	__u8 from_wan;
};

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
};

struct routing_result {
	__u32 mark;
	__u8 must;
	__u8 mac[6];
	__u8 outbound;
	__u8 pname[TASK_COMM_LEN];
	__u32 pid;
	__u32 ifindex;
	__u32 profile_id;
	__u8 dscp;
	__u8 capture_flags;
	__u8 protocol;
	__u8 no_sniff;
	__u64 route_epoch;
};

_Static_assert(sizeof(struct routing_result) == 56,
	       "routing_result pinned-map ABI changed unexpectedly");
_Static_assert(__builtin_offsetof(struct routing_result, capture_flags) == 41,
	       "routing_result capture flags ABI offset");

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

/* Preserve all metadata produced by ingress for the first source decision.
 * pid/pname are not populated in routing_result by ingress; process-name
 * predicates use the socket cookie map separately. Do not restore identity
 * from later packets: interfaces, DSCP and policies can change mid-lifetime.
 */
struct routing_decision {
	__u64 route_epoch;
	__u32 mark;
	__u32 ifindex;
	__u32 profile_id;
	__u8 mac[6];
	__u8 outbound;
	__u8 must;
	__u8 capture_flags;
	__u8 protocol;
	__u8 no_sniff;
	__u8 dscp;
};

struct udp_routing_cache_value {
	struct routing_decision result;
	__u64 cached_until;
	struct bpf_timer timer;
	struct bpf_spin_lock lock;
	__u32 closing;
};

/* Zeroed timer/lock bytes for insertion, without a timer in a per-CPU map. */
struct udp_routing_scratch {
	struct routing_decision result;
	__u64 cached_until;
	__u64 zero[3];
};

_Static_assert(sizeof(struct routing_decision) == 32, "UDP decision ABI size");
_Static_assert(sizeof(struct udp_routing_cache_key) == 24, "UDP source key ABI size");
_Static_assert(sizeof(struct udp_routing_cache_value) == 64, "UDP cache value ABI size");
_Static_assert(__builtin_offsetof(struct udp_routing_cache_value, cached_until) == 32,
	       "UDP cache expiry ABI offset");
_Static_assert(sizeof(struct udp_routing_scratch) == sizeof(struct udp_routing_cache_value),
	       "UDP insertion layout mismatch");

/* Keep ingress temporaries off the limited BPF stack. */
struct ingress_scratch {
	struct tuples tuples;
	struct routing_result result;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ingress_scratch);
	__uint(max_entries, 1);
} ingress_scratch_map SEC(".maps");

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
} unused_device_routes SEC(".maps");

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
	__u32 so_mark_from_dae;
};

volatile const struct dae_param PARAM = {};

/* Updated only when publishing a control plane; zero disables observation. */
volatile __be16 api_port;
volatile __u32 default_routing_profile;

struct api_client {
	__u64 observed_at;
	__u8 mac[6];
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
	__type(value, struct routing_result); // outbound
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	/// NOTICE: It MUST be pinned.
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_tuples_map SEC(".maps");

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
	__type(value, __u64);
	__uint(max_entries, MAX_UDP_ROUTING_CACHE_NUM);
} udp_bindings_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct udp_routing_scratch);
	__uint(max_entries, 1);
} udp_routing_scratch_map SEC(".maps");

#include "routing_abi.h"

struct ip_port_proto {
	__u32 ip[4];
	__be16 port;
	__u8 proto;
};

struct pid_pname {
	__u32 pid;
	char pname[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct pid_pname);
	__uint(max_entries, MAX_COOKIE_PID_PNAME_MAPPING_NUM);
	/// NOTICE: No persistence.
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_pid_map SEC(".maps");
// 6.29 MB

struct udp_conn_state {
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	// For traffic from lan that go through wan ingress, dae parse them in lan egress
	bool is_wan_ingress_direction;

	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DST_MAPPING_NUM_UDP);
	__type(key, struct tuples_key);
	__type(value, struct udp_conn_state);
} udp_conn_state_map SEC(".maps");
// 16.78 MB

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} exited_map SEC(".maps");

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
	if (value->closing) {
		bpf_spin_unlock(&value->lock);
		return 0;
	}
	if (value->cached_until > now)
		remaining = value->cached_until - now;
	else
		value->closing = 1;
	bpf_spin_unlock(&value->lock);
	if (remaining)
		bpf_timer_start(&value->timer, remaining, 0);
	else
		bpf_map_delete_elem(&udp_routing_cache_map, key);
	return 0;
}

static __always_inline void expand_udp_decision(struct routing_result *result,
					       const struct routing_decision *decision)
{
	__builtin_memset(result, 0, sizeof(*result));
	result->route_epoch = decision->route_epoch;
	result->mark = decision->mark;
	result->ifindex = decision->ifindex;
	result->profile_id = decision->profile_id;
	result->outbound = decision->outbound;
	result->must = decision->must;
	result->capture_flags = decision->capture_flags;
	result->protocol = decision->protocol;
	result->no_sniff = decision->no_sniff;
	result->dscp = decision->dscp;
	__builtin_memcpy(result->mac, decision->mac, sizeof(result->mac));
}

static __always_inline void compact_udp_decision(struct routing_decision *decision,
					        const struct routing_result *result)
{
	decision->route_epoch = result->route_epoch;
	decision->mark = result->mark;
	decision->ifindex = result->ifindex;
	decision->profile_id = result->profile_id;
	decision->outbound = result->outbound;
	decision->must = result->must;
	decision->capture_flags = result->capture_flags;
	decision->protocol = result->protocol;
	decision->no_sniff = result->no_sniff;
	decision->dscp = result->dscp;
	__builtin_memcpy(decision->mac, result->mac, sizeof(decision->mac));
}

/* 1 = hit, 0 = new lifetime, -1 = another packet/timer is ending it. */
static __noinline int read_udp_route(struct udp_routing_cache_key *key,
					 struct routing_result *result)
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
	bool stale = device && device->epoch != value->result.route_epoch;

	bpf_spin_lock(&value->lock);
	if (value->closing) {
		bpf_spin_unlock(&value->lock);
		return -1;
	}
	expired = stale || value->cached_until <= now;
	if (expired) {
		value->closing = 1;
	} else {
		value->cached_until = now + UDP_ROUTING_CACHE_TTL_NS;
		expand_udp_decision(result, &value->result);
	}
	bpf_spin_unlock(&value->lock);
	if (expired) {
		bpf_map_delete_elem(&udp_routing_cache_map, key);
		return 0;
	}
	return 1;
}

static __noinline int save_udp_route(struct udp_routing_cache_key *key,
				    struct routing_result *result)
{
	struct udp_routing_scratch *value =
		bpf_map_lookup_elem(&udp_routing_scratch_map, &zero_key);

	if (!value)
		return -1;
	__builtin_memset(value, 0, sizeof(*value));
	compact_udp_decision(&value->result, result);
	value->cached_until = bpf_ktime_get_ns() + UDP_ROUTING_CACHE_TTL_NS;
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
	/* Concurrent first packets must all adopt the winning decision. */
	return read_udp_route(key, result) == 1 ? 0 : -1;
}

static __always_inline int prep_redirect_to_control_plane(
	struct __sk_buff *skb, bool from_wan, __u32 link_h_len,
	struct tuples *tuples, struct ethhdr *ethh)
{
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
	if (bpf_map_update_elem(&redirect_track, &redirect_tuple,
				&redirect_entry, BPF_ANY))
		return -1;

	skb->cb[0] = TPROXY_MARK;
	return 0;
}

static int refresh_udp_conn_state_timer_cb(void *_udp_conn_state_map,
					   struct tuples_key *key,
					   struct udp_conn_state *val)
{
	bpf_map_delete_elem(&udp_conn_state_map, key);
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

static __always_inline struct udp_conn_state *
refresh_udp_conn_state_timer(struct tuples_key *key, bool is_wan_ingress_direction)
{
	struct udp_conn_state *state = bpf_map_lookup_elem(&udp_conn_state_map, key);

	if (state)
		goto rearm;

	struct udp_conn_state new_state = {};

	new_state.is_wan_ingress_direction = is_wan_ingress_direction;
	if (unlikely(bpf_map_update_elem(&udp_conn_state_map, key, &new_state, BPF_NOEXIST)))
		return NULL;

	state = bpf_map_lookup_elem(&udp_conn_state_map, key);
	if (unlikely(!state))
		return NULL;

	bpf_timer_init(&state->timer, &udp_conn_state_map, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&state->timer, refresh_udp_conn_state_timer_cb);

rearm:
	bpf_timer_start(&state->timer, TIMEOUT_UDP_CONN_STATE, 0);
	return state;
}

// Cookie will change after the first packet, so we just use it for
// handshake.
static __always_inline bool pid_is_control_plane(struct __sk_buff *skb,
						 struct pid_pname **pid_pname)
{
	/// NOTICE: No pid pname info for LAN packet.
	// Maybe this packet is also in the host (such as docker) ?
	// I tried and it is false.
	// __u64 cookie = bpf_get_socket_cookie(skb);
	// struct pid_pname *pid_pname = bpf_map_lookup_elem(&cookie_pid_map, &cookie);
	// if (pid_pname) ...
	__u64 cookie = bpf_get_socket_cookie(skb);
	*pid_pname = bpf_map_lookup_elem(&cookie_pid_map, &cookie);

	if (!PARAM.control_plane_pid) {
		bpf_printk("control_plane_pid is not set.");
		return false;
	}
	if (!*pid_pname)
		return false;
	return (*pid_pname)->pid == PARAM.control_plane_pid;
}

static __always_inline int do_tproxy_first_fragment(
	struct __sk_buff *skb, bool is_wan, struct ethhdr *ethh,
	struct l3_hdr *l3h, struct l4_hdr *l4h, __u8 l4proto,
	__u32 payload_offset, __u32 packet_end, int parse_ret)
{
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

		if (conn_state && conn_state->is_wan_ingress_direction) {
			if (skb->mark)
				return TCX_DROP;
			goto direct;
		}
	}

	if (l4proto == IPPROTO_TCP && !(l4h->tcph.syn && !l4h->tcph.ack)) {
		struct routing_result *saved = bpf_map_lookup_elem(&routing_tuples_map, &tuples->five);

		/* An invalid first fragment must not complete the old TCP segment. */
		if (route_epoch && (!saved || saved->route_epoch != route_epoch))
			return TCX_DROP;
		if (saved && (saved->outbound != OUTBOUND_DIRECT || saved->mark || saved->capture_flags))
			return TCX_DROP;
		goto direct;
	}
	struct udp_routing_cache_key udp_key = {};
	if (l4proto == IPPROTO_UDP) {
		struct routing_result *saved = &scratch->result;

		fill_udp_routing_cache_key(&udp_key, tuples);
		if (bpf_map_lookup_elem(&udp_bindings_map, &udp_key))
			return TCX_DROP;
		int hit = read_udp_route(&udp_key, saved);

		if (hit < 0 || (hit && (saved->outbound != OUTBOUND_DIRECT || saved->mark || saved->capture_flags)))
			return TCX_DROP;
		if (hit)
			goto direct;
	}

	struct route_params params;

	params.l4hdr = l4h;
	if (l4proto == IPPROTO_TCP) {
		params.l4proto_type = L4ProtoType_TCP;
	} else {
		params.l4proto_type = L4ProtoType_UDP;
		if (is_utp(skb, l4proto, payload_offset, packet_end))
			params.l4proto_type |= (1 << 2);
	}
	if (skb->protocol == bpf_htons(ETH_P_IP))
		params.ipversion_type = IpVersionType_4;
	else
		params.ipversion_type = IpVersionType_6;
	params.pname = pid_pname ? (const __be32 *)pid_pname->pname : NULL;
	params.dscp = tuples->dscp;
	params.ifindex = skb->ifindex;
	params.mac = ethh->h_source;
	params.saddr = tuples->five.sip.u6_addr32;
	params.daddr = tuples->five.dip.u6_addr32;
	params.isdns = tuples->five.dport == bpf_htons(53) &&
			 l4proto == IPPROTO_UDP;

	if (select_routing_profile(&params))
		return TCX_DROP;
	__s64 route_result = route(&params);

	if (route_result < 0 || (route_result >> ROUTE_RESULT_CAPTURE_SHIFT))
		return TCX_DROP;
	__u8 outbound = route_result;
	__u32 mark = route_result >> 8;

	if (outbound == OUTBOUND_DIRECT) {
		if (mark || skb->mark)
			return TCX_DROP;
		struct routing_result *result = &scratch->result;

		__builtin_memset(result, 0, sizeof(*result));
		result->outbound = OUTBOUND_DIRECT;
		result->route_epoch = route_epoch;
		result->profile_id = params.profile_id;

		__builtin_memcpy(result->mac, ethh->h_source, sizeof(result->mac));
		if (l4proto == IPPROTO_UDP) {
			if (save_udp_route(&udp_key, result) || result->outbound != OUTBOUND_DIRECT)
				return TCX_DROP;
		} else if (route_epoch && bpf_map_update_elem(&routing_tuples_map, &tuples->five, result, BPF_ANY)) {
			return TCX_DROP;
		}
		goto direct;
	}
	if (outbound == OUTBOUND_BLOCK)
		return TCX_DROP;


	/* Proxying only the first fragment would split the datagram across paths. */
	return TCX_DROP;

direct:
	device = device_route(ethh->h_source);
	if (device && (device->updating || device->epoch != route_epoch))
		return TCX_DROP;
	if (l4proto == IPPROTO_UDP &&
	    !refresh_udp_conn_state_timer(&tuples->five, false))
		return TCX_DROP;
	skb->mark = 0;
	return TCX_NEXT;
}

static __always_inline void observe_api_client(
	const struct tuples_key *key, const struct ethhdr *ethh)
{
	struct api_client client = {
		.observed_at = bpf_ktime_get_ns(),
	};

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

	// Backup for feature use.
	// 由于向helper function传递了skb, 一旦verifier无法推断出skb是否被修改, 则可能在访问skb时出现问题
	u16 protocol = skb->protocol;
	u32 ifindex = skb->ifindex;

	/* Observe the actual LAN ingress before direct TCP's established-flow
	 * shortcut. This keeps HTTP keep-alive requests fresh without depending
	 * on the L3 route device, ARP device, or bridge/bond topology.
	 */
	if (!is_wan && link_h_len == ETH_HLEN && l4proto == IPPROTO_TCP &&
	    api_port && tuples->five.dport == api_port)
		observe_api_client(&tuples->five, ethh);

	struct pid_pname *pid_pname = NULL;

	if (is_wan && pid_is_control_plane(skb, &pid_pname)) {
		// From control plane. Direct.
		return TCX_NEXT;
	}

	bool isdns = tuples->five.dport == bpf_htons(53) && l4proto == IPPROTO_UDP;

	struct device_route_state *device = device_route(ethh->h_source);
	struct ip_port destination = { .ip = tuples->five.dip, .port = tuples->five.dport };

	if (l4proto == IPPROTO_TCP && bpf_map_lookup_elem(&route_exempt_map, &destination))
		device = NULL;
	if (device && device->updating)
		return TCX_DROP;
	__u64 route_epoch = device ? device->epoch : 0;

	struct tuples_key routing_tuples_key = tuples->five;

	if (l4proto == IPPROTO_TCP && !(l4h->tcph.syn && !l4h->tcph.ack)) {
		// Established TCP Connection.
		struct routing_result *routing_result =
			bpf_map_lookup_elem(&routing_tuples_map,
					    &routing_tuples_key);

		if (route_epoch && (!routing_result || routing_result->route_epoch != route_epoch)) {
			/* Never re-route established TCP. The transparent listener rejects
			 * an ACK without a connection with RST; existing relays also receive
			 * the userspace Abort. Do not answer an incoming RST. */
			if (l4h->tcph.rst)
				return TCX_DROP;
			goto control_plane;
		}

		if (routing_result) {
			if (routing_result->outbound == OUTBOUND_DIRECT &&
			    !routing_result->capture_flags) {
				// Restore the policy-routing mark for the rest of a
				// direct(mark:N) TCP flow.
				skb->mark = routing_result->mark;
				return TCX_NEXT;
			}
			goto control_plane;
		}

		// Non-proxy connections or previous connections.
		return TCX_NEXT;
	}

	if (l4proto == IPPROTO_UDP) {
		struct udp_conn_state *conn_state =
			refresh_udp_conn_state_timer(&tuples->five, false);
		if (!conn_state)
			return TCX_DROP;
		if (conn_state->is_wan_ingress_direction) {
			// Replay (outbound) of an inbound flow
			// => direct.
			return TCX_NEXT;
		}
	}

	struct routing_result *routing_result = &scratch->result;

	__builtin_memset(routing_result, 0, sizeof(*routing_result));
	struct udp_routing_cache_key udp_key = {};

	if (l4proto == IPPROTO_UDP) {
		fill_udp_routing_cache_key(&udp_key, tuples);
		__u64 *binding = bpf_map_lookup_elem(&udp_bindings_map, &udp_key);

		if (binding) {
			/* Its endpoint releases the old source before a new lifetime starts. */
			if (*binding != route_epoch)
				return TCX_DROP;
			goto control_plane;
		}
		int hit = read_udp_route(&udp_key, routing_result);

		if (hit < 0)
			return TCX_DROP;
		if (hit) {
			/* A later DNS destination is part of this source's relay. */
			if (isdns)
				routing_result->must = 1;
			goto selected;
		}
	}

	struct route_params params;

	params.l4hdr = l4h;
	params.l4proto_type = l4proto == IPPROTO_TCP ? L4ProtoType_TCP : L4ProtoType_UDP;
	if (l4proto == IPPROTO_UDP && is_utp(skb, l4proto, offset, packet_end))
		params.l4proto_type |= (1 << 2);
	params.ipversion_type = protocol == bpf_htons(ETH_P_IP) ? IpVersionType_4 : IpVersionType_6;
	params.pname = pid_pname ? (const __be32 *)pid_pname->pname : NULL;
	params.dscp = tuples->dscp;
	params.ifindex = ifindex;
	params.mac = ethh->h_source;
	params.saddr = tuples->five.sip.u6_addr32;
	params.daddr = tuples->five.dip.u6_addr32;
	params.isdns = isdns;

	if (select_routing_profile(&params))
		return TCX_DROP;
	__s64 route_ret = route(&params);

	if (route_ret < 0)
		return TCX_DROP;
	routing_result->route_epoch = route_epoch;
	routing_result->profile_id = params.profile_id;
	routing_result->outbound = route_ret;
	routing_result->mark = route_ret >> 8;
	routing_result->must = (route_ret >> 40) & 1;
	routing_result->capture_flags = route_ret >> ROUTE_RESULT_CAPTURE_SHIFT;
	routing_result->protocol = params.l4proto_type;
	routing_result->dscp = tuples->dscp;
	routing_result->ifindex = ifindex;
	__builtin_memcpy(routing_result->mac, ethh->h_source, sizeof(routing_result->mac));

	if (routing_result->outbound == OUTBOUND_BLOCK)
		return TCX_DROP;
	if (!isdns && !routing_result->capture_flags && routing_result->outbound != OUTBOUND_DIRECT &&
	    routing_result->outbound < OUTBOUND_MUST_RULES) {
		struct outbound_connectivity_query q = {
			.outbound = routing_result->outbound,
			.ipversion = protocol == bpf_htons(ETH_P_IP) ? 4 : 6,
			.l4proto = l4proto,
		};
		__u32 *state = bpf_map_lookup_elem(&outbound_connectivity_map, &q);

		if (!state || *state == OUTBOUND_CONNECTIVITY_NOALIVE_BLOCK)
			return TCX_DROP;
		/* Direct fallback stays attributable to its original group and
		 * controllable by its recovery policy, including for TCP. */
		if (*state == OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT)
			routing_result->no_sniff = 1;
	}
	if (l4proto == IPPROTO_UDP && (!isdns || routing_result->must || routing_result->capture_flags) &&
	    save_udp_route(&udp_key, routing_result))
		return TCX_DROP;

selected:
	/* A membership commit may have raced route evaluation. */
	device = device_route(ethh->h_source);
	if (device && (device->updating || device->epoch != route_epoch) &&
	    !(l4proto == IPPROTO_TCP && bpf_map_lookup_elem(&route_exempt_map, &destination)))
		return TCX_DROP;
	if (routing_result->outbound == OUTBOUND_DIRECT && !routing_result->capture_flags) {
		if (l4proto == IPPROTO_TCP && (routing_result->mark || route_epoch) &&
		    bpf_map_update_elem(&routing_tuples_map, &routing_tuples_key,
				routing_result, BPF_ANY))
			return TCX_DROP;
		goto direct;
	}
	if (bpf_map_update_elem(&routing_tuples_map, &routing_tuples_key,
				routing_result, BPF_ANY))
		return TCX_DROP;

control_plane:
	// Assign to control plane.
	if (prep_redirect_to_control_plane(skb, is_wan, link_h_len, tuples,
					   ethh))
		return TCX_DROP;
	return bpf_redirect(PARAM.dae0_ifindex, 0);

direct:
	// A new SYN can reuse a formerly proxied or marked tuple, including
	// when an unavailable selector falls back to plain direct.
	if (l4proto == IPPROTO_TCP && !routing_result->mark && !route_epoch)
		bpf_map_delete_elem(&routing_tuples_map, &routing_tuples_key);
	skb->mark = routing_result->mark;
	return TCX_NEXT;

}

static __always_inline int do_tproxy(struct __sk_buff *skb, bool is_wan,
				     u32 link_h_len)
{
	__u8 *exited = bpf_map_lookup_elem(&exited_map, &zero_key);

	if (exited && *exited)
		return TCX_NEXT;

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
		return TCX_NEXT;
	if (fragment_state == FRAGMENT_FIRST)
		return do_tproxy_first_fragment(skb, is_wan, &ethh, &l3h,
			&l4h, l4proto, offset, packet_end, ret);
	return do_tproxy_unfragmented(skb, is_wan, link_h_len, &ethh, &l3h,
		&l4h, l4proto, offset, packet_end, ret);
}

static __always_inline int do_reply_path(struct __sk_buff *skb, u32 link_h_len,
					 bool drop_ndp_redirect)
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

	if (drop_ndp_redirect && skb->ingress_ifindex == NOWHERE_IFINDEX &&
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

		/* Replies also keep a kernel-direct source lifetime alive. */
		read_udp_route(&source, &ignored);


		if (!refresh_udp_conn_state_timer(&reversed_tuples_key, true))
			return TCX_DROP;
	}

	return TCX_NEXT;
}

SEC("tc/lan_egress_l2")
int lan_egress_l2(struct __sk_buff *skb)
{
	return do_reply_path(skb, ETH_HLEN, true);
}

SEC("tc/lan_egress_l3")
int lan_egress_l3(struct __sk_buff *skb)
{
	return do_reply_path(skb, 0, true);
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
	return do_reply_path(skb, ETH_HLEN, false);
}

SEC("tc/wan_ingress_l3")
int tproxy_wan_ingress_l3(struct __sk_buff *skb)
{
	return do_reply_path(skb, 0, false);
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

// Proxy traffic.
SEC("netkit/primary")
int tproxy_dae0peer_ingress(struct __sk_buff *skb)
{
	// Only packets redirected from wan_egress or lan_ingress have this cb mark.
	if (skb->cb[0] != TPROXY_MARK)
		return TC_ACT_SHOT;
	skb->cb[0] = 0;

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
	// TODO: 直接redirect到lo?
	skb->mark = TPROXY_MARK;
	if (bpf_skb_change_type(skb, PACKET_HOST))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

// Reply traffic.
SEC("netkit/peer")
int tproxy_dae0_ingress(struct __sk_buff *skb)
{
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
	struct redirect_entry *redirect_entry =
		bpf_map_lookup_elem(&redirect_track, &redirect_tuple);

	if (!redirect_entry)
		return TC_ACT_OK;

	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
			    redirect_entry->dmac, sizeof(redirect_entry->dmac),
			    0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
			    redirect_entry->smac, sizeof(redirect_entry->smac),
			    0);
	__u32 type = redirect_entry->from_wan ? PACKET_HOST : PACKET_OTHERHOST;

	bpf_skb_change_type(skb, type);
	__u64 flags = redirect_entry->from_wan ? BPF_F_INGRESS : 0;

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

static __always_inline int _update_map_elem_by_cookie(const __u64 cookie,
						      struct pid_pname *val)
{
	if (unlikely(!cookie)) {
		bpf_printk("zero cookie");
		return -EINVAL;
	}
	if (bpf_map_lookup_elem(&cookie_pid_map, &cookie)) {
		// Cookie to pid mapping already exists.
		return 0;
	}

	int ret;

	ret = get_pid_pname(val);
	if (ret)
		return ret;

	// Update map.
	ret = bpf_map_update_elem(&cookie_pid_map, &cookie, val, BPF_ANY);
	if (unlikely(ret)) {
		// bpf_printk("setup_mapping_from_sk: failed update map: %d", ret);
		return ret;
	}

#ifdef __PRINT_SETUP_PROCESS_CONNNECTION
	bpf_printk("setup_mapping: %llu -> %s (%d)", cookie, val.pname,
		   val.pid);
#endif
	return 0;
}

static __always_inline int update_map_elem_by_cookie(const __u64 cookie)
{
	int ret;
	struct pid_pname val = {};

	ret = _update_map_elem_by_cookie(cookie, &val);
	if (ret) {
		// Fallback to only write pid to avoid loop due to packets sent by dae.
		val.pid = bpf_get_current_pid_tgid() >> 32;
		bpf_map_update_elem(&cookie_pid_map, &cookie, &val, BPF_ANY);
		return ret;
	}
	return 0;
}

// Create cookie to pid, pname mapping.
SEC("cgroup/sock_create")
int tproxy_wan_cg_sock_create(struct bpf_sock *sk)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(sk));
	return 1;
}

// Remove cookie to pid, pname mapping.
SEC("cgroup/sock_release")
int tproxy_wan_cg_sock_release(struct bpf_sock *sk)
{
	__u64 cookie = bpf_get_socket_cookie(sk);

	if (unlikely(!cookie)) {
		bpf_printk("zero cookie");
		return 1;
	}
	bpf_map_delete_elem(&cookie_pid_map, &cookie);
	return 1;
}

SEC("cgroup/connect4")
int tproxy_wan_cg_connect4(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/connect6")
int tproxy_wan_cg_connect6(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg4")
int tproxy_wan_cg_sendmsg4(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg6")
int tproxy_wan_cg_sendmsg6(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
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

	if (pid == PARAM.control_plane_pid)
		bpf_map_update_elem(&exited_map, &zero_key, &one_key, BPF_ANY);
	return 0;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
