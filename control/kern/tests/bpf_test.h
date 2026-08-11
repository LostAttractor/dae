// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

#define IP4_HLEN sizeof(struct iphdr)
#define IP6_HLEN sizeof(struct ipv6hdr)
#define TCP_HLEN sizeof(struct tcphdr)

#define OUTBOUND_USER_DEFINED_MIN 2

#define IPV4(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

static const __u32 two_key = 2;
static const __u32 three_key = 3;
static const __u32 four_key = 4;

static __always_inline int
set_ipv4_tcp(struct __sk_buff *skb,
	     __u32 saddr, __u32 daddr,
	     __u16 sport, __u16 dport)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	ip->ihl = 5;
	ip->version = 4;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = bpf_htonl(saddr);
	ip->daddr = bpf_htonl(daddr);
	ip->tos = 4 << 2;

	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	tcp->source = bpf_htons(sport);
	tcp->dest = bpf_htons(dport);
	tcp->syn = 1;

	return TC_ACT_OK;
}

static __always_inline int
check_routing_ipv4_tcp_with_result(struct __sk_buff *skb,
				   __u32 expected_status_code,
				   __u8 expected_outbound,
				   __u8 expected_must,
				   __u32 saddr, __u32 daddr,
				   __u16 sport, __u16 dport)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code, expected_status_code);
		return TC_ACT_SHOT;
	}

	if (expected_status_code == TC_ACT_REDIRECT) {
		if (skb->cb[0] != TPROXY_MARK) {
			bpf_printk("skb->cb[0] != TPROXY_MARK\n");
			return TC_ACT_SHOT;
		}

		if (skb->cb[1] != IPPROTO_TCP) {
			bpf_printk("skb->cb[1] != IPPROTO_TCP\n");
			return TC_ACT_SHOT;
		}

	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("eth->h_proto != ETH_P_IP\n");
		return TC_ACT_SHOT;
	}

	struct iphdr *ip = (void *)eth + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}
	if (ip->saddr != bpf_htonl(saddr)) {
		bpf_printk("ip->saddr != %pI4\n", &saddr);
		return TC_ACT_SHOT;
	}
	if (ip->daddr != bpf_htonl(daddr)) {
		bpf_printk("ip->daddr != %pI4\n", &daddr);
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->source != bpf_htons(sport)) {
		bpf_printk("tcp->source != %d\n", sport);
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(dport)) {
		bpf_printk("tcp->dest != %d\n", dport);
		return TC_ACT_SHOT;
	}

	if (expected_status_code == TC_ACT_REDIRECT) {
		struct tuples tuples = {};
		tuples.five.sip.u6_addr32[2] = bpf_htonl(0xffff);
		tuples.five.sip.u6_addr32[3] = ip->saddr;
		tuples.five.dip.u6_addr32[2] = bpf_htonl(0xffff);
		tuples.five.dip.u6_addr32[3] = ip->daddr;
		tuples.five.sport = tcp->source;
		tuples.five.dport = tcp->dest;
		tuples.five.l4proto = ip->protocol;

		struct routing_result *routing_result;
		routing_result = bpf_map_lookup_elem(&routing_tuples_map, &tuples.five);
		if (!routing_result) {
			bpf_printk("routing_result == NULL\n");
			return TC_ACT_SHOT;
		}

		if (routing_result->outbound != expected_outbound) {
			bpf_printk("routing_result->outbound(%u) != %u\n",
				   routing_result->outbound, expected_outbound);
			return TC_ACT_SHOT;
		}
		if (routing_result->must != expected_must) {
			bpf_printk("routing_result->must(%u) != %u\n",
				   routing_result->must, expected_must);
			return TC_ACT_SHOT;
		}
	}

	return TC_ACT_OK;
}

static __always_inline int
check_routing_ipv4_tcp_with_outbound(struct __sk_buff *skb,
				     __u32 expected_status_code,
				     __u8 expected_outbound,
				     __u32 saddr, __u32 daddr,
				     __u16 sport, __u16 dport)
{
	return check_routing_ipv4_tcp_with_result(
		skb, expected_status_code, expected_outbound, false,
		saddr, daddr, sport, dport);
}

static __always_inline int
check_routing_ipv4_tcp(struct __sk_buff *skb,
			       __u32 expected_status_code,
		       __u32 saddr, __u32 daddr,
		       __u16 sport, __u16 dport)
{
	return check_routing_ipv4_tcp_with_outbound(
		skb, expected_status_code, OUTBOUND_USER_DEFINED_MIN,
		saddr, daddr, sport, dport);
}

static __always_inline void
set_domain_routing_word(__u32 daddr, __u32 word, __u32 bump_bits,
			__u32 routing_bits)
{
	__be32 key[4] = {};
	key[2] = bpf_htonl(0x0000ffff);
	key[3] = bpf_htonl(daddr);

	struct domain_routing value = {};
	value.bump[word] = bump_bits;
	value.routing[word] = routing_bits;
	bpf_map_update_elem(&domain_routing_map, &key, &value, BPF_ANY);
}

static __always_inline void
set_domain_routing(__u32 daddr, __u32 bump_bits, __u32 routing_bits)
{
	set_domain_routing_word(daddr, 0, bump_bits, routing_bits);
}

static __always_inline void
set_outbound_connectivity(__u8 outbound)
{
	struct outbound_connectivity_query query = {
		.outbound = outbound,
		.ipversion = 4,
		.l4proto = IPPROTO_TCP,
	};
	bpf_map_update_elem(&outbound_connectivity_map, &query, &zero_key, BPF_ANY);

	struct outbound_connectivity_query query2 = {
		.outbound = outbound,
		.ipversion = 6,
		.l4proto = IPPROTO_TCP,
	};
	bpf_map_update_elem(&outbound_connectivity_map, &query2, &zero_key, BPF_ANY);

	struct outbound_connectivity_query query3 = {
		.outbound = outbound,
		.ipversion = 4,
		.l4proto = IPPROTO_UDP,
	};
	bpf_map_update_elem(&outbound_connectivity_map, &query3, &zero_key, BPF_ANY);
	
	struct outbound_connectivity_query query4 = {
		.outbound = outbound,
		.ipversion = 6,
		.l4proto = IPPROTO_UDP,
	};
	bpf_map_update_elem(&outbound_connectivity_map, &query4, &zero_key, BPF_ANY);
}

static __always_inline void
set_routing_fallback(__u8 outbound, bool must, const void *key)
{
	struct match_set ms = {
		.type = MatchType_Fallback,
		.outbound = outbound,
		.must = must,
	};
	bpf_map_update_elem(&routing_map, key, &ms, BPF_ANY);
	set_outbound_connectivity(outbound);
}
static __always_inline void
set_outbound_connectivity_dead_try_sniff(__u8 outbound)
{
	__u32 dead = OUTBOUND_CONNECTIVITY_NOALIVE_TRY_SNIFF;

	struct outbound_connectivity_query query = {
		.outbound = outbound,
		.ipversion = 4,
		.l4proto = IPPROTO_TCP,
	};
	bpf_map_update_elem(&outbound_connectivity_map, &query, &dead, BPF_ANY);
}
