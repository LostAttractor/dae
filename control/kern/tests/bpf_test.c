// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

#define __DEBUG
#define __DEBUG_ROUTING
#define __PRINT_ROUTING_RESULT

#include "../tproxy.c"
#include "./bpf_test.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map SEC(".maps") = {
	.values = {
		[0] = &tproxy_wan_egress_l2,
	},
};

SEC("tc/pktgen/dport_match")
int testpktgen_dport_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/dport_match")
int testsetup_dport_match(struct __sk_buff *skb)
{
	/* dport(80) -> proxy */
	struct match_set ms = {
		.port_range = {80, 80},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dport_match")
int testcheck_dport_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/dport_mismatch")
int testpktgen_dport_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/dport_mismatch")
int testsetup_dport_mismatch(struct __sk_buff *skb)
{
	/* dport(80) -> proxy */
	struct match_set ms = {
		.port_range = {80, 80},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dport_mismatch")
int testcheck_dport_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/ipset_match")
int testpktgen_ipset_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(224,1,0,2), 19233, 80);
}

SEC("tc/setup/ipset_match")
int testsetup_ipset_match(struct __sk_buff *skb)
{
	/* dip(224.1.0.0/16) -> direct */
	struct match_set ms = {
		.type = MatchType_IpSet,
		.outbound = OUTBOUND_DIRECT,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_DIRECT);

	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 112 }, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xe0010000); // 224.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipset_match")
int testcheck_ipset_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(224,1,0,2),
				      19233, 80);
}

SEC("tc/pktgen/ipset_mismatch")
int testpktgen_ipset_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(225,1,0,2), 19233, 80);
}

SEC("tc/setup/ipset_mismatch")
int testsetup_ipset_mismatch(struct __sk_buff *skb)
{
	// dip(224.1.0.0/16) -> direct
	struct match_set ms = {
		.type = MatchType_IpSet,
		.outbound = OUTBOUND_DIRECT,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_DIRECT);

	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 112 }, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xe0010000); // 224.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipset_mismatch")
int testcheck_ipset_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(225,1,0,2),
				      19233, 80);
}

SEC("tc/pktgen/source_ipset_match")
int testpktgen_source_ipset_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,50,1), IPV4(224,1,0,2), 19233, 80);
}

SEC("tc/setup/source_ipset_match")
int testsetup_source_ipset_match(struct __sk_buff *skb)
{
	/* sip(192.168.50.0/24) -> direct */
	struct match_set ms = {
		.type = MatchType_SourceIpSet,
		.outbound = OUTBOUND_DIRECT,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_DIRECT);

	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 120 },
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xc0a83200); // 192.168.50.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/source_ipset_match")
int testcheck_source_ipset_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,50,1), IPV4(224,1,0,2),
				      19233, 80);
}

SEC("tc/pktgen/source_ipset_mismatch")
int testpktgen_source_ipset_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,51,1), IPV4(224,1,0,2), 19233, 80);
}

SEC("tc/setup/source_ipset_mismatch")
int testsetup_source_ipset_mismatch(struct __sk_buff *skb)
{
	/* sip(192.168.50.0/24) -> direct */
	struct match_set ms = {
		.type = MatchType_SourceIpSet,
		.outbound = OUTBOUND_DIRECT,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_DIRECT);

	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 120 },
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0xc0a83200); // 192.168.50.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: proxy */
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/source_ipset_mismatch")
int testcheck_source_ipset_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,51,1), IPV4(224,1,0,2),
				      19233, 80);
}

SEC("tc/pktgen/sport_match")
int testpktgen_sport_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/sport_match")
int testsetup_sport_match(struct __sk_buff *skb)
{
	/* sport(19000-20000) -> proxy */
	struct match_set ms = {
		.port_range = {19000, 20000},
		.type = MatchType_SourcePort,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/sport_match")
int testcheck_sport_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/sport_mismatch")
int testpktgen_sport_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/sport_mismatch")
int testsetup_sport_mismatch(struct __sk_buff *skb)
{
	/* sport(19230-19232) -> proxy */
	struct match_set ms = {
		.port_range = {19230, 19232},
		.type = MatchType_SourcePort,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/sport_mismatch")
int testcheck_sport_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/l4proto_match")
int testpktgen_l4proto_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/l4proto_match")
int testsetup_l4proto_match(struct __sk_buff *skb)
{
	/* l4proto(tcp) -> proxy */
	struct match_set ms = {
		.l4proto_type = L4ProtoType_TCP,
		.type = MatchType_L4Proto,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/l4proto_match")
int testcheck_l4proto_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/l4proto_mismatch")
int testpktgen_l4proto_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/l4proto_mismatch")
int testsetup_l4proto_mismatch(struct __sk_buff *skb)
{
	/* l4proto(udp) -> proxy */
	struct match_set ms = {
		.l4proto_type = L4ProtoType_UDP,
		.type = MatchType_L4Proto,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/l4proto_mismatch")
int testcheck_l4proto_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/ipversion_match")
int testpktgen_ipversion_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/ipversion_match")
int testsetup_ipversion_match(struct __sk_buff *skb)
{
	/* ipversion(4) -> proxy */
	struct match_set ms = {
		.ip_version = IpVersionType_4,
		.type = MatchType_IpVersion,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipversion_match")
int testcheck_ipversion_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/ipversion_mismatch")
int testpktgen_ipversion_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/ipversion_mismatch")
int testsetup_ipversion_mismatch(struct __sk_buff *skb)
{
	/* ipversion(6) -> proxy */
	struct match_set ms = {
		.ip_version = IpVersionType_6,
		.type = MatchType_IpVersion,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipversion_mismatch")
int testcheck_ipversion_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/mac_match")
int testpktgen_mac_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/mac_match")
int testsetup_mac_match(struct __sk_buff *skb)
{
	/* mac('06:07:08:09:0a:0b') -> proxy */
	struct match_set ms = {
		.type = MatchType_Mac,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 128 },
	};
	__u8 *data = (__u8 *)&lpm_key.data;
	data[10] = 0x6;
	data[11] = 0x7;
	data[12] = 0x8;
	data[13] = 0x9;
	data[14] = 0xa;
	data[15] = 0xb;
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/mac_match")
int testcheck_mac_match(struct __sk_buff *skb)
{
	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 128 },
	};
	__u8 *data = (__u8 *)&lpm_key.data;
	data[10] = 0x6;
	data[11] = 0x7;
	data[12] = 0x8;
	data[13] = 0x9;
	data[14] = 0xa;
	data[15] = 0xb;
	bpf_map_delete_elem(&unused_lpm_type, &lpm_key);

	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/mac_mismatch")
int testpktgen_mac_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/mac_mismatch")
int testsetup_mac_mismatch(struct __sk_buff *skb)
{
	/* mac('00:01:02:03:04:05') -> proxy */
	struct match_set ms = {
		.type = MatchType_Mac,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 128 },
	};
	__u8 *data = (__u8 *)&lpm_key.data;
	data[10] = 0x0;
	data[11] = 0x1;
	data[12] = 0x2;
	data[13] = 0x3;
	data[14] = 0x4;
	data[15] = 0x5;
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/mac_mismatch")
int testcheck_mac_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/dscp_match")
int testpktgen_dscp_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/dscp_match")
int testsetup_dscp_match(struct __sk_buff *skb)
{
	/* dscp(4) -> proxy */
	struct match_set ms = {
		.dscp = 4,
		.not = false,
		.type = MatchType_Dscp,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_match")
int testcheck_dscp_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/dscp_mismatch")
int testpktgen_dscp_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/dscp_mismatch")
int testsetup_dscp_mismatch(struct __sk_buff *skb)
{
	/* dscp(5) -> proxy */
	struct match_set ms = {
		.dscp = 5,
		.not = false,
		.type = MatchType_Dscp,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/dscp_mismatch")
int testcheck_dscp_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/and_match_1")
int testpktgen_and_match_1(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/and_match_1")
int testsetup_and_match_1(struct __sk_buff *skb)
{
	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms1 = {
		.type = MatchType_IpSet,
		.outbound = OUTBOUND_LOGICAL_AND,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms1, BPF_ANY);

	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 112 }, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x01010000); // 1.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);
	
	struct match_set ms2 = {
		.l4proto_type = L4ProtoType_TCP,
		.type = MatchType_L4Proto,
		.outbound = OUTBOUND_LOGICAL_AND,
	};
	bpf_map_update_elem(&routing_map, &one_key, &ms2, BPF_ANY);

	struct match_set ms3 = {
		.port_range = {1, 1023},
		.type = MatchType_Port,
		.outbound = OUTBOUND_LOGICAL_OR,
	};
	bpf_map_update_elem(&routing_map, &two_key, &ms3, BPF_ANY);

	struct match_set ms4 = {
		.port_range = {8443, 8443},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &three_key, &ms4, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &four_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/and_match_1")
int testcheck_and_match_1(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/and_match_2")
int testpktgen_and_match_2(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 8443);
}

SEC("tc/setup/and_match_2")
int testsetup_and_match_2(struct __sk_buff *skb)
{
	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms1 = {
		.type = MatchType_IpSet,
		.outbound = OUTBOUND_LOGICAL_AND,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms1, BPF_ANY);

	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 112 }, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x01010000); // 1.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	struct match_set ms2 = {
		.l4proto_type = L4ProtoType_TCP,
		.type = MatchType_L4Proto,
		.outbound = OUTBOUND_LOGICAL_AND,
	};
	bpf_map_update_elem(&routing_map, &one_key, &ms2, BPF_ANY);

	struct match_set ms3 = {
		.port_range = {1, 1023},
		.type = MatchType_Port,
		.outbound = OUTBOUND_LOGICAL_OR,
	};
	bpf_map_update_elem(&routing_map, &two_key, &ms3, BPF_ANY);

	struct match_set ms4 = {
		.port_range = {8443, 8443},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &three_key, &ms4, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &four_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/and_match_2")
int testcheck_and_match_2(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 8443);
}

SEC("tc/pktgen/and_mismatch")
int testpktgen_and_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 2333);
}

SEC("tc/setup/and_mismatch")
int testsetup_and_mismatch(struct __sk_buff *skb)
{
	/* dip(1.1.0.0/16) && l4proto(tcp) && dport(1-1023, 8443) -> proxy */
	struct match_set ms1 = {
		.type = MatchType_IpSet,
		.outbound = OUTBOUND_LOGICAL_AND,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms1, BPF_ANY);

	struct lpm_key lpm_key = {
		.trie_key = { .prefixlen = 112 }, // */16
	};
	lpm_key.data[2] = bpf_ntohl(0xffff);
	lpm_key.data[3] = bpf_ntohl(0x01010000); // 1.1.0.0
	__u32 lpm_value = bpf_ntohl(0x01000000);
	bpf_map_update_elem(&unused_lpm_type, &lpm_key, &lpm_value, BPF_ANY);

	struct match_set ms2 = {
		.l4proto_type = L4ProtoType_TCP,
		.type = MatchType_L4Proto,
		.outbound = OUTBOUND_LOGICAL_AND,
	};
	bpf_map_update_elem(&routing_map, &one_key, &ms2, BPF_ANY);

	struct match_set ms3 = {
		.port_range = {1, 1023},
		.type = MatchType_Port,
		.outbound = OUTBOUND_LOGICAL_OR,
	};
	bpf_map_update_elem(&routing_map, &two_key, &ms3, BPF_ANY);

	struct match_set ms4 = {
		.port_range = {8443, 8443},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &three_key, &ms4, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &four_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/and_mismatch")
int testcheck_and_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 2333);
}

SEC("tc/pktgen/not_match")
int testpktgen_not_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/not_match")
int testsetup_not_match(struct __sk_buff *skb)
{
	/* !dport(80) -> proxy */
	struct match_set ms = {
		.port_range = {80, 80},
		.not = true,
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/not_match")
int testcheck_not_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/not_mismtach")
int testpktgen_not_mismtach(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 79);
}

SEC("tc/setup/not_mismtach")
int testsetup_not_mismtach(struct __sk_buff *skb)
{
	/* !dport(80) -> proxy */
	struct match_set ms1 = {
		.port_range = {80, 80},
		.not = true,
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms1, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/not_mismtach")
int testcheck_not_mismtach(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 79);
}

SEC("tc/pktgen/skip_while_noalive_alive")
int testpktgen_skip_while_noalive_alive(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/skip_while_noalive_alive")
int testsetup_skip_while_noalive_alive(struct __sk_buff *skb)
{
	/* dport(80) -> proxy(skip_while_noalive); proxy group is alive */
	struct match_set ms = {
		.port_range = {80, 80},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
		.skip_while_noalive = true,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/skip_while_noalive_alive")
int testcheck_skip_while_noalive_alive(struct __sk_buff *skb)
{
	/* The group is usable, so the rule hits and traffic is proxied. */
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/skip_while_noalive_dead")
int testpktgen_skip_while_noalive_dead(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/skip_while_noalive_dead")
int testsetup_skip_while_noalive_dead(struct __sk_buff *skb)
{
	/* dport(80) -> proxy(skip_while_noalive); proxy group is dead but
	 * no_connectivity_try_sniff is enabled. */
	struct match_set ms = {
		.port_range = {80, 80},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
		.skip_while_noalive = true,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity_dead_try_sniff(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/skip_while_noalive_dead")
int testcheck_skip_while_noalive_dead(struct __sk_buff *skb)
{
	/* The rule-level annotation takes precedence over try-sniff, so the rule
	 * is skipped and traffic falls through to the must_direct fallback. */
	return check_routing_ipv4_tcp(skb,
				      TCX_NEXT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/noalive_try_sniff")
int testpktgen_noalive_try_sniff(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/noalive_try_sniff")
int testsetup_noalive_try_sniff(struct __sk_buff *skb)
{
	/* Without skip_while_noalive, a dead group still reaches the control
	 * plane when no_connectivity_try_sniff is enabled. */
	struct match_set ms = {
		.port_range = {80, 80},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);
	set_outbound_connectivity_dead_try_sniff(OUTBOUND_USER_DEFINED_MIN);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/noalive_try_sniff")
int testcheck_noalive_try_sniff(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_REDIRECT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/skip_while_noalive_block")
int testpktgen_skip_while_noalive_block(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/skip_while_noalive_block")
int testsetup_skip_while_noalive_block(struct __sk_buff *skb)
{
	/* This malformed rule cannot be produced by the userspace builder. Keep
	 * built-in outbounds independent of connectivity map state defensively. */
	struct match_set ms = {
		.port_range = {80, 80},
		.type = MatchType_Port,
		.outbound = OUTBOUND_BLOCK,
		.skip_while_noalive = true,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &ms, BPF_ANY);

	/* fallback: must_direct */
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/skip_while_noalive_block")
int testcheck_skip_while_noalive_block(struct __sk_buff *skb)
{
	/* The block rule must hit even though built-ins have no connectivity map
	 * entries in production. */
	return check_routing_ipv4_tcp(skb,
				      TC_ACT_SHOT,
				      IPV4(192,168,0,1), IPV4(1,1,1,1),
				      19233, 80);
}

SEC("tc/pktgen/domain_not_partial_and_port_match")
int testpktgen_domain_not_partial_and_port_match(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(4,4,4,1), 19233, 80);
}

SEC("tc/setup/domain_not_partial_and_port_match")
int testsetup_domain_not_partial_and_port_match(struct __sk_buff *skb)
{
	/* !domain(...) is ambiguous for this shared IP; dport(80) still matches. */
	struct match_set domain = {
		.type = MatchType_DomainSet,
		.not = true,
		.outbound = OUTBOUND_LOGICAL_AND,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &domain, BPF_ANY);

	struct match_set port = {
		.port_range = {80, 80},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &one_key, &port, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	/* Rule 0 matches some, but not all, domains mapped to 4.4.4.1. */
	set_domain_routing(IPV4(4,4,4,1), 1 << 0, 0);
	set_routing_fallback(OUTBOUND_DIRECT, true, &two_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/domain_not_partial_and_port_match")
int testcheck_domain_not_partial_and_port_match(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp_with_outbound(
		skb, TC_ACT_REDIRECT, OUTBOUND_CONTROL_PLANE_ROUTING,
		IPV4(192,168,0,1), IPV4(4,4,4,1), 19233, 80);
}

SEC("tc/pktgen/domain_not_partial_and_port_mismatch")
int testpktgen_domain_not_partial_and_port_mismatch(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(4,4,4,2), 19233, 79);
}

SEC("tc/setup/domain_not_partial_and_port_mismatch")
int testsetup_domain_not_partial_and_port_mismatch(struct __sk_buff *skb)
{
	/* The ambiguous domain must not override a later failed AND condition. */
	struct match_set domain = {
		.type = MatchType_DomainSet,
		.not = true,
		.outbound = OUTBOUND_LOGICAL_AND,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &domain, BPF_ANY);

	struct match_set port = {
		.port_range = {80, 80},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &one_key, &port, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	set_domain_routing(IPV4(4,4,4,2), 1 << 0, 0);
	set_routing_fallback(OUTBOUND_DIRECT, true, &two_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/domain_not_partial_and_port_mismatch")
int testcheck_domain_not_partial_and_port_mismatch(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(
		skb, TCX_NEXT,
		IPV4(192,168,0,1), IPV4(4,4,4,2), 19233, 79);
}

SEC("tc/pktgen/domain_partial_resolved_by_or")
int testpktgen_domain_partial_resolved_by_or(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(4,4,4,3), 19233, 80);
}

SEC("tc/setup/domain_partial_resolved_by_or")
int testsetup_domain_partial_resolved_by_or(struct __sk_buff *skb)
{
	/* Rule 0 is partial, but rule 1 definitively satisfies the same OR
	 * subrule, so no control-plane lookup is needed. */
	struct match_set partial = {
		.type = MatchType_DomainSet,
		.outbound = OUTBOUND_LOGICAL_OR,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &partial, BPF_ANY);

	struct match_set definite = {
		.type = MatchType_DomainSet,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &one_key, &definite, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	set_domain_routing(IPV4(4,4,4,3), (1 << 0) | (1 << 1), 1 << 1);
	set_routing_fallback(OUTBOUND_DIRECT, true, &two_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/domain_partial_resolved_by_or")
int testcheck_domain_partial_resolved_by_or(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(
		skb, TC_ACT_REDIRECT,
		IPV4(192,168,0,1), IPV4(4,4,4,3), 19233, 80);
}

SEC("tc/pktgen/domain_partial_must_rules")
int testpktgen_domain_partial_must_rules(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(4,4,4,4), 19233, 80);
}

SEC("tc/setup/domain_partial_must_rules")
int testsetup_domain_partial_must_rules(struct __sk_buff *skb)
{
	/* An uncertain must_rules line cannot establish must. Exact routing has
	 * to decide whether this domain actually matches the line. */
	struct match_set domain = {
		.type = MatchType_DomainSet,
		.outbound = OUTBOUND_MUST_RULES,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &domain, BPF_ANY);

	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false, &one_key);
	set_domain_routing(IPV4(4,4,4,4), 1 << 0, 0);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/domain_partial_must_rules")
int testcheck_domain_partial_must_rules(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp_with_result(
		skb, TC_ACT_REDIRECT, OUTBOUND_CONTROL_PLANE_ROUTING, false,
		IPV4(192,168,0,1), IPV4(4,4,4,4), 19233, 80);
}

SEC("tc/pktgen/domain_partial_terminal_must")
int testpktgen_domain_partial_terminal_must(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(4,4,4,5), 19233, 80);
}

SEC("tc/setup/domain_partial_terminal_must")
int testsetup_domain_partial_terminal_must(struct __sk_buff *skb)
{
	/* A terminal must belongs to the uncertain current rule and must not be
	 * copied into the control-plane routing result. */
	struct match_set domain = {
		.type = MatchType_DomainSet,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
		.must = true,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &domain, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);
	set_domain_routing(IPV4(4,4,4,5), 1 << 0, 0);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/domain_partial_terminal_must")
int testcheck_domain_partial_terminal_must(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp_with_result(
		skb, TC_ACT_REDIRECT, OUTBOUND_CONTROL_PLANE_ROUTING, false,
		IPV4(192,168,0,1), IPV4(4,4,4,5), 19233, 80);
}

SEC("tc/pktgen/domain_partial_keeps_prior_must")
int testpktgen_domain_partial_keeps_prior_must(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(4,4,4,6), 19233, 80);
}

SEC("tc/setup/domain_partial_keeps_prior_must")
int testsetup_domain_partial_keeps_prior_must(struct __sk_buff *skb)
{
	/* A definite earlier must_rules line remains valid when a later rule
	 * requires an exact userspace domain match. */
	struct match_set must_port = {
		.port_range = {80, 80},
		.type = MatchType_Port,
		.outbound = OUTBOUND_MUST_RULES,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &must_port, BPF_ANY);

	struct match_set domain = {
		.type = MatchType_DomainSet,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
		.must = true,
	};
	bpf_map_update_elem(&routing_map, &one_key, &domain, BPF_ANY);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);

	set_routing_fallback(OUTBOUND_DIRECT, true, &two_key);
	set_domain_routing(IPV4(4,4,4,6), 1 << 1, 0);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/domain_partial_keeps_prior_must")
int testcheck_domain_partial_keeps_prior_must(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp_with_result(
		skb, TC_ACT_REDIRECT, OUTBOUND_CONTROL_PLANE_ROUTING, true,
		IPV4(192,168,0,1), IPV4(4,4,4,6), 19233, 80);
}

SEC("tc/pktgen/domain_bitmap_second_word")
int testpktgen_domain_bitmap_second_word(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(4,4,4,7), 19233, 80);
}

SEC("tc/setup/domain_bitmap_second_word")
int testsetup_domain_bitmap_second_word(struct __sk_buff *skb)
{
	/* Fill rule indices 0..31 with definite misses so the domain rule lands
	 * at index 32, the first bit in the second bitmap word. */
	struct match_set miss = {
		.port_range = {1, 1},
		.type = MatchType_Port,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN);
	for (__u32 i = 0; i < 32; i++)
		bpf_map_update_elem(&routing_map, &i, &miss, BPF_ANY);

	__u32 domain_key = 32;
	struct match_set domain = {
		.type = MatchType_DomainSet,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
	};
	bpf_map_update_elem(&routing_map, &domain_key, &domain, BPF_ANY);
	set_domain_routing_word(IPV4(4,4,4,7), 1, 1 << 0, 1 << 0);

	__u32 fallback_key = 33;
	set_routing_fallback(OUTBOUND_DIRECT, true, &fallback_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/domain_bitmap_second_word")
int testcheck_domain_bitmap_second_word(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(
		skb, TC_ACT_REDIRECT,
		IPV4(192,168,0,1), IPV4(4,4,4,7), 19233, 80);
}

SEC("tc/pktgen/domain_partial_skips_noalive")
int testpktgen_domain_partial_skips_noalive(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(4,4,4,8), 19233, 80);
}

SEC("tc/setup/domain_partial_skips_noalive")
int testsetup_domain_partial_skips_noalive(struct __sk_buff *skb)
{
	struct match_set domain = {
		.type = MatchType_DomainSet,
		.outbound = OUTBOUND_USER_DEFINED_MIN,
		.skip_while_noalive = true,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &domain, BPF_ANY);
	struct outbound_connectivity_query connectivity = {
		.outbound = OUTBOUND_USER_DEFINED_MIN,
		.ipversion = 4,
		.l4proto = IPPROTO_TCP,
	};
	bpf_map_delete_elem(&outbound_connectivity_map, &connectivity);
	set_domain_routing(IPV4(4,4,4,8), 1 << 0, 0);
	set_routing_fallback(OUTBOUND_DIRECT, true, &one_key);

	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/domain_partial_skips_noalive")
int testcheck_domain_partial_skips_noalive(struct __sk_buff *skb)
{
	return check_routing_ipv4_tcp(
		skb, TCX_NEXT,
		IPV4(192,168,0,1), IPV4(4,4,4,8), 19233, 80);
}
