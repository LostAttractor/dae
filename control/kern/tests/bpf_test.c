// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

#define __DEBUG

#include "../tproxy.c"
#include "./bpf_test.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 4);
	__array(values, int());
} entry_call_map SEC(".maps") = {
	.values = {
		[0] = &tproxy_wan_egress_l2,
		[1] = &lan_egress_l2,
		[2] = &tproxy_wan_ingress_l2,
		[3] = &lan_ingress_l2,
	},
};

SEC("tc/benchmark/parser")
int test_parser_benchmark(struct __sk_buff *skb)
{
	struct ethhdr ethh;
	struct l3_hdr l3h;
	struct l4_hdr l4h;
	__u8 l4proto;
	__u32 offset = 0;
	__u32 packet_end;
	enum fragment_state fragment_state;
	int ret;

	ret = parse_transport(skb, ETH_HLEN, &ethh, &l3h, &l4h,
			      &l4proto, &offset, &packet_end, &fragment_state);
	if (fragment_state == FRAGMENT_NONFIRST)
		return 0;
	return ret;
}

SEC("tc/pktgen/parser_ipv6_udp")
int testpktgen_parser_ipv6_udp(struct __sk_buff *skb)
{
	return set_ipv6_udp(skb, 50, 51, 20500, 443);
}

SEC("tc/setup/parser_ipv6_udp")
int testsetup_parser_ipv6_udp(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_DIRECT, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/parser_ipv6_udp")
int testcheck_parser_ipv6_udp(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_NEXT);
}

static __always_inline int check_setup_result(struct __sk_buff *skb,
					       __u32 expected)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 *status = data;

	if ((void *)(status + 1) > data_end)
		return TC_ACT_SHOT;
	if (*status != expected) {
		bpf_printk("setup status(%u) != %u\n", *status, expected);
		return TC_ACT_SHOT;
	}
	bpf_printk("setup status: %u\n", *status);
	return TC_ACT_OK;
}

SEC("tc/pktgen/so_mark_exact")
int testpktgen_so_mark_exact(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/so_mark_exact")
int testsetup_so_mark_exact(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	struct pid_pname *pid_pname = NULL;

	bpf_map_delete_elem(&cookie_pid_map, &cookie);
	skb->mark = PARAM.so_mark_from_dae;
	return pid_is_control_plane(skb, &pid_pname);
}

SEC("tc/check/so_mark_exact")
int testcheck_so_mark_exact(struct __sk_buff *skb)
{
	return check_setup_result(skb, false);
}

SEC("tc/pktgen/so_mark_neighbor")
int testpktgen_so_mark_neighbor(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/so_mark_neighbor")
int testsetup_so_mark_neighbor(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	struct pid_pname *pid_pname = NULL;

	bpf_map_delete_elem(&cookie_pid_map, &cookie);
	skb->mark = PARAM.so_mark_from_dae ^ 1;
	return pid_is_control_plane(skb, &pid_pname);
}

SEC("tc/check/so_mark_neighbor")
int testcheck_so_mark_neighbor(struct __sk_buff *skb)
{
	return check_setup_result(skb, false);
}

SEC("tc/pktgen/so_mark_pid_precedence")
int testpktgen_so_mark_pid_precedence(struct __sk_buff *skb)
{
	return set_ipv4_tcp(skb, IPV4(192,168,0,1), IPV4(1,1,1,1), 19233, 80);
}

SEC("tc/setup/so_mark_pid_precedence")
int testsetup_so_mark_pid_precedence(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	struct pid_pname value = { .pid = PARAM.control_plane_pid + 1 };
	struct pid_pname *pid_pname = NULL;

	bpf_map_update_elem(&cookie_pid_map, &cookie, &value, BPF_ANY);
	skb->mark = PARAM.so_mark_from_dae;
	return pid_is_control_plane(skb, &pid_pname);
}

SEC("tc/check/so_mark_pid_precedence")
int testcheck_so_mark_pid_precedence(struct __sk_buff *skb)
{
	return check_setup_result(skb, false);
}

SEC("tc/pktgen/ipv4_first_fragment")
int testpktgen_ipv4_first_fragment(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,1), IPV4(1,1,1,1),
				     19233, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment")
int testsetup_ipv4_first_fragment(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_BLOCK, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment")
int testcheck_ipv4_first_fragment(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_fragment_direct")
int testpktgen_ipv4_first_fragment_direct(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,10), IPV4(1,1,1,10),
				     19310, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment_direct")
int testsetup_ipv4_first_fragment_direct(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_DIRECT, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_direct")
int testcheck_ipv4_first_fragment_direct(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_NEXT);
}

SEC("tc/pktgen/ipv4_first_fragment_premarked_direct")
int testpktgen_ipv4_first_fragment_premarked_direct(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,21), IPV4(1,1,1,21),
				     19321, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment_premarked_direct")
int testsetup_ipv4_first_fragment_premarked_direct(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_DIRECT, false, &zero_key);
	skb->mark = 42;
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_premarked_direct")
int testcheck_ipv4_first_fragment_premarked_direct(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_fragment_marked_direct")
int testpktgen_ipv4_first_fragment_marked_direct(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,11), IPV4(1,1,1,11),
				     19311, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment_marked_direct")
int testsetup_ipv4_first_fragment_marked_direct(struct __sk_buff *skb)
{
	struct match_set fallback = {
		.type = MatchType_Fallback,
		.outbound = OUTBOUND_DIRECT,
		.mark = 42,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &fallback, BPF_ANY);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_marked_direct")
int testcheck_ipv4_first_fragment_marked_direct(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_no_ipv4_tcp_routing_result(skb, TCX_DROP,
		IPV4(192,168,0,11), IPV4(1,1,1,11), 19311, 80);
}

SEC("tc/pktgen/ipv4_first_fragment_noalive_direct")
int testpktgen_ipv4_first_fragment_noalive_direct(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,17), IPV4(1,1,1,17),
				     19317, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment_noalive_direct")
int testsetup_ipv4_first_fragment_noalive_direct(struct __sk_buff *skb)
{
	const __u8 outbound = OUTBOUND_USER_DEFINED_MIN + 20;
	struct outbound_connectivity_query query = {
		.outbound = outbound,
		.ipversion = 4,
		.l4proto = IPPROTO_TCP,
	};
	__u32 state = OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT;

	set_routing_fallback(outbound, false, &zero_key);
	bpf_map_update_elem(&outbound_connectivity_map, &query, &state, BPF_ANY);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_noalive_direct")
int testcheck_ipv4_first_fragment_noalive_direct(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_NEXT);
}

SEC("tc/pktgen/ipv4_first_fragment_noalive_block")
int testpktgen_ipv4_first_fragment_noalive_block(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,18), IPV4(1,1,1,18),
				     19318, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment_noalive_block")
int testsetup_ipv4_first_fragment_noalive_block(struct __sk_buff *skb)
{
	const __u8 outbound = OUTBOUND_USER_DEFINED_MIN + 21;
	struct outbound_connectivity_query query = {
		.outbound = outbound,
		.ipversion = 4,
		.l4proto = IPPROTO_TCP,
	};
	__u32 state = OUTBOUND_CONNECTIVITY_NOALIVE_BLOCK;

	set_routing_fallback(outbound, false, &zero_key);
	bpf_map_update_elem(&outbound_connectivity_map, &query, &state, BPF_ANY);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_noalive_block")
int testcheck_ipv4_first_fragment_noalive_block(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_fragment_missing_connectivity")
int testpktgen_ipv4_first_fragment_missing_connectivity(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,19), IPV4(1,1,1,19),
				     19319, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment_missing_connectivity")
int testsetup_ipv4_first_fragment_missing_connectivity(struct __sk_buff *skb)
{
	struct match_set fallback = {
		.type = MatchType_Fallback,
		.outbound = OUTBOUND_USER_DEFINED_MIN + 22,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &fallback, BPF_ANY);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_missing_connectivity")
int testcheck_ipv4_first_fragment_missing_connectivity(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_NEXT);
}

SEC("tc/pktgen/ipv4_first_fragment_marked_missing_connectivity")
int testpktgen_ipv4_first_fragment_marked_missing_connectivity(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,35), IPV4(1,1,1,35),
				     19335, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment_marked_missing_connectivity")
int testsetup_ipv4_first_fragment_marked_missing_connectivity(struct __sk_buff *skb)
{
	struct match_set fallback = {
		.type = MatchType_Fallback,
		.outbound = OUTBOUND_USER_DEFINED_MIN + 23,
	};
	bpf_map_update_elem(&routing_map, &zero_key, &fallback, BPF_ANY);
	skb->mark = 42;
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_marked_missing_connectivity")
int testcheck_ipv4_first_fragment_marked_missing_connectivity(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_fragment_proxy")
int testpktgen_ipv4_first_fragment_proxy(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,12), IPV4(1,1,1,12),
				     19312, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment_proxy")
int testsetup_ipv4_first_fragment_proxy(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_proxy")
int testcheck_ipv4_first_fragment_proxy(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_no_ipv4_tcp_routing_result(skb, TCX_DROP,
		IPV4(192,168,0,12), IPV4(1,1,1,12), 19312, 80);
}

SEC("tc/pktgen/ipv4_first_fragment_control_plane")
int testpktgen_ipv4_first_fragment_control_plane(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,13), IPV4(1,1,1,13),
				     19313, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_fragment_control_plane")
int testsetup_ipv4_first_fragment_control_plane(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	struct pid_pname value = { .pid = PARAM.control_plane_pid };

	bpf_map_update_elem(&cookie_pid_map, &cookie, &value, BPF_ANY);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_control_plane")
int testcheck_ipv4_first_fragment_control_plane(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_NEXT);
}

SEC("tc/pktgen/ipv4_first_fragment_padding")
int testpktgen_ipv4_first_fragment_padding(struct __sk_buff *skb)
{
	return set_ipv4_short_first_fragment(skb, IPV4(192,168,0,14),
		IPV4(1,1,1,14), IPPROTO_TCP);
}

SEC("tc/setup/ipv4_first_fragment_padding")
int testsetup_ipv4_first_fragment_padding(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_padding")
int testcheck_ipv4_first_fragment_padding(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_fragment_reserved_flag")
int testpktgen_ipv4_first_fragment_reserved_flag(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,30), IPV4(1,1,1,30),
				     19330, 80, 0x8000);
}

SEC("tc/setup/ipv4_first_fragment_reserved_flag")
int testsetup_ipv4_first_fragment_reserved_flag(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_reserved_flag")
int testcheck_ipv4_first_fragment_reserved_flag(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_fragment_reserved_flag_reply")
int testpktgen_ipv4_fragment_reserved_flag_reply(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,45), IPV4(1,1,1,45),
				     19345, 80, 0x8000);
}

SEC("tc/setup/ipv4_fragment_reserved_flag_reply")
int testsetup_ipv4_fragment_reserved_flag_reply(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 1);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_fragment_reserved_flag_reply")
int testcheck_ipv4_fragment_reserved_flag_reply(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_fragment_df_mf")
int testpktgen_ipv4_first_fragment_df_mf(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,31), IPV4(1,1,1,31),
				     19331, 80, 0x6000);
}

SEC("tc/setup/ipv4_first_fragment_df_mf")
int testsetup_ipv4_first_fragment_df_mf(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_df_mf")
int testcheck_ipv4_first_fragment_df_mf(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_fragment_tcp_doff_small")
int testpktgen_ipv4_first_fragment_tcp_doff_small(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment_doff(skb, 4);
}

SEC("tc/setup/ipv4_first_fragment_tcp_doff_small")
int testsetup_ipv4_first_fragment_tcp_doff_small(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_tcp_doff_small")
int testcheck_ipv4_first_fragment_tcp_doff_small(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_fragment_tcp_doff_truncated")
int testpktgen_ipv4_first_fragment_tcp_doff_truncated(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment_doff(skb, 15);
}

SEC("tc/setup/ipv4_first_fragment_tcp_doff_truncated")
int testsetup_ipv4_first_fragment_tcp_doff_truncated(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_tcp_doff_truncated")
int testcheck_ipv4_first_fragment_tcp_doff_truncated(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_fragment_udp_len_small")
int testpktgen_ipv4_first_fragment_udp_len_small(struct __sk_buff *skb)
{
	return set_ipv4_udp_fragment_len(skb, UDP_HLEN - 1);
}

SEC("tc/setup/ipv4_first_fragment_udp_len_small")
int testsetup_ipv4_first_fragment_udp_len_small(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_fragment_udp_len_small")
int testcheck_ipv4_first_fragment_udp_len_small(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_nonfirst_fragment")
int testpktgen_ipv4_nonfirst_fragment(struct __sk_buff *skb)
{
	return set_ipv4_tcp_fragment(skb, IPV4(192,168,0,1), IPV4(1,1,1,1),
				     19233, 80, 1);
}

SEC("tc/setup/ipv4_nonfirst_fragment")
int testsetup_ipv4_nonfirst_fragment(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_nonfirst_fragment")
int testcheck_ipv4_nonfirst_fragment(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_NEXT);
}

SEC("tc/pktgen/ipv4_nonfirst_udp_fragment")
int testpktgen_ipv4_nonfirst_udp_fragment(struct __sk_buff *skb)
{
	return set_ipv4_udp_fragment(skb, IPV4(192,168,0,15), IPV4(1,1,1,15),
				     19315, 80, 0x0001);
}

SEC("tc/setup/ipv4_nonfirst_udp_fragment")
int testsetup_ipv4_nonfirst_udp_fragment(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_nonfirst_udp_fragment")
int testcheck_ipv4_nonfirst_udp_fragment(struct __sk_buff *skb)
{
	return check_ipv4_udp_state(skb, TCX_NEXT,
		IPV4(192,168,0,15), IPV4(1,1,1,15), 19315, 80, false);
}

SEC("tc/pktgen/ipv4_nonfirst_udp_fragment_lan_ingress")
int testpktgen_ipv4_nonfirst_udp_fragment_lan_ingress(struct __sk_buff *skb)
{
	return set_ipv4_udp_fragment(skb, IPV4(192,168,0,20), IPV4(1,1,1,20),
				     19320, 80, 0x0001);
}

SEC("tc/setup/ipv4_nonfirst_udp_fragment_lan_ingress")
int testsetup_ipv4_nonfirst_udp_fragment_lan_ingress(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 3);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_nonfirst_udp_fragment_lan_ingress")
int testcheck_ipv4_nonfirst_udp_fragment_lan_ingress(struct __sk_buff *skb)
{
	return check_ipv4_udp_state(skb, TCX_NEXT,
		IPV4(192,168,0,20), IPV4(1,1,1,20), 19320, 80, false);
}

SEC("tc/pktgen/ipv4_nonfirst_fragment_bad_ihl")
int testpktgen_ipv4_nonfirst_fragment_bad_ihl(struct __sk_buff *skb)
{
	return set_ipv4_nonfirst_fragment_ihl(skb, 4);
}

SEC("tc/setup/ipv4_nonfirst_fragment_bad_ihl")
int testsetup_ipv4_nonfirst_fragment_bad_ihl(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_nonfirst_fragment_bad_ihl")
int testcheck_ipv4_nonfirst_fragment_bad_ihl(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_nonfirst_fragment_misaligned")
int testpktgen_ipv4_nonfirst_fragment_misaligned(struct __sk_buff *skb)
{
	return set_ipv4_misaligned_nonfirst_fragment(skb);
}

SEC("tc/setup/ipv4_nonfirst_fragment_misaligned")
int testsetup_ipv4_nonfirst_fragment_misaligned(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_nonfirst_fragment_misaligned")
int testcheck_ipv4_nonfirst_fragment_misaligned(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_nonfirst_udp_fragment_reply")
int testpktgen_ipv4_nonfirst_udp_fragment_reply(struct __sk_buff *skb)
{
	return set_ipv4_udp_fragment(skb, IPV4(192,168,0,32), IPV4(1,1,1,32),
				     19332, 80, 0x0001);
}

SEC("tc/setup/ipv4_nonfirst_udp_fragment_reply")
int testsetup_ipv4_nonfirst_udp_fragment_reply(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 1);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_nonfirst_udp_fragment_reply")
int testcheck_ipv4_nonfirst_udp_fragment_reply(struct __sk_buff *skb)
{
	return check_ipv4_udp_state(skb, TCX_NEXT,
		IPV4(192,168,0,32), IPV4(1,1,1,32), 19332, 80, false);
}

SEC("tc/pktgen/ipv4_first_udp_fragment_routing")
int testpktgen_ipv4_first_udp_fragment_routing(struct __sk_buff *skb)
{
	return set_ipv4_udp_fragment(skb, IPV4(192,168,0,1), IPV4(1,1,1,1),
				     19234, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_udp_fragment_routing")
int testsetup_ipv4_first_udp_fragment_routing(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_BLOCK, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_udp_fragment_routing")
int testcheck_ipv4_first_udp_fragment_routing(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_state(skb, TCX_DROP,
		IPV4(192,168,0,1), IPV4(1,1,1,1), 19234, 80, false);
}

SEC("tc/pktgen/ipv4_first_udp_fragment_direct")
int testpktgen_ipv4_first_udp_fragment_direct(struct __sk_buff *skb)
{
	return set_ipv4_udp_fragment(skb, IPV4(192,168,0,16), IPV4(1,1,1,16),
				     19316, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_udp_fragment_direct")
int testsetup_ipv4_first_udp_fragment_direct(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_DIRECT, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_udp_fragment_direct")
int testcheck_ipv4_first_udp_fragment_direct(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_outbound_state(skb, TCX_NEXT,
		IPV4(192,168,0,16), IPV4(1,1,1,16), 19316, 80);
}

SEC("tc/pktgen/ipv4_first_udp_fragment_marked_ingress_state")
int testpktgen_ipv4_first_udp_fragment_marked_ingress_state(struct __sk_buff *skb)
{
	return set_ipv4_udp_fragment(skb, IPV4(192,168,0,36), IPV4(1,1,1,36),
				     19336, 80, 0x2000);
}

SEC("tc/setup/ipv4_first_udp_fragment_marked_ingress_state")
int testsetup_ipv4_first_udp_fragment_marked_ingress_state(struct __sk_buff *skb)
{
	set_ipv4_udp_ingress_state(IPV4(192,168,0,36), IPV4(1,1,1,36),
				   19336, 80);
	skb->mark = 42;
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_udp_fragment_marked_ingress_state")
int testcheck_ipv4_first_udp_fragment_marked_ingress_state(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv4_first_udp_fragment_lan_egress")
int testpktgen_ipv4_first_udp_fragment_lan_egress(struct __sk_buff *skb)
{
	return set_ipv4_udp_fragment(skb, IPV4(192,168,0,2), IPV4(1,1,1,2),
				     19235, 81, 0x2000);
}

SEC("tc/setup/ipv4_first_udp_fragment_lan_egress")
int testsetup_ipv4_first_udp_fragment_lan_egress(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 1);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_first_udp_fragment_lan_egress")
int testcheck_ipv4_first_udp_fragment_lan_egress(struct __sk_buff *skb)
{
	return check_ipv4_udp_state(skb, TCX_NEXT,
		IPV4(192,168,0,2), IPV4(1,1,1,2), 19235, 81, true);
}

SEC("tc/pktgen/ipv6_first_udp_fragment_routing")
int testpktgen_ipv6_first_udp_fragment_routing(struct __sk_buff *skb)
{
	return set_ipv6_udp_fragment(skb, 1, 2, 19236, 82, 0x0001);
}

SEC("tc/setup/ipv6_first_udp_fragment_routing")
int testsetup_ipv6_first_udp_fragment_routing(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_BLOCK, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_first_udp_fragment_routing")
int testcheck_ipv6_first_udp_fragment_routing(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv6_udp_state(skb, TCX_DROP, 1, 2, 19236, 82, false);
}

SEC("tc/pktgen/ipv6_first_udp_fragment_direct")
int testpktgen_ipv6_first_udp_fragment_direct(struct __sk_buff *skb)
{
	return set_ipv6_udp_fragment(skb, 17, 18, 19317, 80, 0x0001);
}

SEC("tc/setup/ipv6_first_udp_fragment_direct")
int testsetup_ipv6_first_udp_fragment_direct(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_DIRECT, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_first_udp_fragment_direct")
int testcheck_ipv6_first_udp_fragment_direct(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv6_udp_outbound_state(skb, TCX_NEXT, 17, 18, 19317, 80);
}

SEC("tc/pktgen/ipv6_first_tcp_fragment_direct")
int testpktgen_ipv6_first_tcp_fragment_direct(struct __sk_buff *skb)
{
	return set_ipv6_tcp_fragment(skb, 37, 38, 19337, 80);
}

SEC("tc/setup/ipv6_first_tcp_fragment_direct")
int testsetup_ipv6_first_tcp_fragment_direct(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_DIRECT, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_first_tcp_fragment_direct")
int testcheck_ipv6_first_tcp_fragment_direct(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_NEXT);
}

SEC("tc/pktgen/ipv6_first_udp_fragment_wan_ingress")
int testpktgen_ipv6_first_udp_fragment_wan_ingress(struct __sk_buff *skb)
{
	return set_ipv6_udp_fragment(skb, 3, 4, 19237, 83, 0x0001);
}

SEC("tc/setup/ipv6_first_udp_fragment_wan_ingress")
int testsetup_ipv6_first_udp_fragment_wan_ingress(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 2);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_first_udp_fragment_wan_ingress")
int testcheck_ipv6_first_udp_fragment_wan_ingress(struct __sk_buff *skb)
{
	return check_ipv6_udp_state(skb, TCX_NEXT, 3, 4, 19237, 83, true);
}

SEC("tc/pktgen/ipv6_nonfirst_udp_fragment")
int testpktgen_ipv6_nonfirst_udp_fragment(struct __sk_buff *skb)
{
	return set_ipv6_udp_fragment(skb, 5, 6, 19238, 84, 0x0008);
}

SEC("tc/setup/ipv6_nonfirst_udp_fragment")
int testsetup_ipv6_nonfirst_udp_fragment(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_nonfirst_udp_fragment")
int testcheck_ipv6_nonfirst_udp_fragment(struct __sk_buff *skb)
{
	return check_ipv6_udp_state(skb, TCX_NEXT, 5, 6, 19238, 84, false);
}

SEC("tc/pktgen/ipv6_ah_udp_fragment")
int testpktgen_ipv6_ah_udp_fragment(struct __sk_buff *skb)
{
	return set_ipv6_ah_udp_fragment(skb, 9, 10, 19240, 86);
}

SEC("tc/setup/ipv6_ah_udp_fragment")
int testsetup_ipv6_ah_udp_fragment(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_BLOCK, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_ah_udp_fragment")
int testcheck_ipv6_ah_udp_fragment(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv6_short_ah_fragment")
int testpktgen_ipv6_short_ah_fragment(struct __sk_buff *skb)
{
	return set_ipv6_short_ah_fragment(skb);
}

SEC("tc/setup/ipv6_short_ah_fragment")
int testsetup_ipv6_short_ah_fragment(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_short_ah_fragment")
int testcheck_ipv6_short_ah_fragment(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv6_ah_udp_unfragmented")
int testpktgen_ipv6_ah_udp_unfragmented(struct __sk_buff *skb)
{
	return set_ipv6_ah_udp(skb, 22, 23, 19322, 80);
}

SEC("tc/setup/ipv6_ah_udp_unfragmented")
int testsetup_ipv6_ah_udp_unfragmented(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_ah_udp_unfragmented")
int testcheck_ipv6_ah_udp_unfragmented(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv6_udp_state(skb, TCX_NEXT, 22, 23, 19322, 80, false);
}

SEC("tc/pktgen/ipv6_excessive_extensions")
int testpktgen_ipv6_excessive_extensions(struct __sk_buff *skb)
{
	return set_ipv6_extensions(skb, IPV6_MAX_EXTENSIONS + 1);
}

SEC("tc/setup/ipv6_excessive_extensions")
int testsetup_ipv6_excessive_extensions(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_excessive_extensions")
int testcheck_ipv6_excessive_extensions(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv6_max_extensions")
int testpktgen_ipv6_max_extensions(struct __sk_buff *skb)
{
	return set_ipv6_extensions(skb, IPV6_MAX_EXTENSIONS);
}

SEC("tc/setup/ipv6_max_extensions")
int testsetup_ipv6_max_extensions(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_max_extensions")
int testcheck_ipv6_max_extensions(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TC_ACT_REDIRECT);
}

SEC("tc/pktgen/ipv6_repeated_atomic_fragments")
int testpktgen_ipv6_repeated_atomic_fragments(struct __sk_buff *skb)
{
	return set_ipv6_repeated_atomic_fragments(skb);
}

SEC("tc/setup/ipv6_repeated_atomic_fragments")
int testsetup_ipv6_repeated_atomic_fragments(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_repeated_atomic_fragments")
int testcheck_ipv6_repeated_atomic_fragments(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv6_truncated_fragment")
int testpktgen_ipv6_truncated_fragment(struct __sk_buff *skb)
{
	return set_ipv6_truncated_fragment(skb);
}

SEC("tc/setup/ipv6_truncated_fragment")
int testsetup_ipv6_truncated_fragment(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_truncated_fragment")
int testcheck_ipv6_truncated_fragment(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv6_misaligned_first_fragment")
int testpktgen_ipv6_misaligned_first_fragment(struct __sk_buff *skb)
{
	return set_ipv6_misaligned_first_fragment(skb);
}

SEC("tc/setup/ipv6_misaligned_first_fragment")
int testsetup_ipv6_misaligned_first_fragment(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_misaligned_first_fragment")
int testcheck_ipv6_misaligned_first_fragment(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/ipv6_invalid_version_nonfirst_fragment")
int testpktgen_ipv6_invalid_version_nonfirst_fragment(struct __sk_buff *skb)
{
	return set_ipv6_invalid_version_nonfirst_fragment(skb);
}

SEC("tc/setup/ipv6_invalid_version_nonfirst_fragment")
int testsetup_ipv6_invalid_version_nonfirst_fragment(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_invalid_version_nonfirst_fragment")
int testcheck_ipv6_invalid_version_nonfirst_fragment(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_DROP);
}

SEC("tc/pktgen/utp_extension_outside_packet")
int testpktgen_utp_extension_outside_packet(struct __sk_buff *skb)
{
	return set_utp_extension_packet(skb, 160, 0);
}

SEC("tc/setup/utp_extension_outside_packet")
int testsetup_utp_extension_outside_packet(struct __sk_buff *skb)
{
	return is_utp(skb, IPPROTO_UDP, ETH_HLEN + IP4_HLEN + UDP_HLEN,
		ETH_HLEN + IP4_HLEN + UDP_HLEN + 160);
}

SEC("tc/check/utp_extension_outside_packet")
int testcheck_utp_extension_outside_packet(struct __sk_buff *skb)
{
	return check_setup_result(skb, false);
}

SEC("tc/pktgen/utp_extension_overrun")
int testpktgen_utp_extension_overrun(struct __sk_buff *skb)
{
	return set_utp_extension_packet(skb, 162, 10);
}

SEC("tc/setup/utp_extension_overrun")
int testsetup_utp_extension_overrun(struct __sk_buff *skb)
{
	return is_utp(skb, IPPROTO_UDP, ETH_HLEN + IP4_HLEN + UDP_HLEN,
		ETH_HLEN + IP4_HLEN + UDP_HLEN + 162);
}

SEC("tc/check/utp_extension_overrun")
int testcheck_utp_extension_overrun(struct __sk_buff *skb)
{
	return check_setup_result(skb, false);
}

SEC("tc/pktgen/utp_extension_valid")
int testpktgen_utp_extension_valid(struct __sk_buff *skb)
{
	return set_utp_extension_packet(skb, 162, 0);
}

SEC("tc/setup/utp_extension_valid")
int testsetup_utp_extension_valid(struct __sk_buff *skb)
{
	return is_utp(skb, IPPROTO_UDP, ETH_HLEN + IP4_HLEN + UDP_HLEN,
		ETH_HLEN + IP4_HLEN + UDP_HLEN + 162);
}

SEC("tc/check/utp_extension_valid")
int testcheck_utp_extension_valid(struct __sk_buff *skb)
{
	return check_setup_result(skb, true);
}

SEC("tc/pktgen/ipv6_atomic_udp_fragment")
int testpktgen_ipv6_atomic_udp_fragment(struct __sk_buff *skb)
{
	return set_ipv6_udp_fragment(skb, 7, 8, 19239, 85, 0x0000);
}

SEC("tc/setup/ipv6_atomic_udp_fragment")
int testsetup_ipv6_atomic_udp_fragment(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_atomic_udp_fragment")
int testcheck_ipv6_atomic_udp_fragment(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_status_code(skb, TC_ACT_REDIRECT);
}

SEC("tc/pktgen/ipv4_nonfirst_icmp_fragment")
int testpktgen_ipv4_nonfirst_icmp_fragment(struct __sk_buff *skb)
{
	return set_ipv4_nonfirst_fragment(skb, IPV4(192,168,0,1),
					  IPV4(1,1,1,1), IPPROTO_ICMP);
}

SEC("tc/setup/ipv4_nonfirst_icmp_fragment")
int testsetup_ipv4_nonfirst_icmp_fragment(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv4_nonfirst_icmp_fragment")
int testcheck_ipv4_nonfirst_icmp_fragment(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_NEXT);
}

SEC("tc/pktgen/ipv6_nonfirst_icmp_fragment")
int testpktgen_ipv6_nonfirst_icmp_fragment(struct __sk_buff *skb)
{
	return set_ipv6_nonfirst_fragment(skb, 1, 2, IPPROTO_ICMPV6);
}

SEC("tc/setup/ipv6_nonfirst_icmp_fragment")
int testsetup_ipv6_nonfirst_icmp_fragment(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/ipv6_nonfirst_icmp_fragment")
int testcheck_ipv6_nonfirst_icmp_fragment(struct __sk_buff *skb)
{
	return check_status_code(skb, TCX_NEXT);
}

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

SEC("tc/pktgen/udp_route_cache_miss")
int testpktgen_udp_route_cache_miss(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,1), IPV4(1,1,1,1),
			    20001, 443);
}

SEC("tc/setup/udp_route_cache_miss")
int testsetup_udp_route_cache_miss(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN + 30, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_miss")
int testcheck_udp_route_cache_miss(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_routing_cache(
		skb, TC_ACT_REDIRECT, IPV4(192,168,1,1), IPV4(1,1,1,1),
		20001, 443,
		true, OUTBOUND_USER_DEFINED_MIN + 30);
}

SEC("tc/pktgen/udp_route_cache_hit")
int testpktgen_udp_route_cache_hit(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,2), IPV4(1,1,1,2),
			    20002, 443);
}

SEC("tc/setup/udp_route_cache_hit")
int testsetup_udp_route_cache_hit(struct __sk_buff *skb)
{
	const __u8 cached_outbound = OUTBOUND_USER_DEFINED_MIN + 31;

	set_ipv4_udp_routing_cache(skb, IPV4(192,168,1,2), IPV4(1,1,1,2),
		20002, 443, cached_outbound,
		bpf_ktime_get_ns() + 10 * UDP_ROUTING_CACHE_TTL_NS);
	set_outbound_connectivity(cached_outbound);
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN + 32, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_hit")
int testcheck_udp_route_cache_hit(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_routing_cache(
		skb, TC_ACT_REDIRECT, IPV4(192,168,1,2), IPV4(1,1,1,2),
		20002, 443,
		true, OUTBOUND_USER_DEFINED_MIN + 31);
}

SEC("tc/pktgen/udp_route_cache_target_change")
int testpktgen_udp_route_cache_target_change(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,9), IPV4(1,1,1,9),
			    20009, 80);
}

SEC("tc/setup/udp_route_cache_target_change")
int testsetup_udp_route_cache_target_change(struct __sk_buff *skb)
{
	const __u8 cached_outbound = OUTBOUND_USER_DEFINED_MIN + 41;

	set_ipv4_udp_routing_cache(skb, IPV4(192,168,1,9), IPV4(1,1,1,8),
		20009, 443, cached_outbound,
		bpf_ktime_get_ns() + 10 * UDP_ROUTING_CACHE_TTL_NS);
	set_ipv4_udp_routing_handoff(
		IPV4(192,168,1,9), IPV4(1,1,1,8), 20009, 443,
		cached_outbound);
	set_outbound_connectivity(cached_outbound);
	set_routing_fallback(OUTBOUND_BLOCK, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_target_change")
int testcheck_udp_route_cache_target_change(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	int ret = check_ipv4_udp_routing_cache(
		skb, TCX_DROP, IPV4(192,168,1,9), IPV4(1,1,1,9),
		20009, 80, false, OUTBOUND_BLOCK);
	delete_ipv4_udp_routing_cache(skb,
		IPV4(192,168,1,9), IPV4(1,1,1,8), 20009, 443);
	delete_ipv4_udp_routing_handoff(
		IPV4(192,168,1,9), IPV4(1,1,1,8), 20009, 443);
	return ret;
}

SEC("tc/pktgen/udp_route_cache_skip_noalive")
int testpktgen_udp_route_cache_skip_noalive(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,10), IPV4(1,1,1,10),
			    20010, 443);
}

SEC("tc/setup/udp_route_cache_skip_noalive")
int testsetup_udp_route_cache_skip_noalive(struct __sk_buff *skb)
{
	const __u8 cached_outbound = OUTBOUND_USER_DEFINED_MIN + 42;
	const __u8 fallback_outbound = OUTBOUND_USER_DEFINED_MIN + 43;
	struct match_set cached_rule = {
		.type = MatchType_Fallback,
		.outbound = cached_outbound,
		.skip_while_noalive = true,
	};

	set_ipv4_udp_routing_cache(skb, IPV4(192,168,1,10), IPV4(1,1,1,10),
		20010, 443, cached_outbound,
		bpf_ktime_get_ns() + 10 * UDP_ROUTING_CACHE_TTL_NS);
	bpf_map_update_elem(&routing_map, &zero_key, &cached_rule, BPF_ANY);
	set_outbound_connectivity_state(
		cached_outbound, OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT);
	set_routing_fallback(fallback_outbound, false, &one_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_skip_noalive")
int testcheck_udp_route_cache_skip_noalive(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	clear_routing_entry(&one_key);
	return check_ipv4_udp_routing_state(
		skb, TC_ACT_REDIRECT, IPV4(192,168,1,10), IPV4(1,1,1,10),
		20010, 443, true, false, OUTBOUND_USER_DEFINED_MIN + 43);
}

SEC("tc/pktgen/udp_route_cache_dns_change")
int testpktgen_udp_route_cache_dns_change(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,11), IPV4(1,1,1,11),
			    20011, 53);
}

SEC("tc/setup/udp_route_cache_dns_change")
int testsetup_udp_route_cache_dns_change(struct __sk_buff *skb)
{
	const __u8 cached_outbound = OUTBOUND_USER_DEFINED_MIN + 44;

	set_ipv4_udp_routing_cache(skb, IPV4(192,168,1,11), IPV4(1,1,1,11),
		20011, 443, cached_outbound,
		bpf_ktime_get_ns() + 10 * UDP_ROUTING_CACHE_TTL_NS);
	set_ipv4_udp_routing_handoff(
		IPV4(192,168,1,11), IPV4(1,1,1,11), 20011, 443,
		cached_outbound);
	set_outbound_connectivity(cached_outbound);
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN + 45, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_dns_change")
int testcheck_udp_route_cache_dns_change(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	int ret = check_ipv4_udp_routing_cache(
		skb, TC_ACT_REDIRECT, IPV4(192,168,1,11), IPV4(1,1,1,11),
		20011, 53, true, OUTBOUND_CONTROL_PLANE_ROUTING);
	delete_ipv4_udp_routing_cache(skb,
		IPV4(192,168,1,11), IPV4(1,1,1,11), 20011, 443);
	delete_ipv4_udp_routing_handoff(
		IPV4(192,168,1,11), IPV4(1,1,1,11), 20011, 443);
	return ret;
}

SEC("tc/pktgen/udp_route_cache_expired")
int testpktgen_udp_route_cache_expired(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,3), IPV4(1,1,1,3),
			    20003, 443);
}

SEC("tc/setup/udp_route_cache_expired")
int testsetup_udp_route_cache_expired(struct __sk_buff *skb)
{
	set_ipv4_udp_routing_cache(skb, IPV4(192,168,1,3), IPV4(1,1,1,3),
		20003, 443, OUTBOUND_USER_DEFINED_MIN + 33, 1);
	set_outbound_connectivity(OUTBOUND_USER_DEFINED_MIN + 33);
	set_routing_fallback(OUTBOUND_USER_DEFINED_MIN + 34, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_expired")
int testcheck_udp_route_cache_expired(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_routing_cache(
		skb, TC_ACT_REDIRECT, IPV4(192,168,1,3), IPV4(1,1,1,3),
		20003, 443,
		true, OUTBOUND_USER_DEFINED_MIN + 34);
}

SEC("tc/pktgen/udp_route_cache_connectivity_direct")
int testpktgen_udp_route_cache_connectivity_direct(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,4), IPV4(1,1,1,4),
			    20004, 443);
}

SEC("tc/setup/udp_route_cache_connectivity_direct")
int testsetup_udp_route_cache_connectivity_direct(struct __sk_buff *skb)
{
	const __u8 cached_outbound = OUTBOUND_USER_DEFINED_MIN + 35;

	set_ipv4_udp_routing_cache(skb, IPV4(192,168,1,4), IPV4(1,1,1,4),
		20004, 443, cached_outbound,
		bpf_ktime_get_ns() + 10 * UDP_ROUTING_CACHE_TTL_NS);
	set_routing_fallback(cached_outbound, false, &zero_key);
	set_outbound_connectivity_state(
		cached_outbound, OUTBOUND_CONNECTIVITY_NOALIVE_DIRECT);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_connectivity_direct")
int testcheck_udp_route_cache_connectivity_direct(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_routing_cache(
		skb, TCX_NEXT, IPV4(192,168,1,4), IPV4(1,1,1,4),
		20004, 443, false, OUTBOUND_USER_DEFINED_MIN + 35);
}

SEC("tc/pktgen/udp_route_cache_connectivity_block")
int testpktgen_udp_route_cache_connectivity_block(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,5), IPV4(1,1,1,5),
			    20005, 443);
}

SEC("tc/setup/udp_route_cache_connectivity_block")
int testsetup_udp_route_cache_connectivity_block(struct __sk_buff *skb)
{
	const __u8 cached_outbound = OUTBOUND_USER_DEFINED_MIN + 37;

	set_ipv4_udp_routing_cache(skb, IPV4(192,168,1,5), IPV4(1,1,1,5),
		20005, 443, cached_outbound,
		bpf_ktime_get_ns() + 10 * UDP_ROUTING_CACHE_TTL_NS);
	set_routing_fallback(cached_outbound, false, &zero_key);
	set_outbound_connectivity_state(
		cached_outbound, OUTBOUND_CONNECTIVITY_NOALIVE_BLOCK);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_connectivity_block")
int testcheck_udp_route_cache_connectivity_block(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_routing_cache(
		skb, TCX_DROP, IPV4(192,168,1,5), IPV4(1,1,1,5),
		20005, 443, false, OUTBOUND_USER_DEFINED_MIN + 37);
}

SEC("tc/pktgen/udp_route_cache_connectivity_try_sniff")
int testpktgen_udp_route_cache_connectivity_try_sniff(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,6), IPV4(1,1,1,6),
			    20006, 443);
}

SEC("tc/setup/udp_route_cache_connectivity_try_sniff")
int testsetup_udp_route_cache_connectivity_try_sniff(struct __sk_buff *skb)
{
	const __u8 cached_outbound = OUTBOUND_USER_DEFINED_MIN + 39;

	set_ipv4_udp_routing_cache(skb, IPV4(192,168,1,6), IPV4(1,1,1,6),
		20006, 443, cached_outbound,
		bpf_ktime_get_ns() + 10 * UDP_ROUTING_CACHE_TTL_NS);
	set_routing_fallback(cached_outbound, false, &zero_key);
	set_outbound_connectivity_dead_try_sniff(cached_outbound);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_connectivity_try_sniff")
int testcheck_udp_route_cache_connectivity_try_sniff(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_routing_cache(
		skb, TC_ACT_REDIRECT, IPV4(192,168,1,6), IPV4(1,1,1,6),
		20006, 443,
		true, OUTBOUND_USER_DEFINED_MIN + 39);
}

SEC("tc/pktgen/udp_route_cache_direct_not_stored")
int testpktgen_udp_route_cache_direct_not_stored(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,7), IPV4(1,1,1,7),
			    20007, 443);
}

SEC("tc/setup/udp_route_cache_direct_not_stored")
int testsetup_udp_route_cache_direct_not_stored(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_DIRECT, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_direct_not_stored")
int testcheck_udp_route_cache_direct_not_stored(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_routing_cache(
		skb, TCX_NEXT, IPV4(192,168,1,7), IPV4(1,1,1,7),
		20007, 443,
		false, OUTBOUND_DIRECT);
}

SEC("tc/pktgen/udp_route_cache_block_not_stored")
int testpktgen_udp_route_cache_block_not_stored(struct __sk_buff *skb)
{
	return set_ipv4_udp(skb, IPV4(192,168,1,8), IPV4(1,1,1,8),
			    20008, 443);
}

SEC("tc/setup/udp_route_cache_block_not_stored")
int testsetup_udp_route_cache_block_not_stored(struct __sk_buff *skb)
{
	set_routing_fallback(OUTBOUND_BLOCK, false, &zero_key);
	bpf_tail_call(skb, &entry_call_map, 0);
	return TC_ACT_OK;
}

SEC("tc/check/udp_route_cache_block_not_stored")
int testcheck_udp_route_cache_block_not_stored(struct __sk_buff *skb)
{
	clear_routing_entry(&zero_key);
	return check_ipv4_udp_routing_cache(
		skb, TCX_DROP, IPV4(192,168,1,8), IPV4(1,1,1,8),
		20008, 443,
		false, OUTBOUND_BLOCK);
}
