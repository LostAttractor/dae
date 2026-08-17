// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

// +build ignore

#define BPF_NO_PRESERVE_ACCESS_INDEX 1

#include "errno-base.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop

#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define MAX_SPLICE_ENDPOINTS (65536 * 2)
#define SPLICE_FAULT_TARGET 1ULL
#define SPLICE_FAULT_APPLY 2ULL
#define SPLICE_FAULT_EGRESS 4ULL

#define unlikely(x) __builtin_expect((x), 0)

struct splice_endpoint {
	__u64 peer_cookie;
	__u64 expected;
};

struct splice_stats {
	__u64 skb_pass;
	__u64 skb_redirected;
	__u64 egress_accepted;
	__u64 fault;
	__u64 skb_active;
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, __u64);
	__type(value, __u64);
	__uint(max_entries, MAX_SPLICE_ENDPOINTS);
} splice_socks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct splice_endpoint);
	__uint(max_entries, MAX_SPLICE_ENDPOINTS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} splice_endpoints SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct splice_stats);
	__uint(max_entries, MAX_SPLICE_ENDPOINTS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} splice_stats SEC(".maps");

SEC("sk_skb/stream_verdict")
int splice_stream_verdict(struct __sk_buff *skb)
{
	const struct splice_endpoint *endpoint;
	struct splice_stats *stats;
	__u64 peer_cookie;
	__u64 cookie;
	long ret;

	cookie = bpf_get_socket_cookie(skb);
	if (!cookie)
		return SK_PASS;
	stats = bpf_map_lookup_elem(&splice_stats, &cookie);
	if (!stats)
		return SK_PASS;
	__sync_fetch_and_add(&stats->skb_active, 1);
	if (!skb->len)
		goto out;
	endpoint = bpf_map_lookup_elem(&splice_endpoints, &cookie);
	if (!endpoint)
		goto out;
	peer_cookie = endpoint->peer_cookie;
	if (!peer_cookie || stats->skb_pass != endpoint->expected) {
		__sync_fetch_and_add(&stats->skb_pass, skb->len);
		goto out;
	}
	ret = bpf_sk_redirect_hash(skb, &splice_socks, &peer_cookie, 0);
	if (unlikely(ret != SK_PASS)) {
		__sync_fetch_and_or(&stats->fault, SPLICE_FAULT_TARGET);
		__sync_fetch_and_add(&stats->skb_pass, skb->len);
		goto out;
	}
	__sync_fetch_and_add(&stats->skb_redirected, skb->len);
out:
	__sync_fetch_and_sub(&stats->skb_active, 1);
	return SK_PASS;
}

SEC("fexit/sk_psock_verdict_apply")
int BPF_PROG(splice_account_skb_fault, struct sk_psock *psock,
	     struct sk_buff *skb, int verdict, int ret)
{
	struct splice_stats *stats;
	__u64 cookie;

	if (!psock || !psock->sk)
		return 0;
	cookie = bpf_get_socket_cookie(psock->sk);
	if (!cookie)
		return 0;
	stats = bpf_map_lookup_elem(&splice_stats, &cookie);
	if (!stats)
		return 0;
	(void)skb;
	if (verdict == __SK_REDIRECT && ret < 0)
		__sync_fetch_and_or(&stats->fault, SPLICE_FAULT_APPLY);
	return 0;
}

SEC("fexit/skb_send_sock")
int BPF_PROG(splice_account_egress, struct sock *sk, struct sk_buff *skb,
	     int offset, int len, int ret)
{
	struct splice_stats *stats;
	struct sock *source;
	__u64 cookie;

	(void)offset;
	(void)len;
	if (!sk)
		return 0;
	if (ret <= 0) {
		if (!skb || ret == -EAGAIN)
			return 0;
		source = __builtin_preserve_access_index(skb->sk);
		if (!source)
			return 0;
		cookie = bpf_get_socket_cookie(source);
		stats = bpf_map_lookup_elem(&splice_stats, &cookie);
		if (stats)
			__sync_fetch_and_or(&stats->fault, SPLICE_FAULT_EGRESS);
		return 0;
	}
	cookie = bpf_get_socket_cookie(sk);
	if (!cookie)
		return 0;
	stats = bpf_map_lookup_elem(&splice_stats, &cookie);
	if (!stats)
		return 0;
	__sync_fetch_and_add(&stats->egress_accepted, (__u64)ret);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
