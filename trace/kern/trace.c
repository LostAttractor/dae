#include "headers/if_ether_defs.h"
#include "headers/vmlinux.h"

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"

#define IFNAMSIZ 16
#define PNAME_LEN 32
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fff
#define EEXIST 17

enum event_flags {
	EVENT_F_TERMINAL = 1 << 0,
	EVENT_F_DROP = 1 << 1,
	EVENT_F_DROP_REASON = 1 << 2,
	EVENT_F_TUPLE_VALID = 1 << 3,
	EVENT_F_CONSUME_HOOK = 1 << 4,
};

struct trace_raw_args {
	u64 args[0];
};

union addr {
	u32 v4addr;
	struct {
		u64 d1;
		u64 d2;
	} v6addr;
} __attribute__((packed));

struct meta {
	u64 pc;
	u64 skb;
	u64 generation;
	u32 sequence;
	u32 drop_reason;
	u32 flags;
	u32 mark;
	u32 netns;
	u32 ifindex;
	u32 pid;
	unsigned char ifname[IFNAMSIZ];
	unsigned char pname[PNAME_LEN];
} __attribute__((packed));

struct tuple {
	union addr saddr;
	union addr daddr;
	u16 sport;
	u16 dport;
	u16 l3_proto;
	u8 l4_proto;
	u8 tcp_flags;
	u16 payload_len;
} __attribute__((packed));

struct event {
	struct meta meta;
	struct tuple tuple;
} __attribute__((packed));

const struct event *_ __attribute__((unused));

struct tracing_config {
	u32 not_dropped_reason;
	u32 consumed_reason;
	u16 port;
	u16 l4_proto;
	u8 ip_vsn;
};

const volatile struct tracing_config tracing_cfg = {};

struct trace_state {
	u64 generation;
	u32 next_sequence;
	u32 active_producers;
	u32 closing;
	u32 terminal_emitted;
	struct event terminal_event;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct trace_state);
	__uint(max_entries, 4096);
} trace_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} control SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
} gro_pending SEC(".maps");

struct runtime_state {
	u64 next_generation;
	u64 ring_lost;
	u64 admission_failures;
	u64 admission_races;
	u64 generation_failures;
	u64 active_producers;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct runtime_state);
	__uint(max_entries, 1);
} runtime SEC(".maps");

static __always_inline bool
range_valid(__u32 off, __u32 len, __u32 end)
{
	return off <= end && len <= end - off;
}

// Walk supported IPv6 extension headers. Any failed or out-of-bounds read
// invalidates the layout instead of interpreting an extension as L4.
static __always_inline bool
skip_ipv6_exthdr(void *skb_head, __u32 *off, __u32 end, __u8 *nexthdr)
{
#pragma unroll
	for (int i = 0; i < 8; i++) {
		__u8 next;
		__u8 hdrlen;
		__u32 len;

		switch (*nexthdr) {
		case 0:  // Hop-by-Hop
		case 43: // Routing
		case 60: // Destination Options
			if (!range_valid(*off, 2, end))
				return false;
			if (bpf_probe_read_kernel(&next, sizeof(next),
						  skb_head + *off) < 0)
				return false;
			if (bpf_probe_read_kernel(&hdrlen, sizeof(hdrlen),
						  skb_head + *off + 1) < 0)
				return false;
			len = ((__u32)hdrlen + 1) * 8;
			if (!range_valid(*off, len, end))
				return false;
			*off += len;
			*nexthdr = next;
			break;
		case 51: // Authentication Header
			if (!range_valid(*off, 2, end))
				return false;
			if (bpf_probe_read_kernel(&next, sizeof(next),
						  skb_head + *off) < 0)
				return false;
			if (bpf_probe_read_kernel(&hdrlen, sizeof(hdrlen),
						  skb_head + *off + 1) < 0)
				return false;
			len = ((__u32)hdrlen + 2) * 4;
			if (!range_valid(*off, len, end))
				return false;
			*off += len;
			*nexthdr = next;
			break;
		case 44: // Fragment
			{
				__be16 frag_off;

				if (!range_valid(*off, 8, end))
					return false;
				if (bpf_probe_read_kernel(&next, sizeof(next),
							  skb_head + *off) < 0)
					return false;
				if (bpf_probe_read_kernel(&frag_off, sizeof(frag_off),
							  skb_head + *off + 2) < 0)
					return false;
				*off += 8;
				*nexthdr = next;
				if (frag_off & bpf_htons(0xfff8)) {
					*nexthdr = 0;
					return true;
				}
			}
			break;
		default:
			return true;
		}
	}

	// More extension headers remain than this bounded parser can validate.
	switch (*nexthdr) {
	case 0:
	case 43:
	case 44:
	case 51:
	case 60:
		return false;
	default:
		return true;
	}
}

static __always_inline u32
get_netns(struct sk_buff *skb)
{
	u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

	// if skb->dev is not initialized, try to get ns from sk->__sk_common.skc_net.net->ns.inum
	if (netns == 0) {
		struct sock *sk = BPF_CORE_READ(skb, sk);
		if (sk != NULL)
			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	}

	return netns;
}

static __always_inline bool
set_tuple(struct tuple *tpl, struct sk_buff *skb)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	__u32 linear_end = BPF_CORE_READ(skb, tail);
	__u32 l3_off = BPF_CORE_READ(skb, network_header);
	__u32 l4_off;
	__u32 packet_end;
	__u32 l3_total_len;
	__u8 version_ihl;

	if (!range_valid(l3_off, sizeof(version_ihl), linear_end))
		return false;
	if (bpf_probe_read_kernel(&version_ihl, sizeof(version_ihl),
				  skb_head + l3_off) < 0)
		return false;

	if ((version_ihl >> 4) == 4) {
		struct iphdr ip4;
		__u32 ihl = (__u32)(version_ihl & 0x0f) * 4;
		__u16 frag_off;

		if (ihl < sizeof(ip4) ||
		    !range_valid(l3_off, sizeof(ip4), linear_end))
			return false;
		if (bpf_probe_read_kernel(&ip4, sizeof(ip4),
					  skb_head + l3_off) < 0)
			return false;
		l3_total_len = bpf_ntohs(ip4.tot_len);
		if (l3_total_len < ihl || l3_total_len > ~l3_off)
			return false;
		packet_end = l3_off + l3_total_len;
		if (packet_end < linear_end)
			linear_end = packet_end;
		if (!range_valid(l3_off, ihl, linear_end))
			return false;

		tpl->saddr.v4addr = ip4.saddr;
		tpl->daddr.v4addr = ip4.daddr;
		tpl->l3_proto = ETH_P_IP;
		frag_off = bpf_ntohs(ip4.frag_off);
		if (frag_off & IPV4_FRAGMENT_OFFSET_MASK) {
			tpl->l4_proto = 0;
			return false;
		}
		tpl->l4_proto = ip4.protocol;
		l4_off = l3_off + ihl;
	} else if ((version_ihl >> 4) == 6) {
		struct ipv6hdr ip6;
		__u32 payload_len;

		if (!range_valid(l3_off, sizeof(ip6), linear_end))
			return false;
		if (bpf_probe_read_kernel(&ip6, sizeof(ip6),
					  skb_head + l3_off) < 0)
			return false;
		payload_len = bpf_ntohs(ip6.payload_len);
		l3_total_len = sizeof(ip6) + payload_len;
		if (l3_total_len > ~l3_off)
			return false;
		packet_end = l3_off + l3_total_len;
		if (packet_end < linear_end)
			linear_end = packet_end;

		__builtin_memcpy(&tpl->saddr, &ip6.saddr, sizeof(ip6.saddr));
		__builtin_memcpy(&tpl->daddr, &ip6.daddr, sizeof(ip6.daddr));
		tpl->l3_proto = ETH_P_IPV6;
		tpl->l4_proto = ip6.nexthdr;
		l4_off = l3_off + sizeof(ip6);
		if (!skip_ipv6_exthdr(skb_head, &l4_off, linear_end,
					  &tpl->l4_proto))
			return false;
		if (tpl->l4_proto == 0)
			return false;
	} else {
		return false;
	}

	if (tpl->l4_proto == IPPROTO_TCP) {
		struct tcphdr tcp;
		__u8 tcp_doff;
		__u32 l4_hdr_len;
		__u32 l3_hdr_len = l4_off - l3_off;

		if (!range_valid(l4_off, sizeof(tcp), linear_end))
			return false;
		if (bpf_probe_read_kernel(&tcp, sizeof(tcp),
					  skb_head + l4_off) < 0)
			return false;
		if (bpf_probe_read_kernel(&tcp_doff, sizeof(tcp_doff),
					  skb_head + l4_off + 12) < 0)
			return false;
		l4_hdr_len = (__u32)(tcp_doff >> 4) * 4;
		if (l4_hdr_len < sizeof(tcp) ||
		    !range_valid(l4_off, l4_hdr_len, linear_end))
			return false;

		tpl->sport = tcp.source;
		tpl->dport = tcp.dest;
		if (bpf_probe_read_kernel(&tpl->tcp_flags,
					  sizeof(tpl->tcp_flags),
					  skb_head + l4_off + 13) < 0)
			return false;
		if (l3_total_len >= l3_hdr_len + l4_hdr_len)
			tpl->payload_len = l3_total_len - l3_hdr_len -
					   l4_hdr_len;
	} else if (tpl->l4_proto == IPPROTO_UDP) {
		struct udphdr udp;
		__u32 udp_len;
		__u32 l3_hdr_len = l4_off - l3_off;
		__u32 l3_payload_len;

		if (l3_total_len < l3_hdr_len)
			return false;
		l3_payload_len = l3_total_len - l3_hdr_len;
		if (!range_valid(l4_off, sizeof(udp), linear_end))
			return false;
		if (bpf_probe_read_kernel(&udp, sizeof(udp),
					  skb_head + l4_off) < 0)
			return false;
		tpl->sport = udp.source;
		tpl->dport = udp.dest;
		udp_len = bpf_ntohs(udp.len);
		// The UDP header must be linear, but its payload may be nonlinear.
		if (udp_len < sizeof(udp) || udp_len > l3_payload_len)
			return false;
		tpl->payload_len = udp_len - sizeof(udp);
	} else {
		return false;
	}

	return true;
}

static __always_inline bool
tuple_matches(const struct tuple *tpl)
{
	if (tracing_cfg.ip_vsn == 4 && tpl->l3_proto != ETH_P_IP)
		return false;
	if (tracing_cfg.ip_vsn == 6 && tpl->l3_proto != ETH_P_IPV6)
		return false;
	if (tpl->l4_proto != tracing_cfg.l4_proto)
		return false;
	return tpl->dport == tracing_cfg.port ||
	       tpl->sport == tracing_cfg.port;
}

static __always_inline void
set_meta(struct meta *meta, struct sk_buff *skb, __u64 pc)
{
	meta->pc = pc;
	meta->skb = (__u64)skb;
	meta->mark = BPF_CORE_READ(skb, mark);
	meta->netns = get_netns(skb);
	meta->ifindex = BPF_CORE_READ(skb, dev, ifindex);
	BPF_CORE_READ_STR_INTO(&meta->ifname, skb, dev, name);

	struct task_struct *current = (void *)bpf_get_current_task();
	meta->pid = BPF_CORE_READ(current, pid);
	u64 arg_start = BPF_CORE_READ(current, mm, arg_start);
	bpf_probe_read_user_str(&meta->pname, PNAME_LEN, (void *)arg_start);
}

static __always_inline struct runtime_state *
get_runtime(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&runtime, &key);
}

static __always_inline bool
tracing_stopped(void)
{
	__u32 key = 0;
	__u32 *stopped = bpf_map_lookup_elem(&control, &key);

	return stopped && *stopped;
}

static __always_inline struct trace_state *
admit_trace(struct runtime_state *rt, __u64 skb_addr)
{
	struct trace_state initial = {};
	struct trace_state *state;
	long ret;

	initial.generation = __sync_fetch_and_add(&rt->next_generation, 1) + 1;
	if (!initial.generation) {
		__sync_fetch_and_add(&rt->generation_failures, 1);
		return NULL;
	}
	ret = bpf_map_update_elem(&trace_states, &skb_addr, &initial,
				  BPF_NOEXIST);
	if (ret == -EEXIST) {
		__sync_fetch_and_add(&rt->admission_races, 1);
		state = bpf_map_lookup_elem(&trace_states, &skb_addr);
		if (state)
			return state;
	} else if (ret == 0) {
		state = bpf_map_lookup_elem(&trace_states, &skb_addr);
		if (state)
			return state;
	}

	__sync_fetch_and_add(&rt->admission_failures, 1);
	return NULL;
}

static __always_inline bool
skb_has_live_reference(struct sk_buff *skb)
{
	return BPF_CORE_READ(skb, users.refs.counter) > 0;
}

static __always_inline struct runtime_state *
enter_producer(void)
{
	struct runtime_state *rt;

	if (tracing_stopped())
		return NULL;
	rt = get_runtime();
	if (!rt)
		return NULL;
	__sync_fetch_and_add(&rt->active_producers, 1);
	if (tracing_stopped()) {
		__sync_fetch_and_sub(&rt->active_producers, 1);
		return NULL;
	}
	return rt;
}

static __always_inline void
output_event(struct runtime_state *rt, struct event *ev)
{
	if (bpf_ringbuf_output(&events, ev, sizeof(*ev), 0) < 0)
		__sync_fetch_and_add(&rt->ring_lost, 1);
}

static __always_inline void
leave_trace(struct runtime_state *rt, struct trace_state *state,
	    __u64 skb_addr)
{
	if (__sync_fetch_and_sub(&state->active_producers, 1) != 1 ||
	    !state->closing ||
	    __sync_val_compare_and_swap(&state->terminal_emitted, 0, 1) != 0)
		return;

	state->terminal_event.meta.sequence =
		__sync_fetch_and_add(&state->next_sequence, 1);
	output_event(rt, &state->terminal_event);
	bpf_map_delete_elem(&trace_states, &skb_addr);
}

static __always_inline int
handle_skb(struct sk_buff *skb, __u64 pc, __u32 flags,
	   __u32 drop_reason)
{
	struct runtime_state *rt = enter_producer();
	struct trace_state *state;
	__u64 skb_addr;
	bool tuple_valid;
	struct event ev = {};

	if (!rt)
		return 0;

	if (!skb)
		goto out;
	skb_addr = (__u64)skb;

	state = bpf_map_lookup_elem(&trace_states, &skb_addr);
	if (!state && !(flags & EVENT_F_TERMINAL) &&
	    !skb_has_live_reference(skb))
		goto out;

	tuple_valid = set_tuple(&ev.tuple, skb);
	if (!state) {
		if (!tuple_valid || !tuple_matches(&ev.tuple))
			goto out;
		state = admit_trace(rt, skb_addr);
		if (!state)
			goto out;
	}
	__sync_fetch_and_add(&state->active_producers, 1);
	if (state->closing)
		goto out_trace;

	if (tuple_valid)
		flags |= EVENT_F_TUPLE_VALID;

	set_meta(&ev.meta, skb, pc);
	ev.meta.generation = state->generation;
	ev.meta.flags = flags;
	ev.meta.drop_reason = drop_reason;

	if (flags & EVENT_F_TERMINAL) {
		if (__sync_val_compare_and_swap(&state->closing, 0, 1) == 0)
			__builtin_memcpy(&state->terminal_event, &ev, sizeof(ev));
	} else {
		ev.meta.sequence =
			__sync_fetch_and_add(&state->next_sequence, 1);
		output_event(rt, &ev);
	}
out_trace:
	leave_trace(rt, state, skb_addr);
out:
	__sync_fetch_and_sub(&rt->active_producers, 1);
	return 0;
}

// kfree_skbmem runs after skb payload metadata may already have been released.
// Complete any still-live trace without dereferencing the skb so direct free
// paths cannot leave a stale address in trace_states.
static __always_inline int
handle_skb_lifetime_end(__u64 skb_addr, __u64 pc, __u32 flags)
{
	struct runtime_state *rt = enter_producer();
	struct trace_state *state;
	struct event ev = {};

	if (!rt)
		return 0;
	state = bpf_map_lookup_elem(&trace_states, &skb_addr);
	if (!state)
		goto out;

	__sync_fetch_and_add(&state->active_producers, 1);
	if (state->closing)
		goto out_trace;

	ev.meta.pc = pc;
	ev.meta.skb = skb_addr;
	ev.meta.generation = state->generation;
	ev.meta.flags = EVENT_F_TERMINAL | flags;
	if (__sync_val_compare_and_swap(&state->closing, 0, 1) == 0)
		__builtin_memcpy(&state->terminal_event, &ev, sizeof(ev));
out_trace:
	leave_trace(rt, state, skb_addr);
out:
	__sync_fetch_and_sub(&rt->active_producers, 1);
	return 0;
}

static __always_inline int
remember_gro_skb(struct trace_raw_args *ctx, __u32 slot)
{
	__u64 *pending = bpf_map_lookup_elem(&gro_pending, &slot);

	if (pending)
		*pending = tracing_stopped() ? 0 : ctx->args[0];
	return 0;
}

static __always_inline int
finish_gro_skb(struct trace_raw_args *ctx, __u32 slot)
{
	__u64 *pending = bpf_map_lookup_elem(&gro_pending, &slot);
	__u64 skb_addr;

	if (!pending)
		return 0;
	skb_addr = *pending;
	*pending = 0;
	if (ctx->args[0] != GRO_MERGED_FREE || !skb_addr)
		return 0;
	return handle_skb_lifetime_end(skb_addr, 0, EVENT_F_CONSUME_HOOK);
}

#define KPROBE_SKB_AT(X)                                                \
  SEC("kprobe/skb-" #X)                                                \
  int kprobe_skb_##X(struct pt_regs *ctx)                              \
  {                                                                    \
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM##X(ctx);      \
    return handle_skb(skb, bpf_get_func_ip(ctx), 0, 0);                \
  }

KPROBE_SKB_AT(1)
KPROBE_SKB_AT(2)
KPROBE_SKB_AT(3)
KPROBE_SKB_AT(4)
KPROBE_SKB_AT(5)

#define KPROBE_MULTI_SKB_AT(X)                                          \
  SEC("kprobe.multi/skb-" #X)                                          \
  int kprobe_multi_skb_##X(struct pt_regs *ctx)                         \
  {                                                                    \
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM##X(ctx);      \
    return handle_skb(skb, bpf_get_func_ip(ctx), 0, 0);                \
  }

KPROBE_MULTI_SKB_AT(1)
KPROBE_MULTI_SKB_AT(2)
KPROBE_MULTI_SKB_AT(3)
KPROBE_MULTI_SKB_AT(4)
KPROBE_MULTI_SKB_AT(5)

SEC("kprobe/skb_lifetime_termination")
int kprobe_skb_lifetime_termination(struct pt_regs *ctx)
{
	return handle_skb_lifetime_end(PT_REGS_PARM1(ctx),
				       bpf_get_func_ip(ctx), 0);
}

SEC("raw_tracepoint/kfree_skb")
int raw_tracepoint_kfree_skb_reason(struct trace_raw_args *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
	__u64 location = ctx->args[1];
	__u32 reason = ctx->args[2];
	__u32 flags = EVENT_F_TERMINAL | EVENT_F_DROP_REASON;

	if (reason != tracing_cfg.not_dropped_reason &&
	    reason != tracing_cfg.consumed_reason)
		flags |= EVENT_F_DROP;
	return handle_skb(skb, location, flags, reason);
}

SEC("raw_tracepoint/kfree_skb")
int raw_tracepoint_kfree_skb_legacy(struct trace_raw_args *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
	__u64 location = ctx->args[1];

	return handle_skb(skb, location, EVENT_F_TERMINAL | EVENT_F_DROP, 0);
}

SEC("raw_tracepoint/consume_skb")
int raw_tracepoint_consume_skb(struct trace_raw_args *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->args[0];

	return handle_skb(skb, 0,
			  EVENT_F_TERMINAL | EVENT_F_CONSUME_HOOK, 0);
}

SEC("raw_tracepoint/napi_gro_receive_entry")
int raw_tracepoint_napi_gro_receive_entry(struct trace_raw_args *ctx)
{
	return remember_gro_skb(ctx, 0);
}

SEC("raw_tracepoint/napi_gro_receive_exit")
int raw_tracepoint_napi_gro_receive_exit(struct trace_raw_args *ctx)
{
	return finish_gro_skb(ctx, 0);
}

SEC("raw_tracepoint/napi_gro_frags_entry")
int raw_tracepoint_napi_gro_frags_entry(struct trace_raw_args *ctx)
{
	return remember_gro_skb(ctx, 1);
}

SEC("raw_tracepoint/napi_gro_frags_exit")
int raw_tracepoint_napi_gro_frags_exit(struct trace_raw_args *ctx)
{
	return finish_gro_skb(ctx, 1);
}

SEC("license") const char __license[] = "Dual BSD/GPL";
