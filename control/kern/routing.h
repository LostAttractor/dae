/* SPDX-License-Identifier: AGPL-3.0-only */
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

#ifndef DAE_ROUTING_H
#define DAE_ROUTING_H

#include "routing_abi.h"

/* Policy selection and evaluation. Packet parsing, connection ownership,
 * caching and forwarding belong to tproxy.c. The caller provides parsed
 * l4_hdr input and the outbound connectivity map.
 */

static __always_inline bool equal16(const __be32 x[4], const __be32 y[4])
{
	return x[0] == y[0] && x[1] == y[1] &&
	       x[2] == y[2] && x[3] == y[3];
}

struct route_params {
	const struct l4_hdr *l4hdr;
	const __be32 *saddr;
	const __be32 *daddr;
	const __u8 *mac;
	const __be32 *pname;
	__u32 ifindex;
	__u32 profile_id;
	const struct routing_profile *profile;
	__u8 l4proto_type;
	__u8 ipversion_type;
	__u8 dscp;
	bool isdns : 1;
};

enum match_result {
	MATCH_MISS,
	MATCH_MAYBE,
	MATCH_HIT,
};

struct route_ctx {
	const struct route_params *params;
	const struct domain_routing *domain;
	/* Keep the PC in callback context so numeric-iterator verification
	 * converges despite data-dependent forward jumps.
	 */
	__u32 position;
	__u16 h_dport;
	__u16 h_sport;
	__s64 result;
	struct lpm_key lpm_key_saddr, lpm_key_daddr, lpm_key_mac;
	/* Volatile prevents loop-carried states from being specialized into
	 * long verifier paths; the two tri-state values stay in packet context.
	 */
	volatile __u8 subrule;
	volatile __u8 must;
	__u8 capture_flags;
	volatile bool rule_uncertain;
	bool flow_bump;
	bool skipped_noalive;
	bool domain_loaded;
};

/* OR accumulates MISS < MAYBE < HIT. A MAYBE means only some of the names
 * mapped to this destination match, so the exact domain is needed.
 */
static __always_inline int route_predicate(struct route_ctx *ctx,
					   const struct match_set *match_set)
{
	struct lpm_key *lpm_key;
	struct map_lpm_type *lpm;
	const struct domain_routing *domain;

	switch (match_set->type) {
	case MatchType_Mac:
		lpm_key = &ctx->lpm_key_mac;
		goto lookup_lpm;
	case MatchType_IpSet:
		lpm_key = &ctx->lpm_key_daddr;
		goto lookup_lpm;
	case MatchType_SourceIpSet:
		lpm_key = &ctx->lpm_key_saddr;
lookup_lpm:
		lpm = bpf_map_lookup_elem(&lpm_array_map, &match_set->index);
		if (unlikely(!lpm))
			return -EFAULT;
		return bpf_map_lookup_elem(lpm, lpm_key) ? MATCH_HIT : MATCH_MISS;
	case MatchType_Port:
		if (match_set->port_range.port_start <= ctx->h_dport &&
		    ctx->h_dport <= match_set->port_range.port_end) {
			return MATCH_HIT;
		}
		break;
	case MatchType_SourcePort:
		if (match_set->port_range.port_start <= ctx->h_sport &&
		    ctx->h_sport <= match_set->port_range.port_end) {
			return MATCH_HIT;
		}
		break;
	case MatchType_L4Proto:
		if (ctx->params->l4proto_type & match_set->l4proto_type)
			return MATCH_HIT;
		break;
	case MatchType_IpVersion:
		if (ctx->params->ipversion_type & match_set->ip_version)
			return MATCH_HIT;
		break;
	case MatchType_DomainSet:

		/* One snapshot per packet, including absence. All domain predicates
		 * read the same atomically published pair of bitmaps.
		 */
		if (!ctx->domain_loaded) {
			ctx->domain = bpf_map_lookup_elem(&domain_routing_map,
							  ctx->params->daddr);
			ctx->domain_loaded = true;
		}
		domain = ctx->domain;

		/* Domain IDs are shared across programs and independent of the
		 * instruction offset (including duplicate DNAT predicates). */
		__u32 domain_id = match_set->index;

		if (domain_id >= MAX_MATCH_SET_LEN)
			return -EINVAL;
		if (domain &&
		    (domain->routing[domain_id / 32] >> (domain_id % 32)) & 1) {
			// All domains mapped by the current IP address are matched.
			return MATCH_HIT;
		} else if (domain &&
			   (domain->bump[domain_id / 32] >> (domain_id % 32)) & 1) {
			// The current IP has mapped domains that match this rule, but not
			// all of them do.
			return MATCH_MAYBE;
		}
		break;
	case MatchType_ProcessName:
		if (ctx->params->pname && equal16(match_set->pname, ctx->params->pname))
			return MATCH_HIT;
		break;
	case MatchType_IfIndex:
		if (ctx->params->ifindex == match_set->ifindex)
			return MATCH_HIT;
		break;
	case MatchType_Dscp:
		if (ctx->params->dscp == match_set->dscp)
			return MATCH_HIT;
		break;
	case MatchType_Fallback:
		return MATCH_HIT;
	default:
		return -EINVAL;
	}

	return MATCH_MISS;
}

static int route_step(struct route_ctx *ctx)
{
	const struct routing_profile *profile = ctx->params->profile;
	__u32 position = ctx->position;

	if (unlikely(position >= MAX_MATCH_SET_LEN || position >= profile->length))
		return 1;
	__u32 k = profile->steps[position];

	if (unlikely(k >= MAX_MATCH_SET_LEN))
		return 1;
	const struct match_set *match = bpf_map_lookup_elem(&routing_map, &k);

	if (unlikely(!match))
		return 1;

	if (ctx->subrule != MATCH_HIT) {
		int result = route_predicate(ctx, match);

		if (result < 0)
			return 1;
		if (result > ctx->subrule)
			ctx->subrule = result;
	}

	__u32 distance = 1;

	if (match->action == MatchAction_Or) {
		if (ctx->subrule == MATCH_HIT)
			distance = match->mark;
		goto advance;
	}

	/* Only the clause tail applies NOT. MAYBE is unchanged by negation. */
	__u8 clause = ctx->subrule;

	ctx->subrule = MATCH_MISS;
	if (match->flags & MATCH_FLAG_NOT)
		clause = MATCH_HIT - clause;
	if (clause == MATCH_MISS) {
		if (match->action == MatchAction_And)
			distance = match->mark;
		goto next_rule;
	}
	ctx->rule_uncertain |= clause == MATCH_MAYBE;
	if (match->action == MatchAction_And)
		goto advance;

	/* Controls accumulate until FlowEnd. Ambiguous capture/bump rules are
	 * candidates; ambiguous must cannot override a later definite must.
	 */
	switch (match->action) {
	case MatchAction_Must:
		if (!ctx->rule_uncertain)
			ctx->must = MATCH_HIT;
		else if (ctx->must == MATCH_MISS)
			ctx->must = MATCH_MAYBE;
		goto next_rule;
	case MatchAction_Bump:
		ctx->flow_bump = true;
		goto next_rule;
	case MatchAction_Capture:
		ctx->capture_flags |= MATCH_CAPTURE_FLAGS(match);
		/* Destination rules run before flow controls and routing. Their exact
		 * target is selected in userspace; never commit a route for the old IP.
		 */
		if (ctx->capture_flags & (CAPTURE_DESTINATION | CAPTURE_HTTP_REQUEST))
			goto exact_domain;
		goto next_rule;
	case MatchAction_FlowEnd:
		if (ctx->flow_bump || ctx->must == MATCH_MAYBE)
			goto exact_domain;
		goto next_rule;
	case MatchAction_Route:
		break;
	default:
		return 1;
	}

	if (match->flags & MATCH_FLAG_SKIP_NOALIVE) {
		struct outbound_connectivity_query q = {
			.outbound = match->outbound,
			.ipversion = (ctx->params->ipversion_type & IpVersionType_4) ? 4 : 6,
			.l4proto = (ctx->params->l4proto_type & L4ProtoType_TCP) ?
				IPPROTO_TCP : IPPROTO_UDP,
		};
		__u32 *state = bpf_map_lookup_elem(&outbound_connectivity_map, &q);

		if (!state || *state != OUTBOUND_CONNECTIVITY_ALIVE) {
			ctx->skipped_noalive = true;
			goto next_rule;
		}
	}

	/* An ambiguous terminal cannot commit its mark or must bit. */
	if (ctx->rule_uncertain)
		goto exact_domain;
	bool must = ctx->must == MATCH_HIT || (match->flags & MATCH_FLAG_MUST);
	__u8 outbound = match->outbound;

	if (!must && ctx->params->isdns && !(match->flags & MATCH_FLAG_BYPASS))
		ctx->capture_flags |= CAPTURE_DNS;
	ctx->result = (__s64)outbound | ((__s64)match->mark << 8) |
		      ((__s64)must << 40);
	return 1;

exact_domain:
	ctx->result = (__s64)OUTBOUND_CONTROL_PLANE_ROUTING |
		      ((__s64)(ctx->must == MATCH_HIT) << 40);
	return 1;
next_rule:
	ctx->rule_uncertain = false;
advance:
	/* The compiler checks rule structure; the kernel checks jump bounds. */
	if (unlikely(!distance || distance > MAX_MATCH_SET_LEN - position))
		return 1;
	ctx->position = position + distance;
	return 0;
}

static __always_inline int select_routing_profile(struct route_params *params)
{
	__u32 *selected_id =
		bpf_map_lookup_elem(&routing_interface_map, &params->ifindex);

	params->profile_id = selected_id ? *selected_id : default_routing_profile;
	const struct routing_profile *profile =
		bpf_map_lookup_elem(&routing_profile_map, &params->profile_id);

	if (unlikely(!profile || !profile->length ||
		     profile->length > MAX_MATCH_SET_LEN))
		return -EFAULT;
	params->profile = profile;
	return 0;
}

static __always_inline __s64 route(struct route_params *params)
{
	int index;
	struct route_ctx ctx = {};

	ctx.params = params;
	ctx.result = -EFAULT;

	/* TCP and UDP share the source/destination port layout. */
	ctx.h_dport = bpf_ntohs(params->l4hdr->udph.dest);
	ctx.h_sport = bpf_ntohs(params->l4hdr->udph.source);

	ctx.lpm_key_saddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx.lpm_key_daddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx.lpm_key_mac.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
	__builtin_memcpy(ctx.lpm_key_saddr.data, params->saddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy(ctx.lpm_key_daddr.data, params->daddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy((__u8 *)ctx.lpm_key_mac.data + IPV6_BYTE_LENGTH - ETH_ALEN,
			 params->mac, ETH_ALEN);

	bpf_for(index, 0, MAX_MATCH_SET_LEN) {
		if (route_step(&ctx))
			break;
	}
	if (ctx.result >= 0) {
		ctx.result |= (__s64)ctx.capture_flags << ROUTE_RESULT_CAPTURE_SHIFT;
		if (ctx.skipped_noalive)
			ctx.result |= ROUTE_RESULT_SKIPPED_NOALIVE;
		return ctx.result;
	}
	bpf_printk(
		"No match_set hits. Did coder forget to sync common/consts/ebpf.go with enum MatchType?");
	return -EPERM;
}

#endif /* DAE_ROUTING_H */
