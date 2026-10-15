/* SPDX-License-Identifier: AGPL-3.0-only */
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

#ifndef DAE_ROUTING_H
#define DAE_ROUTING_H

#include "routing_abi.h"

/* Policy selection and evaluation. Packet parsing, connection ownership,
 * caching and forwarding belong to tproxy.c. The caller provides parsed
 * packet fields and the outbound connectivity map.
 */

static __always_inline bool equal16(const __be32 x[4], const __be32 y[4])
{
	return x[0] == y[0] && x[1] == y[1] &&
	       x[2] == y[2] && x[3] == y[3];
}

/* Pointer-free input lets the verifier check route() independently of packet
 * parsing and connection state. profile_id is filled by policy selection.
 */
struct route_params {
	__be32 saddr[4];
	__be32 daddr[4];
	__be32 pname[4];
	__u32 ifindex;
	__u32 profile_id;
	__u32 physinif;
	__be16 sport;
	__be16 dport;
	__u8 mac[6];
	__u8 l4proto_type;
	__u8 ipversion_type;
	__u8 dscp;
	bool isdns;
	bool has_pname;
};

enum match_result {
	MATCH_MISS,
	MATCH_MAYBE,
	MATCH_HIT,
};

/* Loop control only; the routing decision is stored in route_state.result. */
enum route_step_result {
	ROUTE_CONTINUE,
	ROUTE_STOP,
};

enum http_client_admission {
	HTTP_CLIENT_UNCHECKED,
	HTTP_CLIENT_DENIED,
	HTTP_CLIENT_ALLOWED,
};

/* Pointer-free control state is verified independently of predicate caches. */
struct route_state {
	/* Packed routing decision; negative until a terminal action succeeds. */
	__s64 result;
	__u32 position;
	/* Nested forward blocks need one ambiguity boundary, not a scope stack. */
	__u32 uncertain_until;
	__u8 clause_result;
	__u8 must;
	__u8 capture_flags;
	bool rule_uncertain;
	bool flow_bump;
	bool skipped_noalive;
};

struct route_ctx {
	const struct route_params *params;
	const struct routing_profile *profile;
	const struct domain_routing *domain;
	struct route_state *state;
	bool domain_loaded;
	__u8 http_client_admission;
};

#include "http_clients.h"

/* Keep lookup keys in a separate frame so the inline rule walker leaves
 * enough stack for HTTP admission and the packet classifier.
 */
static __noinline int route_match_lpm(const struct route_params *params,
				      const struct match_set *match)
{
	struct lpm_key key = { .trie_key.prefixlen = IPV6_BYTE_LENGTH * 8 };

	switch (match->type) {
	case MatchType_Mac:
		__builtin_memcpy((__u8 *)key.data + IPV6_BYTE_LENGTH - ETH_ALEN,
				 params->mac, ETH_ALEN);
		break;
	case MatchType_IpSet:
		__builtin_memcpy(key.data, params->daddr, IPV6_BYTE_LENGTH);
		break;
	case MatchType_SourceIpSet:
		__builtin_memcpy(key.data, params->saddr, IPV6_BYTE_LENGTH);
		break;
	default:
		return -EINVAL;
	}
	struct map_lpm_type *lpm = bpf_map_lookup_elem(&lpm_array_map, &match->index);

	if (unlikely(!lpm))
		return -EFAULT;
	return bpf_map_lookup_elem(lpm, &key) ? MATCH_HIT : MATCH_MISS;
}

/* OR accumulates MISS < MAYBE < HIT. A MAYBE means only some of the names
 * mapped to this destination match, so the exact domain is needed.
 */
static __always_inline int route_predicate(struct route_ctx *ctx,
					   const struct match_set *match_set)
{
	const struct domain_routing *domain;

	switch (match_set->type) {
	case MatchType_HTTPClient:
		if (ctx->http_client_admission == HTTP_CLIENT_UNCHECKED)
			ctx->http_client_admission = http_client_allowed(ctx->params) ?
				HTTP_CLIENT_ALLOWED : HTTP_CLIENT_DENIED;
		return ctx->http_client_admission == HTTP_CLIENT_ALLOWED ?
			MATCH_HIT : MATCH_MISS;
	case MatchType_Mac:
	case MatchType_IpSet:
	case MatchType_SourceIpSet:
		return route_match_lpm(ctx->params, match_set);
	case MatchType_Port:
		if (match_set->port_range.port_start <= bpf_ntohs(ctx->params->dport) &&
		    bpf_ntohs(ctx->params->dport) <= match_set->port_range.port_end) {
			return MATCH_HIT;
		}
		break;
	case MatchType_SourcePort:
		if (match_set->port_range.port_start <= bpf_ntohs(ctx->params->sport) &&
		    bpf_ntohs(ctx->params->sport) <= match_set->port_range.port_end) {
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
		if (ctx->params->has_pname && equal16(match_set->pname, ctx->params->pname))
			return MATCH_HIT;
		break;
	case MatchType_IfIndex:
		if (match_set->ifindex &&
		    (ctx->params->ifindex == match_set->ifindex ||
		     ctx->params->physinif == match_set->ifindex))
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

static __always_inline bool route_outbound_alive(const struct route_params *params,
						 __u8 outbound)
{
	struct outbound_connectivity_query query = {
		.outbound = outbound,
		.ipversion = (params->ipversion_type & IpVersionType_4) ? 4 : 6,
		.l4proto = (params->l4proto_type & L4ProtoType_TCP) ? IPPROTO_TCP : IPPROTO_UDP,
	};
	__u32 *connectivity = bpf_map_lookup_elem(&outbound_connectivity_map, &query);

	return connectivity && *connectivity == OUTBOUND_CONNECTIVITY_ALIVE;
}

/* Capture flags and connectivity evidence are appended when route() finishes. */
static __always_inline __s64 route_result_encode(__u8 outbound, __u32 mark, bool must)
{
	return (__s64)outbound | ((__s64)mark << 8) | ((__s64)must << 40);
}

/* Apply a matched terminal. Keep this global so actions are verified once,
 * independently of predicate branches and loop-carried condition state.
 */
__noinline enum route_step_result route_apply(struct route_state *state,
					      const struct match_set *match,
					      const struct route_params *params)
{
	if (!state || !match || !params)
		return ROUTE_STOP;

	/* Controls accumulate until FlowEnd. Ambiguous capture/bump rules are
	 * candidates; ambiguous must cannot override a later definite must.
	 */
	switch (match->action) {
	case MatchAction_Must:
		if (!state->rule_uncertain)
			state->must = MATCH_HIT;
		else if (state->must == MATCH_MISS)
			state->must = MATCH_MAYBE;
		return ROUTE_CONTINUE;
	case MatchAction_Bump:
		state->flow_bump = true;
		return ROUTE_CONTINUE;
	case MatchAction_Capture:
		state->capture_flags |= MATCH_CAPTURE_FLAGS(match);
		/* Destination rules run before flow controls and routing. Their exact
		 * target is selected in userspace; never commit a route for the old IP.
		 */
		if (state->capture_flags & (CAPTURE_DESTINATION | CAPTURE_HTTP_REQUEST))
			goto to_userspace;
		return ROUTE_CONTINUE;
	case MatchAction_FlowEnd:
		if (state->flow_bump || state->must == MATCH_MAYBE)
			goto to_userspace;
		return ROUTE_CONTINUE;
	case MatchAction_Route:
		break;
	default:
		return ROUTE_STOP;
	}

	if ((match->flags & MATCH_FLAG_SKIP_NOALIVE) &&
	    !route_outbound_alive(params, match->outbound)) {
		state->skipped_noalive = true;
		return ROUTE_CONTINUE;
	}

	/* An ambiguous terminal cannot commit its mark or must bit. */
	if (state->rule_uncertain)
		goto to_userspace;
	bool must = state->must == MATCH_HIT || (match->flags & MATCH_FLAG_MUST);

	if (!must && params->isdns && !(match->flags & MATCH_FLAG_BYPASS))
		state->capture_flags |= CAPTURE_DNS;
	state->result = route_result_encode(match->outbound, match->mark, must);
	return ROUTE_STOP;

to_userspace:
	state->result = route_result_encode(OUTBOUND_CONTROL_PLANE_ROUTING, 0,
					    state->must == MATCH_HIT);
	return ROUTE_STOP;
}

/* Keep conditions and forward jumps inline. Only a matched terminal needs
 * the independently verified action subprogram.
 */
static __always_inline enum route_step_result route_step(struct route_ctx *ctx)
{
	const struct routing_profile *profile = ctx->profile;
	struct route_state *state = ctx->state;
	__u32 position = state->position;
	__u32 length = profile->length;

	if (unlikely(position >= MAX_MATCH_SET_LEN || position >= length))
		return ROUTE_STOP;
	__u32 k = profile->steps[position];

	if (unlikely(k >= MAX_MATCH_SET_LEN))
		return ROUTE_STOP;
	const struct match_set *match = bpf_map_lookup_elem(&routing_map, &k);

	if (unlikely(!match))
		return ROUTE_STOP;

	int predicate_result = MATCH_HIT;

	if (state->clause_result != MATCH_HIT) {
		predicate_result = route_predicate(ctx, match);
		if (predicate_result < 0)
			return ROUTE_STOP;
	}
	__u32 distance = 1;
	__u8 clause = state->clause_result;

	if (predicate_result > clause)
		clause = predicate_result;

	if (match->action == MatchAction_Or) {
		state->clause_result = clause;
		if (clause == MATCH_HIT)
			distance = match->mark;
		goto advance;
	}

	/* Only the clause tail applies NOT. MAYBE is unchanged by negation. */
	state->clause_result = MATCH_MISS;
	if (match->flags & MATCH_FLAG_NOT)
		clause = MATCH_HIT - clause;
	if (clause == MATCH_MISS) {
		if (match->action == MatchAction_And ||
		    match->action == MatchAction_ConditionalJump)
			distance = match->mark;
		goto finish_rule;
	}
	state->rule_uncertain |= clause == MATCH_MAYBE;
	if (match->action == MatchAction_And)
		goto advance;
	if (match->action == MatchAction_ConditionalJump) {
		if (unlikely(!match->mark || match->mark > length - position))
			return ROUTE_STOP;
		/* Keep the outermost ambiguous end. Nested scopes cannot outlive
		 * their parent; a sibling starts at or beyond the previous end.
		 */
		if (state->rule_uncertain && position + match->mark > state->uncertain_until)
			state->uncertain_until = position + match->mark;
		goto finish_rule;
	}
	state->rule_uncertain |= position < state->uncertain_until;

	if (route_apply(state, match, ctx->params) == ROUTE_STOP)
		return ROUTE_STOP;
finish_rule:
	state->rule_uncertain = false;
advance:
	/* The compiler checks rule structure; the kernel checks jump bounds. */
	if (unlikely(!distance || distance > length - position))
		return ROUTE_STOP;
	state->position = position + distance;
	return ROUTE_CONTINUE;
}

/* Keep this global: static subprograms inherit each caller's verifier states,
 * multiplying the routing iterator's paths by the packet classifier's paths.
 */
__noinline __s64 route(struct route_params *params, struct route_state *state)
{
	struct route_ctx ctx = {};

	if (!params || !state)
		return -EFAULT;
	__u32 *selected_id =
		bpf_map_lookup_elem(&routing_interface_map, &params->ifindex);

	params->profile_id = selected_id ? *selected_id : default_routing_profile;
	const struct routing_profile *profile =
		bpf_map_lookup_elem(&routing_profile_map, &params->profile_id);

	if (unlikely(!profile || !profile->length ||
		     profile->length > MAX_MATCH_SET_LEN))
		return -EFAULT;
	ctx.profile = profile;
	ctx.params = params;
	__builtin_memset(state, 0, sizeof(*state));
	state->result = -EFAULT;
	ctx.state = state;

	bpf_repeat(MAX_MATCH_SET_LEN) {
		if (route_step(&ctx) == ROUTE_STOP)
			break;
	}
	if (state->result >= 0) {
		state->result |= (__s64)state->capture_flags << ROUTE_RESULT_CAPTURE_SHIFT;
		if (state->skipped_noalive)
			state->result |= ROUTE_RESULT_SKIPPED_NOALIVE;
		return state->result;
	}
	bpf_printk(
		"No match_set hits. Did coder forget to sync common/consts/ebpf.go with enum MatchType?");
	return -EPERM;
}

#endif /* DAE_ROUTING_H */
