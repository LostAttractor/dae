/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef DAE_HTTP_CLIENTS_H
#define DAE_HTTP_CLIENTS_H

/* An immutable inner trie is replaced as one unit. Every lookup for a packet
 * uses this one snapshot, preserving override and ordered-rule precedence.
 * Kind and data layout are mirrored by control/http_clients.go.
 * Keep lookup temporaries in a separate frame to bound route()'s stack usage.
 */
static __noinline bool http_client_allowed(const struct route_params *params)
{
	__u32 zero = 0;
	struct http_client_map *clients = bpf_map_lookup_elem(&http_clients_map, &zero);

	if (!clients)
		return false;
	struct http_client_key key = { .prefixlen = 160 };
	struct http_client_decision best = { .order = 0xffffffff };
	struct http_client_decision *found;
	bool known_mac = params->mac[0] || params->mac[1] || params->mac[2] ||
			 params->mac[3] || params->mac[4] || params->mac[5];

	if (known_mac) {
		key.kind = 1;
		__builtin_memcpy(key.address, params->mac, ETH_ALEN);
		found = bpf_map_lookup_elem(clients, &key);
		if (found)
			return found->allow != 0;
		key.kind = 2;
		found = bpf_map_lookup_elem(clients, &key);
		if (found)
			best = *found;
	}
	key.kind = (params->ipversion_type & IpVersionType_4) ? 4 : 6;
	__builtin_memcpy(key.address, params->saddr, IPV6_BYTE_LENGTH);
	found = bpf_map_lookup_elem(clients, &key);
	if (found && found->order < best.order)
		best = *found;
	key.kind = 0;
	__builtin_memset(key.address, 0, sizeof(key.address));
	found = bpf_map_lookup_elem(clients, &key);
	if (found && found->order < best.order)
		best = *found;
	return best.allow != 0;
}

#endif /* DAE_HTTP_CLIENTS_H */
