// SPDX-License-Identifier: AGPL-3.0-only
#include "vmlinux_include.h"
#include "headers/bpf_helpers.h"

/* Only count maps explicitly selected by the owning control plane. */
volatile __u32 requested_map_ids[32];

struct map_usage {
	__u32 id;
	__u32 limit;
	__s64 used;
};

/* Retain the record layout in BTF for bpf2go, without a runtime map. */
struct map_usage map_usage_layout SEC(".discard");

SEC("iter/bpf_map")
int read_map_usage(struct bpf_iter__bpf_map *ctx)
{
	struct bpf_map *map = ctx->map;

	if (!map)
		return 0;
	for (int i = 0; i < 32; i++) {
		if (requested_map_ids[i] != map->id)
			continue;
		struct map_usage usage_sample = {
			.id = map->id,
			.limit = map->max_entries,
			.used = bpf_map_sum_elem_count(map),
		};

		bpf_seq_write(ctx->meta->seq, &usage_sample, sizeof(usage_sample));
		break;
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
