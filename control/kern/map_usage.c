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

struct map_usage usage_sample;

SEC("iter/bpf_map")
int read_map_usage(struct bpf_iter__bpf_map *ctx)
{
	struct bpf_map *map = ctx->map;

	if (!map)
		return 0;
	for (int i = 0; i < 32; i++) {
		if (requested_map_ids[i] != map->id)
			continue;
		usage_sample.id = map->id;
		usage_sample.limit = map->max_entries;
		usage_sample.used = bpf_map_sum_elem_count(map);
		bpf_seq_write(ctx->meta->seq, &usage_sample, sizeof(usage_sample));
		break;
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
