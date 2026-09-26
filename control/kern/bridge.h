/* SPDX-License-Identifier: AGPL-3.0-only */

#ifndef DAE_BRIDGE_H
#define DAE_BRIDGE_H

/* These optional types are absent from some of our minimal vmlinux headers.
 * Use CO-RE flavors, including the enum value, rather than kernel offsets.
 */
enum skb_ext_id___dae_bridge {
	SKB_EXT_BRIDGE_NF___dae_bridge,
};

struct skb_ext___dae_bridge {
	__u8 offset[1];
} __attribute__((preserve_access_index));

struct sk_buff___dae_bridge {
	__u8 active_extensions;
	struct skb_ext___dae_bridge *extensions;
} __attribute__((preserve_access_index));

struct nf_bridge_info___dae_bridge {
	int physinif;
};

extern void *bpf_cast_to_kern_ctx(void *ctx) __ksym;

/* br_netfilter saves the bridge member before skb_iif becomes the bridge.
 * Absence (including kernels built without bridge netfilter) is not a match.
 * Keep this out of the classifier's nearly full BPF stack frame.
 */
static __noinline __u32 skb_bridge_physinif(struct __sk_buff *ctx)
{
	struct sk_buff___dae_bridge *skb;
	struct skb_ext___dae_bridge *ext;
	struct nf_bridge_info___dae_bridge *bridge;
	__u8 offset;
	int physinif = 0;

	if (!bpf_core_enum_value_exists(enum skb_ext_id___dae_bridge,
					SKB_EXT_BRIDGE_NF___dae_bridge) ||
	    !bpf_core_field_exists(struct sk_buff___dae_bridge, active_extensions) ||
	    !bpf_core_field_exists(struct sk_buff___dae_bridge, extensions) ||
	    !bpf_core_field_exists(struct skb_ext___dae_bridge, offset) ||
	    !bpf_core_field_exists(struct nf_bridge_info___dae_bridge, physinif))
		return 0;
	__u32 id = bpf_core_enum_value(enum skb_ext_id___dae_bridge,
				      SKB_EXT_BRIDGE_NF___dae_bridge);

	if (id >= 8)
		return 0;
	skb = bpf_cast_to_kern_ctx(ctx);
	/* Typed pointers allow verifier-checked CO-RE loads without probe helpers. */
	if (!(skb->active_extensions & (1U << id)))
		return 0;
	ext = skb->extensions;
	if (!ext)
		return 0;
	offset = ext->offset[id];
	if (!offset)
		return 0;
	/* skb_ext offsets are in eight-byte units. The variable-offset payload
	 * needs a probe read: unlike the typed fields above, it is not a BTF pointer.
	 */
	bridge = (void *)ext + ((__u32)offset << 3);
	if (bpf_core_read(&physinif, sizeof(physinif), &bridge->physinif))
		return 0;
	return physinif > 0 ? physinif : 0;
}

#endif /* DAE_BRIDGE_H */
