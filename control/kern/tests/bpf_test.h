// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

//go:build exclude

#define IP4_HLEN sizeof(struct iphdr)
#define IP6_HLEN sizeof(struct ipv6hdr)
#define TCP_HLEN sizeof(struct tcphdr)
#define UDP_HLEN sizeof(struct udphdr)
#define IPV6_FRAG_HLEN sizeof(struct frag_hdr)
#define IPV6_OPT_HLEN 8
#define IPV6_AH_HLEN 12

#define OUTBOUND_USER_DEFINED_MIN 2

#define IPV4(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

static const __u32 two_key = 2;
static const __u32 three_key = 3;
static const __u32 four_key = 4;

static __always_inline int
set_ipv4_tcp(struct __sk_buff *skb,
	     __u32 saddr, __u32 daddr,
	     __u16 sport, __u16 dport)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	eth->h_dest[0] = 0x0;
	eth->h_dest[1] = 0x1;
	eth->h_dest[2] = 0x2;
	eth->h_dest[3] = 0x3;
	eth->h_dest[4] = 0x4;
	eth->h_dest[5] = 0x5;
	eth->h_source[0] = 0x6;
	eth->h_source[1] = 0x7;
	eth->h_source[2] = 0x8;
	eth->h_source[3] = 0x9;
	eth->h_source[4] = 0xa;
	eth->h_source[5] = 0xb;
	eth->h_proto = bpf_htons(ETH_P_IP);

	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	ip->ihl = 5;
	ip->version = 4;
	ip->tot_len = bpf_htons(IP4_HLEN + TCP_HLEN);
	ip->protocol = IPPROTO_TCP;
	ip->saddr = bpf_htonl(saddr);
	ip->daddr = bpf_htonl(daddr);
	ip->tos = 4 << 2;

	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	tcp->source = bpf_htons(sport);
	tcp->dest = bpf_htons(dport);
	tcp->doff = 5;
	tcp->syn = 1;

	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_tcp_fragment(struct __sk_buff *skb,
			      __u32 saddr, __u32 daddr,
			      __u16 sport, __u16 dport, __u16 frag_off)
{
	int ret = set_ipv4_tcp(skb, saddr, daddr, sport, dport);
	if (ret)
		return ret;

	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN + 4, 0);
	__be16 total_len = bpf_htons(IP4_HLEN + TCP_HLEN + 4);
	__be16 value = bpf_htons(frag_off);
	return bpf_skb_store_bytes(skb,
		ETH_HLEN + offsetof(struct iphdr, tot_len),
		&total_len, sizeof(total_len), 0) || bpf_skb_store_bytes(skb,
		ETH_HLEN + offsetof(struct iphdr, frag_off),
		&value, sizeof(value), 0);
}

static __always_inline int
set_ipv4_udp_fragment(struct __sk_buff *skb,
			      __u32 saddr, __u32 daddr,
			      __u16 sport, __u16 dport, __u16 frag_off)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + UDP_HLEN + 8, 0);

	struct ethhdr eth = {
		.h_proto = bpf_htons(ETH_P_IP),
	};
	struct iphdr ip = {
		.ihl = 5,
		.version = 4,
		.tot_len = bpf_htons(IP4_HLEN + UDP_HLEN + 8),
		.frag_off = bpf_htons(frag_off),
		.protocol = IPPROTO_UDP,
		.saddr = bpf_htonl(saddr),
		.daddr = bpf_htonl(daddr),
	};
	struct udphdr udp = {
		.source = bpf_htons(sport),
		.dest = bpf_htons(dport),
		/* The complete datagram extends into a later fragment. */
		.len = bpf_htons(UDP_HLEN + 16),
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP4_HLEN, &udp, sizeof(udp), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_short_first_fragment(struct __sk_buff *skb,
			      __u32 saddr, __u32 daddr, __u8 protocol)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN + TCP_HLEN, 0);

	struct ethhdr eth = { .h_proto = bpf_htons(ETH_P_IP) };
	struct iphdr ip = {
		.ihl = 5,
		.version = 4,
		.tot_len = bpf_htons(IP4_HLEN),
		.frag_off = bpf_htons(0x2000),
		.protocol = protocol,
		.saddr = bpf_htonl(saddr),
		.daddr = bpf_htonl(daddr),
	};
	struct tcphdr padding = {
		.source = bpf_htons(19241),
		.dest = bpf_htons(87),
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP4_HLEN, &padding,
				sizeof(padding), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_tcp_fragment_doff(struct __sk_buff *skb, __u8 doff)
{
	int ret = set_ipv4_tcp_fragment(skb, IPV4(192,168,0,24),
		IPV4(1,1,1,24), 19324, 80, 0x2000);
	if (ret)
		return ret;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct tcphdr *tcp = data + ETH_HLEN + IP4_HLEN;

	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_SHOT;
	tcp->doff = doff;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_udp_fragment_len(struct __sk_buff *skb, __u16 udp_len)
{
	int ret = set_ipv4_udp_fragment(skb, IPV4(192,168,0,25),
		IPV4(1,1,1,25), 19325, 80, 0x2000);
	if (ret)
		return ret;

	__be16 value = bpf_htons(udp_len);
	return bpf_skb_store_bytes(skb,
		ETH_HLEN + IP4_HLEN + offsetof(struct udphdr, len),
		&value, sizeof(value), 0);
}

static __always_inline int
set_ipv4_nonfirst_fragment_ihl(struct __sk_buff *skb, __u8 ihl)
{
	int ret = set_ipv4_udp_fragment(skb, IPV4(192,168,0,26),
		IPV4(1,1,1,26), 19326, 80, 0x0001);
	if (ret)
		return ret;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + ETH_HLEN;

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT;
	ip->ihl = ihl;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_misaligned_nonfirst_fragment(struct __sk_buff *skb)
{
	int ret = set_ipv4_udp_fragment(skb, IPV4(192,168,0,39),
		IPV4(1,1,1,39), 19339, 80, 0x2001);
	if (ret)
		return ret;

	__be16 total_len = bpf_htons(IP4_HLEN + UDP_HLEN + 7);
	return bpf_skb_store_bytes(skb,
		ETH_HLEN + offsetof(struct iphdr, tot_len),
		&total_len, sizeof(total_len), 0);
}

static __always_inline int
set_ipv6_udp_fragment(struct __sk_buff *skb,
			      __u32 saddr, __u32 daddr,
			      __u16 sport, __u16 dport, __u16 frag_off)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + IPV6_FRAG_HLEN + UDP_HLEN + 8, 0);

	struct ethhdr eth = {
		.h_proto = bpf_htons(ETH_P_IPV6),
	};
	struct ipv6hdr ip = {
		.version = 6,
		.payload_len = bpf_htons(IPV6_FRAG_HLEN + UDP_HLEN + 8),
		.nexthdr = IPPROTO_FRAGMENT,
	};
	union ip6 src = {}, dst = {};
	src.u6_addr32[0] = bpf_htonl(0x20010db8);
	src.u6_addr32[3] = bpf_htonl(saddr);
	dst.u6_addr32[0] = bpf_htonl(0x20010db8);
	dst.u6_addr32[3] = bpf_htonl(daddr);
	__builtin_memcpy(&ip.saddr, &src, sizeof(src));
	__builtin_memcpy(&ip.daddr, &dst, sizeof(dst));

	struct frag_hdr fragment = {
		.nexthdr = IPPROTO_UDP,
		.frag_off = bpf_htons(frag_off),
		.identification = bpf_htonl(1),
	};
	struct udphdr udp = {
		.source = bpf_htons(sport),
		.dest = bpf_htons(dport),
		/* The complete datagram extends into a later fragment. */
		.len = bpf_htons(UDP_HLEN + 16),
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN, &fragment, sizeof(fragment), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN + IPV6_FRAG_HLEN, &udp, sizeof(udp), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_tcp_fragment(struct __sk_buff *skb,
			      __u32 saddr, __u32 daddr,
			      __u16 sport, __u16 dport)
{
	const __u16 fragmentable_len = TCP_HLEN + 4;
	const __u16 payload_len = IPV6_FRAG_HLEN + fragmentable_len;
	bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + payload_len, 0);

	struct ethhdr eth = { .h_proto = bpf_htons(ETH_P_IPV6) };
	struct ipv6hdr ip = {
		.version = 6,
		.payload_len = bpf_htons(payload_len),
		.nexthdr = IPPROTO_FRAGMENT,
	};
	union ip6 src = {}, dst = {};
	src.u6_addr32[0] = bpf_htonl(0x20010db8);
	src.u6_addr32[3] = bpf_htonl(saddr);
	dst.u6_addr32[0] = bpf_htonl(0x20010db8);
	dst.u6_addr32[3] = bpf_htonl(daddr);
	__builtin_memcpy(&ip.saddr, &src, sizeof(src));
	__builtin_memcpy(&ip.daddr, &dst, sizeof(dst));
	struct frag_hdr fragment = {
		.nexthdr = IPPROTO_TCP,
		.frag_off = bpf_htons(0x0001),
		.identification = bpf_htonl(1),
	};
	struct tcphdr tcp = {
		.source = bpf_htons(sport),
		.dest = bpf_htons(dport),
		.doff = 5,
		.syn = 1,
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN, &fragment,
				sizeof(fragment), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN + IPV6_FRAG_HLEN,
				&tcp, sizeof(tcp), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_repeated_atomic_fragments(struct __sk_buff *skb)
{
	const __u16 payload_len = 2 * IPV6_FRAG_HLEN + UDP_HLEN;
	bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + payload_len, 0);

	struct ethhdr eth = { .h_proto = bpf_htons(ETH_P_IPV6) };
	struct ipv6hdr ip = {
		.version = 6,
		.payload_len = bpf_htons(payload_len),
		.nexthdr = IPPROTO_FRAGMENT,
	};
	struct frag_hdr first = {
		.nexthdr = IPPROTO_FRAGMENT,
		.identification = bpf_htonl(1),
	};
	struct frag_hdr second = {
		.nexthdr = IPPROTO_UDP,
		.identification = bpf_htonl(2),
	};
	struct udphdr udp = {
		.source = bpf_htons(19323),
		.dest = bpf_htons(80),
		.len = bpf_htons(UDP_HLEN),
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN, &first,
				sizeof(first), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN + IPV6_FRAG_HLEN,
				&second, sizeof(second), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN + 2 * IPV6_FRAG_HLEN,
				&udp, sizeof(udp), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_truncated_fragment(struct __sk_buff *skb)
{
	const __u16 payload_len = 4;
	bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + payload_len, 0);

	struct ethhdr eth = { .h_proto = bpf_htons(ETH_P_IPV6) };
	struct ipv6hdr ip = {
		.version = 6,
		.payload_len = bpf_htons(payload_len),
		.nexthdr = IPPROTO_FRAGMENT,
	};
	__u8 fragment_prefix[4] = { IPPROTO_UDP };

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN, fragment_prefix,
				sizeof(fragment_prefix), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_misaligned_first_fragment(struct __sk_buff *skb)
{
	int ret = set_ipv6_udp_fragment(skb, 27, 28, 19327, 80, 0x0001);
	if (ret)
		return ret;

	__be16 payload_len = bpf_htons(IPV6_FRAG_HLEN + UDP_HLEN + 7);
	return bpf_skb_store_bytes(skb,
		ETH_HLEN + offsetof(struct ipv6hdr, payload_len),
		&payload_len, sizeof(payload_len), 0);
}

static __always_inline int
set_ipv6_invalid_version_nonfirst_fragment(struct __sk_buff *skb)
{
	int ret = set_ipv6_udp_fragment(skb, 40, 41, 19340, 80, 0x0008);
	if (ret)
		return ret;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip = data + ETH_HLEN;

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT;
	ip->version = 4;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_ah_udp_fragment(struct __sk_buff *skb,
			 __u32 saddr, __u32 daddr,
			 __u16 sport, __u16 dport)
{
	const __u16 payload_len = IPV6_AH_HLEN + IPV6_FRAG_HLEN + UDP_HLEN + 8;
	bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + payload_len, 0);

	struct ethhdr eth = { .h_proto = bpf_htons(ETH_P_IPV6) };
	struct ipv6hdr ip = {
		.version = 6,
		.payload_len = bpf_htons(payload_len),
		.nexthdr = IPPROTO_AH,
	};
	union ip6 src = {}, dst = {};
	src.u6_addr32[0] = bpf_htonl(0x20010db8);
	src.u6_addr32[3] = bpf_htonl(saddr);
	dst.u6_addr32[0] = bpf_htonl(0x20010db8);
	dst.u6_addr32[3] = bpf_htonl(daddr);
	__builtin_memcpy(&ip.saddr, &src, sizeof(src));
	__builtin_memcpy(&ip.daddr, &dst, sizeof(dst));
	__u8 ah[IPV6_AH_HLEN] = {
		[0] = IPPROTO_FRAGMENT,
		[1] = 1,
	};
	struct frag_hdr fragment = {
		.nexthdr = IPPROTO_UDP,
		.frag_off = bpf_htons(0x0001),
		.identification = bpf_htonl(1),
	};
	struct udphdr udp = {
		.source = bpf_htons(sport),
		.dest = bpf_htons(dport),
		/* The complete datagram extends into a later fragment. */
		.len = bpf_htons(UDP_HLEN + 16),
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN, ah, sizeof(ah), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN + IPV6_AH_HLEN,
				&fragment, sizeof(fragment), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN + IPV6_AH_HLEN +
				IPV6_FRAG_HLEN, &udp, sizeof(udp), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_short_ah_fragment(struct __sk_buff *skb)
{
	int ret = set_ipv6_ah_udp_fragment(skb, 42, 43, 19342, 80);
	if (ret)
		return ret;

	__u8 invalid_payload_len = 0;
	return bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN + 1,
		&invalid_payload_len, sizeof(invalid_payload_len), 0);
}

static __always_inline int
set_utp_extension_packet(struct __sk_buff *skb, __u16 declared_payload_len,
			 __u8 extension_len)
{
	const __u16 actual_payload_len = 162;
	const __u32 udp_offset = ETH_HLEN + IP4_HLEN;
	const __u32 payload_offset = udp_offset + UDP_HLEN;
	bpf_skb_change_tail(skb, payload_offset + actual_payload_len, 0);

	struct ethhdr eth = { .h_proto = bpf_htons(ETH_P_IP) };
	struct iphdr ip = {
		.ihl = 5,
		.version = 4,
		.tot_len = bpf_htons(IP4_HLEN + UDP_HLEN + declared_payload_len),
		.protocol = IPPROTO_UDP,
		.saddr = bpf_htonl(IPV4(192,168,0,44)),
		.daddr = bpf_htonl(IPV4(1,1,1,44)),
	};
	struct udphdr udp = {
		.source = bpf_htons(19344),
		.dest = bpf_htons(80),
		.len = bpf_htons(UDP_HLEN + declared_payload_len),
	};
	__u8 utp_header[2] = { 0x11, 1 };
	__u8 extension_header[2] = { 0, extension_len };

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, udp_offset, &udp, sizeof(udp), 0) ||
	    bpf_skb_store_bytes(skb, payload_offset, utp_header,
				sizeof(utp_header), 0) ||
	    bpf_skb_store_bytes(skb, payload_offset + 160, extension_header,
				sizeof(extension_header), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_ah_udp(struct __sk_buff *skb, __u32 saddr, __u32 daddr,
		__u16 sport, __u16 dport)
{
	const __u16 payload_len = IPV6_AH_HLEN + UDP_HLEN + 8;
	bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + payload_len, 0);

	struct ethhdr eth = { .h_proto = bpf_htons(ETH_P_IPV6) };
	struct ipv6hdr ip = {
		.version = 6,
		.payload_len = bpf_htons(payload_len),
		.nexthdr = IPPROTO_AH,
	};
	union ip6 src = {}, dst = {};
	src.u6_addr32[0] = bpf_htonl(0x20010db8);
	src.u6_addr32[3] = bpf_htonl(saddr);
	dst.u6_addr32[0] = bpf_htonl(0x20010db8);
	dst.u6_addr32[3] = bpf_htonl(daddr);
	__builtin_memcpy(&ip.saddr, &src, sizeof(src));
	__builtin_memcpy(&ip.daddr, &dst, sizeof(dst));
	__u8 ah[IPV6_AH_HLEN] = {
		[0] = IPPROTO_UDP,
		[1] = 1,
	};
	struct udphdr udp = {
		.source = bpf_htons(sport),
		.dest = bpf_htons(dport),
		.len = bpf_htons(UDP_HLEN + 8),
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN, ah, sizeof(ah), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN + IPV6_AH_HLEN,
				&udp, sizeof(udp), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_extensions(struct __sk_buff *skb, __u32 extension_count)
{
	const __u32 payload_len = extension_count * IPV6_OPT_HLEN + UDP_HLEN;
	bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + payload_len, 0);

	struct ethhdr eth = { .h_proto = bpf_htons(ETH_P_IPV6) };
	struct ipv6hdr ip = {
		.version = 6,
		.payload_len = bpf_htons(payload_len),
		.nexthdr = IPPROTO_DSTOPTS,
	};
	__u8 option[IPV6_OPT_HLEN] = { IPPROTO_DSTOPTS, 0 };
	struct udphdr udp = {
		.source = bpf_htons(19240),
		.dest = bpf_htons(86),
		.len = bpf_htons(UDP_HLEN),
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0))
		return TC_ACT_SHOT;
	for (__u32 i = 0; i < extension_count; i++) {
		if (i == extension_count - 1)
			option[0] = IPPROTO_UDP;
		if (bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN + i * IPV6_OPT_HLEN,
					option, sizeof(option), 0))
			return TC_ACT_SHOT;
	}
	if (bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN +
				extension_count * IPV6_OPT_HLEN, &udp, sizeof(udp), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv4_nonfirst_fragment(struct __sk_buff *skb,
			   __u32 saddr, __u32 daddr, __u8 protocol)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP4_HLEN, 0);

	struct ethhdr eth = {
		.h_proto = bpf_htons(ETH_P_IP),
	};
	struct iphdr ip = {
		.ihl = 5,
		.version = 4,
		.tot_len = bpf_htons(IP4_HLEN),
		.frag_off = bpf_htons(1),
		.protocol = protocol,
		.saddr = bpf_htonl(saddr),
		.daddr = bpf_htonl(daddr),
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
set_ipv6_nonfirst_fragment(struct __sk_buff *skb,
			   __u32 saddr, __u32 daddr, __u8 protocol)
{
	bpf_skb_change_tail(skb, ETH_HLEN + IP6_HLEN + IPV6_FRAG_HLEN, 0);

	struct ethhdr eth = {
		.h_proto = bpf_htons(ETH_P_IPV6),
	};
	struct ipv6hdr ip = {
		.version = 6,
		.payload_len = bpf_htons(IPV6_FRAG_HLEN),
		.nexthdr = IPPROTO_FRAGMENT,
	};
	union ip6 src = {}, dst = {};
	src.u6_addr32[0] = bpf_htonl(0x20010db8);
	src.u6_addr32[3] = bpf_htonl(saddr);
	dst.u6_addr32[0] = bpf_htonl(0x20010db8);
	dst.u6_addr32[3] = bpf_htonl(daddr);
	__builtin_memcpy(&ip.saddr, &src, sizeof(src));
	__builtin_memcpy(&ip.daddr, &dst, sizeof(dst));

	struct frag_hdr fragment = {
		.nexthdr = protocol,
		.frag_off = bpf_htons(0x0008),
		.identification = bpf_htonl(1),
	};

	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof(ip), 0) ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + IP6_HLEN, &fragment, sizeof(fragment), 0))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
check_status_code(struct __sk_buff *skb, __u32 expected_status_code)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 *status_code = data;

	if ((void *)(status_code + 1) > data_end || *status_code != expected_status_code)
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
check_ipv4_udp_state(struct __sk_buff *skb, __u32 expected_status_code,
		     __u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
		     bool expected_state)
{
	if (check_status_code(skb, expected_status_code))
		return TC_ACT_SHOT;

	struct tuples_key key = {};
	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(saddr);
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(daddr);
	key.sport = bpf_htons(sport);
	key.dport = bpf_htons(dport);
	key.l4proto = IPPROTO_UDP;
	if (!expected_state && bpf_map_lookup_elem(&udp_conn_state_map, &key))
		return TC_ACT_SHOT;

	__builtin_memset(&key, 0, sizeof(key));
	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(daddr);
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(saddr);
	key.sport = bpf_htons(dport);
	key.dport = bpf_htons(sport);
	key.l4proto = IPPROTO_UDP;

	struct udp_conn_state *state = bpf_map_lookup_elem(&udp_conn_state_map, &key);
	if (!!state != expected_state || (state && !state->is_wan_ingress_direction))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
check_ipv6_udp_state(struct __sk_buff *skb, __u32 expected_status_code,
		     __u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
		     bool expected_state)
{
	if (check_status_code(skb, expected_status_code))
		return TC_ACT_SHOT;

	struct tuples_key key = {};
	key.sip.u6_addr32[0] = bpf_htonl(0x20010db8);
	key.sip.u6_addr32[3] = bpf_htonl(saddr);
	key.dip.u6_addr32[0] = bpf_htonl(0x20010db8);
	key.dip.u6_addr32[3] = bpf_htonl(daddr);
	key.sport = bpf_htons(sport);
	key.dport = bpf_htons(dport);
	key.l4proto = IPPROTO_UDP;
	if (!expected_state && bpf_map_lookup_elem(&udp_conn_state_map, &key))
		return TC_ACT_SHOT;

	__builtin_memset(&key, 0, sizeof(key));
	key.sip.u6_addr32[0] = bpf_htonl(0x20010db8);
	key.sip.u6_addr32[3] = bpf_htonl(daddr);
	key.dip.u6_addr32[0] = bpf_htonl(0x20010db8);
	key.dip.u6_addr32[3] = bpf_htonl(saddr);
	key.sport = bpf_htons(dport);
	key.dport = bpf_htons(sport);
	key.l4proto = IPPROTO_UDP;

	struct udp_conn_state *state = bpf_map_lookup_elem(&udp_conn_state_map, &key);
	if (!!state != expected_state || (state && !state->is_wan_ingress_direction))
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int
check_ipv4_udp_outbound_state(struct __sk_buff *skb, __u32 expected_status_code,
			      __u32 saddr, __u32 daddr,
			      __u16 sport, __u16 dport)
{
	if (check_status_code(skb, expected_status_code))
		return TC_ACT_SHOT;

	struct tuples_key key = {};
	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(saddr);
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(daddr);
	key.sport = bpf_htons(sport);
	key.dport = bpf_htons(dport);
	key.l4proto = IPPROTO_UDP;
	struct udp_conn_state *state = bpf_map_lookup_elem(&udp_conn_state_map, &key);
	if (!state || state->is_wan_ingress_direction)
		return TC_ACT_SHOT;
	bpf_map_delete_elem(&udp_conn_state_map, &key);
	return TC_ACT_OK;
}

static __always_inline int
check_ipv6_udp_outbound_state(struct __sk_buff *skb, __u32 expected_status_code,
			      __u32 saddr, __u32 daddr,
			      __u16 sport, __u16 dport)
{
	if (check_status_code(skb, expected_status_code))
		return TC_ACT_SHOT;

	struct tuples_key key = {};
	key.sip.u6_addr32[0] = bpf_htonl(0x20010db8);
	key.sip.u6_addr32[3] = bpf_htonl(saddr);
	key.dip.u6_addr32[0] = bpf_htonl(0x20010db8);
	key.dip.u6_addr32[3] = bpf_htonl(daddr);
	key.sport = bpf_htons(sport);
	key.dport = bpf_htons(dport);
	key.l4proto = IPPROTO_UDP;
	struct udp_conn_state *state = bpf_map_lookup_elem(&udp_conn_state_map, &key);
	if (!state || state->is_wan_ingress_direction)
		return TC_ACT_SHOT;
	bpf_map_delete_elem(&udp_conn_state_map, &key);
	return TC_ACT_OK;
}

static __always_inline void
set_ipv4_udp_ingress_state(__u32 saddr, __u32 daddr,
			   __u16 sport, __u16 dport)
{
	struct tuples_key key = {};
	struct udp_conn_state state = { .is_wan_ingress_direction = true };

	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(saddr);
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(daddr);
	key.sport = bpf_htons(sport);
	key.dport = bpf_htons(dport);
	key.l4proto = IPPROTO_UDP;
	bpf_map_update_elem(&udp_conn_state_map, &key, &state, BPF_ANY);
}

static __always_inline int
check_routing_ipv4_tcp_with_result(struct __sk_buff *skb,
				   __u32 expected_status_code,
				   __u8 expected_outbound,
				   __u8 expected_must,
				   __u32 saddr, __u32 daddr,
				   __u16 sport, __u16 dport)
{
	__u32 *status_code;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*status_code) > data_end) {
		bpf_printk("data + sizeof(*status_code) > data_end\n");
		return TC_ACT_SHOT;
	}

	status_code = data;
	if (*status_code != expected_status_code) {
		bpf_printk("status_code(%d) != %d\n", *status_code, expected_status_code);
		return TC_ACT_SHOT;
	}

	if (expected_status_code == TC_ACT_REDIRECT) {
		if (skb->cb[0] != TPROXY_MARK) {
			bpf_printk("skb->cb[0] != TPROXY_MARK\n");
			return TC_ACT_SHOT;
		}

	}

	struct ethhdr *eth = data + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end) {
		bpf_printk("data + sizeof(*eth) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("eth->h_proto != ETH_P_IP\n");
		return TC_ACT_SHOT;
	}

	struct iphdr *ip = (void *)eth + ETH_HLEN;
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("data + sizeof(*ip) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (ip->protocol != IPPROTO_TCP) {
		bpf_printk("ip->protocol != IPPROTO_TCP\n");
		return TC_ACT_SHOT;
	}
	if (ip->saddr != bpf_htonl(saddr)) {
		bpf_printk("ip->saddr != %pI4\n", &saddr);
		return TC_ACT_SHOT;
	}
	if (ip->daddr != bpf_htonl(daddr)) {
		bpf_printk("ip->daddr != %pI4\n", &daddr);
		return TC_ACT_SHOT;
	}

	struct tcphdr *tcp = (void *)ip + IP4_HLEN;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("data + sizeof(*tcp) > data_end\n");
		return TC_ACT_SHOT;
	}
	if (tcp->source != bpf_htons(sport)) {
		bpf_printk("tcp->source != %d\n", sport);
		return TC_ACT_SHOT;
	}
	if (tcp->dest != bpf_htons(dport)) {
		bpf_printk("tcp->dest != %d\n", dport);
		return TC_ACT_SHOT;
	}

	if (expected_status_code == TC_ACT_REDIRECT) {
		struct tuples tuples = {};
		tuples.five.sip.u6_addr32[2] = bpf_htonl(0xffff);
		tuples.five.sip.u6_addr32[3] = ip->saddr;
		tuples.five.dip.u6_addr32[2] = bpf_htonl(0xffff);
		tuples.five.dip.u6_addr32[3] = ip->daddr;
		tuples.five.sport = tcp->source;
		tuples.five.dport = tcp->dest;
		tuples.five.l4proto = ip->protocol;

		struct routing_result *routing_result;
		routing_result = bpf_map_lookup_elem(&routing_tuples_map, &tuples.five);
		if (!routing_result) {
			bpf_printk("routing_result == NULL\n");
			return TC_ACT_SHOT;
		}

		if (routing_result->outbound != expected_outbound) {
			bpf_printk("routing_result->outbound(%u) != %u\n",
				   routing_result->outbound, expected_outbound);
			return TC_ACT_SHOT;
		}
		if (routing_result->must != expected_must) {
			bpf_printk("routing_result->must(%u) != %u\n",
				   routing_result->must, expected_must);
			return TC_ACT_SHOT;
		}
	}

	return TC_ACT_OK;
}

static __always_inline int
check_routing_ipv4_tcp_with_outbound(struct __sk_buff *skb,
				     __u32 expected_status_code,
				     __u8 expected_outbound,
				     __u32 saddr, __u32 daddr,
				     __u16 sport, __u16 dport)
{
	return check_routing_ipv4_tcp_with_result(
		skb, expected_status_code, expected_outbound, false,
		saddr, daddr, sport, dport);
}

static __always_inline int
check_routing_ipv4_tcp(struct __sk_buff *skb,
			       __u32 expected_status_code,
		       __u32 saddr, __u32 daddr,
		       __u16 sport, __u16 dport)
{
	return check_routing_ipv4_tcp_with_outbound(
		skb, expected_status_code, OUTBOUND_USER_DEFINED_MIN,
		saddr, daddr, sport, dport);
}

static __always_inline int
check_no_ipv4_tcp_routing_result(struct __sk_buff *skb,
				 __u32 expected_status_code,
				 __u32 saddr, __u32 daddr,
				 __u16 sport, __u16 dport)
{
	struct tuples_key key = {};

	key.sip.u6_addr32[2] = bpf_htonl(0xffff);
	key.sip.u6_addr32[3] = bpf_htonl(saddr);
	key.dip.u6_addr32[2] = bpf_htonl(0xffff);
	key.dip.u6_addr32[3] = bpf_htonl(daddr);
	key.sport = bpf_htons(sport);
	key.dport = bpf_htons(dport);
	key.l4proto = IPPROTO_TCP;
	if (bpf_map_lookup_elem(&routing_tuples_map, &key))
		return TC_ACT_SHOT;
	return check_status_code(skb, expected_status_code);
}

static __always_inline void
set_domain_routing_word(__u32 daddr, __u32 word, __u32 bump_bits,
			__u32 routing_bits)
{
	__be32 key[4] = {};
	key[2] = bpf_htonl(0x0000ffff);
	key[3] = bpf_htonl(daddr);

	struct domain_routing value = {};
	value.bump[word] = bump_bits;
	value.routing[word] = routing_bits;
	bpf_map_update_elem(&domain_routing_map, &key, &value, BPF_ANY);
}

static __always_inline void
set_domain_routing(__u32 daddr, __u32 bump_bits, __u32 routing_bits)
{
	set_domain_routing_word(daddr, 0, bump_bits, routing_bits);
}

static __always_inline void
set_outbound_connectivity_state(__u8 outbound, __u32 state)
{
	struct outbound_connectivity_query query = {
		.outbound = outbound,
		.l4proto = IPPROTO_TCP,
		.ipversion = 4,
	};
	bpf_map_update_elem(&outbound_connectivity_map, &query, &state, BPF_ANY);
	query.ipversion = 6;
	bpf_map_update_elem(&outbound_connectivity_map, &query, &state, BPF_ANY);
	query.l4proto = IPPROTO_UDP;
	query.ipversion = 4;
	bpf_map_update_elem(&outbound_connectivity_map, &query, &state, BPF_ANY);
	query.ipversion = 6;
	bpf_map_update_elem(&outbound_connectivity_map, &query, &state, BPF_ANY);
}

static __always_inline void
set_outbound_connectivity(__u8 outbound)
{
	set_outbound_connectivity_state(outbound, OUTBOUND_CONNECTIVITY_ALIVE);
}

static __always_inline void
set_routing_fallback(__u8 outbound, bool must, const void *key)
{
	struct match_set ms = {
		.type = MatchType_Fallback,
		.outbound = outbound,
		.must = must,
	};
	bpf_map_update_elem(&routing_map, key, &ms, BPF_ANY);
	set_outbound_connectivity(outbound);
}

static __always_inline void clear_routing_entry(const void *key)
{
	struct match_set empty = {};
	bpf_map_update_elem(&routing_map, key, &empty, BPF_ANY);
}

static __always_inline void
set_outbound_connectivity_dead_try_sniff(__u8 outbound)
{
	set_outbound_connectivity_state(
		outbound, OUTBOUND_CONNECTIVITY_NOALIVE_TRY_SNIFF);
}
