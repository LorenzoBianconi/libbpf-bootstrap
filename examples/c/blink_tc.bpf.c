// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK	0
#define TC_ACT_SHOT	2

#define ETH_P_8021Q	0x8100
#define ETH_P_8021AD	0x88a8
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86dd

#define MAX_LEN		450

#define s6_addr32		in6_u.u6_addr32
#define ipv6_addr_equal(a, b)	((a).s6_addr32[0] == (b).s6_addr32[0] &&	\
				 (a).s6_addr32[1] == (b).s6_addr32[1] &&	\
				 (a).s6_addr32[2] == (b).s6_addr32[2] &&	\
				 (a).s6_addr32[3] == (b).s6_addr32[3])

const volatile struct in6_addr lr_addr;
const volatile struct in6_addr or_addr;
bool drop = true;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} drops SEC(".maps");

SEC("tc")
int blink_tc_ingress(struct __sk_buff *skb)
{
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *eh = data;
	__u64 nh_off = sizeof(*eh);
	struct ipv6hdr *ih6;
	__u32 *val, key = 0;

	if (!drop)
		return TC_ACT_OK;

	if (skb->protocol != bpf_htons(ETH_P_IP) &&
	    skb->protocol != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	if (eh + 1 > (struct ethhdr *)data_end)
		return TC_ACT_SHOT;

	/* Handle VLAN tagged packet */
	if (eh->h_proto == bpf_htons(ETH_P_8021Q) ||
	    eh->h_proto == bpf_htons(ETH_P_8021AD)) {
		nh_off += sizeof(struct vlan_hdr);

		if (data + nh_off > data_end)
			return TC_ACT_SHOT;
	}

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr *ih = (struct iphdr *)(data + nh_off);

		if (ih + 1 > (struct iphdr *)data_end)
			return TC_ACT_SHOT;

		if (ih->saddr != lr_addr.s6_addr32[3] &&
		    ih->saddr != or_addr.s6_addr32[3])
			return TC_ACT_OK;

		goto out;
	}

	ih6 = (struct ipv6hdr *)(data + nh_off);
	if (ih6 + 1 > (struct ipv6hdr *)data_end)
		return TC_ACT_SHOT;

	if (!ipv6_addr_equal(ih6->saddr, lr_addr) &&
	    !ipv6_addr_equal(ih6->saddr, or_addr))
		return TC_ACT_OK;
out:
	if (skb->len < MAX_LEN)
		return TC_ACT_OK;

	val = bpf_map_lookup_elem(&drops, &key);
	if (val)
		__sync_add_and_fetch(val, 1);
	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
