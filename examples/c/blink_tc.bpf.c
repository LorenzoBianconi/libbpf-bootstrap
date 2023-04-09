// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK	0
#define TC_ACT_SHOT	2

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define MAX_LEN		450

const volatile __be32 lr_addr;
const volatile __be32 or_addr;
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
	struct iphdr *ih = (struct iphdr *)(eh + 1);

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	if (eh + 1 > (struct ethhdr *)data_end)
		return TC_ACT_SHOT;

	ih = (struct iphdr *)(eh + 1);
	if (ih + 1 > (struct iphdr *)data_end)
		return TC_ACT_SHOT;

	if (ih->saddr == lr_addr || ih->saddr == or_addr) {
		if (skb->len < MAX_LEN)
			return TC_ACT_OK;

		if (drop) {
			__u32 *val, key = 0;
		
			val = bpf_map_lookup_elem(&drops, &key);
			if (val)
				__sync_add_and_fetch(val, 1);
			return TC_ACT_SHOT;
		}
	}

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
