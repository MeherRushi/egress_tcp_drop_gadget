// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation


#include <vmlinux.h>

/* I am directly including the 
value of the constants instead of 
the linux/if_ether.h header file
because of redeclration conflicts with
vmlinux.h */

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/


/*  Although the below mentioned are the 
return values mentioned in the linux/pkt_cls.h header file : 

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		1
#define TC_ACT_PIPE		3


It turns out that the ingress and egress hookpoints programs 
require the return value to be either 0 (drop) or 1 (pass)

reference : https://stackoverflow.com/questions/77191387/invalid-argument-error-from-ebpf-program-when-when-loading-program-using-bpftool 

So I redefine the macros
 */

#define TC_OK 1
#define TC_SHOT 0

#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/buffer.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

struct event {
	gadget_timestamp timestamp_raw;
	__u16 family;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	struct gadget_l4endpoint_t filter_ipv4;

    __u64 drop_cnt;

    gadget_mntns_id mntns_id;
};


// This is an egress program, so we target the 
// destination address and drop based on that
struct{
	__uint(type,BPF_MAP_TYPE_HASH);
	__uint(max_entries,MAX_ENTRIES);
	__type(key,struct gadget_l4endpoint_t);	// The key is just going to be destination addr
	__type(value,u64);

} trace_drop_count SEC(".maps");

// const volatile struct iface{
// 	char interface[10];
// };

/* 
Let's take the ip to be in the 
format of -a 127 -b 0 -c 0 -d 1 -p 443
which translates to 127.0.0.1:443 */

const volatile __u8 a = 0;
const volatile __u8 b = 0;
const volatile __u8 c = 0;
const volatile __u8 d = 0;
const volatile __u16 p = 0;

GADGET_PARAM(a);
GADGET_PARAM(b);
GADGET_PARAM(c);
GADGET_PARAM(d);
GADGET_PARAM(p);


GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(tracedropcnt, events, event);


SEC("classifier/egress/drop")
int egress_tcp_drop(struct __sk_buff *skb){
		
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	struct gadget_l4endpoint_t filter_ip;

	__u16 family;
	__u64 mntns_id;

	struct event *event;

	if(!skb) 
		return TC_SHOT;

	mntns_id = gadget_get_mntns_id();

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
	struct iphdr *ip4h ;
	struct ipv6hdr *ip6h ;
	__u64 *drop_cnt_ptr ;

    /* 
	 * Check if the ethernet headers are invalid
	 * if so ignore the packets, else do the further
	 * processing
	 */
    if ((void *)(eth + 1)> data_end)
    {
        // bpf_debug("Eth headers incomplete");
		return TC_OK; // Letting them pass through the without further processing
    }

 	family = bpf_ntohs(eth->h_proto);

	/* 
	 * Ignore the packets which are not IPv4 or IPv6 
	 * and let them pass through in the default way
	 */

	if (gadget_should_discard_mntns_id(mntns_id))
		return TC_OK;   // Letting them pass through the without further processing


    // IPv4 Processing
	if (family == ETH_P_IP) {
		ip4h = (struct iphdr *)(eth + 1);

		/* Check if the IPv4 headers are invalid */
		if ((void *)(ip4h + 1) > data_end) {
			return TC_OK;
		}

		// Check if packets follow TCP protocol
		if (ip4h->protocol == IPPROTO_TCP) {
			// Read source and destination IP addresses
			src.addr_raw.v4 = bpf_ntohl(ip4h->saddr);
			dst.addr_raw.v4 = bpf_ntohl(ip4h->daddr);
			src.version = dst.version = 4;
			struct tcphdr *tcph = (struct tcphdr *)((__u8 *)ip4h + (ip4h->ihl * 4));
			if ((void *)(tcph + 1) > data_end) return TC_OK;  // Packet is too short, ignore
			src.proto = dst.proto = IPPROTO_TCP;
			src.port = bpf_ntohs(tcph->source);
			dst.port = bpf_ntohs(tcph->dest);
		}
		else{
			return TC_OK;
		}
	}
	// IPv6 Processing
	else if (family == ETH_P_IPV6) {
		ip6h = (struct ipv6hdr *)(eth + 1);

		/* Check if the IPv6 headers are invalid */
		if ((void *)(ip6h + 1)  > data_end) {
			return TC_OK;
		}

		// Check if packets follow TCP protocol

		if (ip6h->nexthdr != IPPROTO_TCP) {
			bpf_probe_read_kernel(src.addr_raw.v6, sizeof(src.addr_raw.v6), ip6h->saddr.in6_u.u6_addr8);
			bpf_probe_read_kernel(dst.addr_raw.v6, sizeof(dst.addr_raw.v6), ip6h->daddr.in6_u.u6_addr8);
			src.version = dst.version = 6;

			struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)  return TC_OK;  // Packet is too short, ignore
			src.proto = dst.proto = IPPROTO_TCP;
			src.port = bpf_ntohs(tcph->source);
			dst.port = bpf_ntohs(tcph->dest);

		}
		else{
			return TC_OK;
		}
	}
	else{
		return TC_OK;	// Letting them pass through the without further processing
	}

	/*  
		We know for a fact that the packets we are tracing
		are TCP packets and the dst.proto would be IPPROTO_TCP,
		else we would have ignored it anyways.

		Secondly, for now we are only focusing on filtering
		by IPv4 address.

		We drop all the packets if the parameters of the 
		filter IP are default values
	 */

	if(a == 0 && b == 0 && c == 0 && d == 0 && p == 0){
		drop_cnt_ptr = bpf_map_lookup_elem(&trace_drop_count,&dst);

		if(!drop_cnt_ptr){
			__u64 drp_cnt= 1 ;
			drop_cnt_ptr = &drp_cnt;
			bpf_map_update_elem(&trace_drop_count,&dst,drop_cnt_ptr,BPF_NOEXIST);
		}else{
			*drop_cnt_ptr = (*drop_cnt_ptr) + 1;
			bpf_map_update_elem(&trace_drop_count,&dst,drop_cnt_ptr,BPF_EXIST);
		}
	}
	else{
		// If the filter IP is not default value
		// then we only drop the filtered destination ip
		filter_ip.addr_raw.v4 = bpf_ntohl((a << 24) | (b << 16) | (c << 8) | d);
		filter_ip.port = p;
		filter_ip.proto = IPPROTO_TCP;
		filter_ip.version = 4;

		if(dst.version == 4 && filter_ip.version == 4) {
			if(dst.addr_raw.v4 == filter_ip.addr_raw.v4 && dst.port == filter_ip.port){
				drop_cnt_ptr = bpf_map_lookup_elem(&trace_drop_count,&dst);

				if(!drop_cnt_ptr){
					__u64 drp_cnt= 1 ;
					drop_cnt_ptr = &drp_cnt;
					bpf_map_update_elem(&trace_drop_count,&dst,drop_cnt_ptr,BPF_NOEXIST);
				}else{
					*drop_cnt_ptr = (*drop_cnt_ptr) + 1;
					bpf_map_update_elem(&trace_drop_count,&dst,drop_cnt_ptr,BPF_EXIST);
				}
			}else{
				//ignore the packet
				return TC_OK;
			}
		}else{
			//ignore the packet
			return TC_OK;
		}
	}


	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	if(family == ETH_P_IP) event->family = 4;
	else if(family == ETH_P_IPV6) event->family = 6;
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->src.addr_raw.v4 = src.addr_raw.v4;
	event->dst.addr_raw.v4 = dst.addr_raw.v4;
	event->src.version = event->dst.version = src.version;
	event->src.port = src.port;
	event->dst.port = dst.port;
	event->src.proto = event->dst.proto = src.proto;
	event->mntns_id = mntns_id;
	event->filter_ipv4 = filter_ip;
	event->drop_cnt = (*drop_cnt_ptr);

	gadget_submit_buf(skb, &events, event, sizeof(*event));

	// Drop the packet after all this
	return TC_SHOT;
}


char __license[] SEC("license") = "GPL";