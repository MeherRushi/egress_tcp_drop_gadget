// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation

//polish and make PR	
/* 
To do :

- Change the IP parameter
- Add filter by pid and 
- then use kubeIPresolver to filter by name etc
- add IPv6 support
- decouple the port and ip filter
- Extend for UDP and TCP 
 */


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
#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/buffer.h>

#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>


/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define TASK_COMM_LEN 16

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	struct gadget_l4endpoint_t filter_ipv4;
    __u64 drop_cnt;

	gadget_mntns_id mntns_id;
	gadget_netns_id netns_id;

	char comm[TASK_COMM_LEN];
	char pcomm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
};

// const volatile struct iface{
// 	char interface[10];
// };

/* 
Let's take the ip to be in the 
format of -a 127 -b 0 -c 0 -d 1 -port 443
which translates to 127.0.0.1:443 */

const volatile __u8 a = 0;
const volatile __u8 b = 0;
const volatile __u8 c = 0;
const volatile __u8 d = 0;
const volatile __u16 port = 0;
const volatile __u32 loss_percentage = 100;

GADGET_PARAM(a);
GADGET_PARAM(b);
GADGET_PARAM(c);
GADGET_PARAM(d);
GADGET_PARAM(port);
GADGET_PARAM(loss_percentage);

struct events_map_key{
	struct gadget_l4endpoint_t dst_endpoint;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key,struct events_map_key);	// The key is going to be <dst addr,port> pair
	__type(value,struct event);
} events_map SEC(".maps");

GADGET_MAPITER(events_map_iter,events_map);


SEC("classifier/egress/drop")
int egress_tcp_drop(struct __sk_buff *skb){
		
	struct events_map_key key;	
	struct sockets_key sockets_key_for_md = {
		0,
	}; 
	struct gadget_l4endpoint_t filter_ip;

	struct event *event = NULL;
	struct event *event_map_val = NULL;

	if(!skb) 
		return TC_SHOT;

	event->netns_id = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
	sockets_key_for_md.netns = event->netns_id;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
	struct iphdr *ip4h ;
	struct ipv6hdr *ip6h ;

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


	/* 
	 * Ignore the packets which are not IPv4 or IPv6 
	 * and let them pass through in the default way
	 */

    // IPv4 Processing
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
		ip4h = (struct iphdr *)(eth + 1);

		/* Check if the IPv4 headers are invalid */
		if ((void *)(ip4h + 1) > data_end) {
			return TC_OK;
		}
		
		// Check if packets follow TCP protocol
		if (ip4h->protocol == IPPROTO_TCP) {
			// Read source and destination IP addresses
			event->src.addr_raw.v4 = bpf_ntohl(ip4h->saddr);
			event->dst.addr_raw.v4 = bpf_ntohl(ip4h->daddr);
			event->src.version = event->dst.version = 4;
			struct tcphdr *tcph = (struct tcphdr *)((__u8 *)ip4h + (ip4h->ihl * 4));
			if ((void *)(tcph + 1) > data_end) return TC_OK;  // Packet is too short, ignore
			event->src.proto = event->dst.proto = IPPROTO_TCP;
			event->src.port = bpf_ntohs(tcph->source);
			event->dst.port = bpf_ntohs(tcph->dest);
			// Enrich event with process metadata
			sockets_key_for_md.family = SE_AF_INET;
			sockets_key_for_md.proto = IPPROTO_TCP;
		}
		else{
			return TC_OK;
		}
	}
	// IPv6 Processing
	else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
		ip6h = (struct ipv6hdr *)(eth + 1);

		/* Check if the IPv6 headers are invalid */
		if ((void *)(ip6h + 1)  > data_end) {
			return TC_OK;
		}

		// Check if packets follow TCP protocol
		if (ip6h->nexthdr != IPPROTO_TCP) {
			bpf_probe_read_kernel(event->src.addr_raw.v6, sizeof(event->src.addr_raw.v6), ip6h->saddr.in6_u.u6_addr8);
			bpf_probe_read_kernel(event->dst.addr_raw.v6, sizeof(event->dst.addr_raw.v6), ip6h->daddr.in6_u.u6_addr8);
			event->src.version = event->src.version = 6;

			struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)  return TC_OK;  // Packet is too short, ignore
			event->src.proto = event->dst.proto = IPPROTO_TCP;
			event->src.port = bpf_ntohs(tcph->source);
			event->src.port = bpf_ntohs(tcph->dest);
			// Enrich event with process metadata
			sockets_key_for_md.family = SE_AF_INET6;
			sockets_key_for_md.proto = IPPROTO_TCP;
		}
		else {
			return TC_OK;
		}
	}
	else{
		return TC_OK;	// Letting them pass through the without further processing
	}
	
	sockets_key_for_md.port = event->dst.port;
	struct sockets_value *skb_val = bpf_map_lookup_elem(&gadget_sockets, &sockets_key_for_md);;
	if (skb_val != NULL) {
		event->mntns_id = skb_val->mntns;
		event->pid = skb_val->pid_tgid >> 32;
		event->tid = (__u32)skb_val->pid_tgid;
		event->ppid = skb_val->ppid;
		__builtin_memcpy(&event->comm, skb_val->task,
				sizeof(event->comm));
		__builtin_memcpy(&event->pcomm, skb_val->ptask,
				sizeof(event->pcomm));
		event->uid = (__u32)skb_val->uid_gid;
		event->gid = (__u32)(skb_val->uid_gid >> 32);
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

	key.dst_endpoint = event->dst;
	filter_ip.addr_raw.v4 = bpf_ntohl((a << 24) | (b << 16) | (c << 8) | d);
	filter_ip.port = port;
	filter_ip.proto = IPPROTO_TCP;
	filter_ip.version = 4;
	event->filter_ipv4 = filter_ip;
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	// Get a random 32-bit unsigned integer
    u32 rand_num = bpf_get_prandom_u32();

    // Set the threshold
    u64 threshold = ((u64)loss_percentage * 0xFFFFFFFF)/100; // loss_percentage% of UINT32_MAX

    // Run the code only if the random number is less than the threshold

	if(a == 0 && b == 0 && c == 0 && d == 0 && port == 0){
		event_map_val = bpf_map_lookup_elem(&events_map,&key);
		    
		if (rand_num < (u32)threshold) {
			if(!event_map_val){
				event->drop_cnt = 1;
				bpf_map_update_elem(&events_map,&key,event,BPF_NOEXIST);
			}else{
					// Increment the the value of drop count by 1. 
					// We use sync fetch and add which is an atomic addition operation
					__sync_fetch_and_add(&event->drop_cnt, 1);
					bpf_map_update_elem(&events_map,&key,event,BPF_EXIST);
			}
			return TC_SHOT;			
		}
	}
	else {
		// If the filter IP is not default value
		// then we only drop the filtered destination ip
		if(event->dst.addr_raw.v4 == filter_ip.addr_raw.v4 && event->dst.port == filter_ip.port){
			event_map_val = bpf_map_lookup_elem(&events_map,&key);

			if (rand_num < (u32)threshold) {
				if(!event_map_val){
					event->drop_cnt = 1;
					bpf_map_update_elem(&events_map,&key,event,BPF_NOEXIST);
				}else{
					// Increment the the value of drop count by 1. 
					// We use sync fetch and add which is an atomic addition operation
					__sync_fetch_and_add(&event->drop_cnt, 1);
					bpf_map_update_elem(&events_map,&key,event,BPF_EXIST);
				}
				return TC_SHOT;
			}
		}
	}
	
	return TC_OK;
}


char __license[] SEC("license") = "GPL";	