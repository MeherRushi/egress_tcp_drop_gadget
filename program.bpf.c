// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Microsoft Corporation

/* 

To do :
# Kernel space
- decouple the port and ip filter - in C - DONE
- Extend for UDP and TCP - in C - DONE
- fix the cache coherency issues. - DONE

# user space
- Change the IP parameter for ipv4 and ipv6 - need to read code
- then use kubeIPresolver to filter by name etc - need to read code

# Current Issues:
- Gadget Parameter issue
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

#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>


/* The maximum number of items in maps */
#define MAX_ENTRIES 8192
#define TASK_COMM_LEN 16

struct events_map_key{
	struct gadget_l4endpoint_t dst;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key,struct events_map_key);	// The key is going to be <dst addr,port> pair
	__type(value,struct event);
} events_map SEC(".maps");

GADGET_MAPITER(events_map_iter,events_map);


// we use the following variables as parameters
const volatile __u8 a = 0;
const volatile __u8 b = 0;
const volatile __u8 c = 0;
const volatile __u8 d = 0;
const volatile __u16 port = 0;
const volatile __u32 loss_percentage = 50;
const volatile bool filter_tcp = true;		/* This is a boolean flag to enable filtering of TCP packets */
const volatile bool filter_udp = true;		/* This is a boolean flag to enable filtering of UDP packets */

GADGET_PARAM(a);
GADGET_PARAM(b);
GADGET_PARAM(c);
GADGET_PARAM(d);
GADGET_PARAM(port);
GADGET_PARAM(loss_percentage);

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_l4endpoint_t src;
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
which translates to 127.0.0.1:443 
*/


/* This function drops packets based on independent (Bernoulli) probability model 
where each packet is dropped with an independent probabilty for dropping packets */
static int drop_packet(__u32 rand_num, __u64 threshold, struct event *event_map_val,
								   struct event *event, struct events_map_key *key)
{
	// Run the code only if the random number is less than the threshold
	if (rand_num <= (u32)threshold) {
		if(!event_map_val){
			event->drop_cnt = 1;
			bpf_map_update_elem(&events_map,key,event,BPF_NOEXIST);
		}else{
				// Increment the the value of drop count by 1. 
				// We use sync fetch and add which is an atomic addition operation
				__sync_fetch_and_add(&event->drop_cnt, 1);
				bpf_map_update_elem(&events_map,key,event,BPF_EXIST);
		}
		return TC_SHOT;			
	} 
	return TC_OK;
}

static __always_inline void read_ipv6_address(struct event *event, struct events_map_key *key, struct ipv6hdr *ip6h ){
	bpf_probe_read_kernel(event->src.addr_raw.v6, sizeof(event->src.addr_raw.v6), ip6h->saddr.in6_u.u6_addr8);
	bpf_probe_read_kernel(key->dst.addr_raw.v6, sizeof(key->dst.addr_raw.v6), ip6h->daddr.in6_u.u6_addr8);
}

SEC("classifier/egress/drop")
int egress_tcp_drop(struct __sk_buff *skb){
		
	struct events_map_key key;						/* This is the key for events_map -> being the dst addr,port pair */
	struct sockets_key sockets_key_for_md; 			/* This is for socket enrichement map */

	struct gadget_l4endpoint_t filter_ip;			/* filter ip - ideally should be a parameter from userspace */

	struct event event;								/* The sturct to store the information regarding the event */
	struct event *event_map_val ;					/* The evetnts which are stored in the events_map */

	if(!skb) 
		return TC_SHOT;							

	event.netns_id = skb->cb[0]; 					// cb[0] initialized by dispatcher.bpf.c to get the netns
	sockets_key_for_md.netns = event.netns_id;		

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
        // ("Eth headers incomplete");
		return TC_OK; // Letting them pass through the without further processing
    }


	/* 
	 * Ignore the packets which are not IPv4 or IPv6 
	 * and let them pass through in the default way
	 */

    // IPv4 Processing
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP) 
	{
		ip4h = (struct iphdr *)(eth + 1);

		/* Check if the IPv4 headers are invalid */
		if ((void *)(ip4h + 1) > data_end)
		{
			return TC_OK;
		}

		event.src.addr_raw.v4 = bpf_ntohl(ip4h->saddr);
		key.dst.addr_raw.v4 = bpf_ntohl(ip4h->daddr);
		event.src.version = key.dst.version = 4;
		sockets_key_for_md.family = SE_AF_INET;

		// Check if packets follow TCP protocol and if we want to drop tcp packets 
		if (filter_tcp == true && ip4h->protocol == IPPROTO_TCP) 
		{								
			struct tcphdr *tcph = (struct tcphdr *)((__u8 *)ip4h + (ip4h->ihl * 4));
			if ((void *)(tcph + 1) > data_end) return TC_OK;  								// Packet is too short, ignore
			event.src.proto = key.dst.proto = IPPROTO_TCP;
			event.src.port = bpf_ntohs(tcph->source);										// Extract source and destination ports from the TCP header			
			key.dst.port = bpf_ntohs(tcph->dest);
			sockets_key_for_md.proto = IPPROTO_TCP;
		} 
		else if (filter_udp == true && ip4h->protocol == IPPROTO_UDP )
		{										
			struct udphdr *udph = (struct udphdr *)((__u8 *)ip4h + (ip4h->ihl * 4));
			if ((void *)(udph + 1) > data_end) return TC_OK;  								// Packet is too short
			event.src.port = bpf_ntohs(udph->source);										// Extract source and destination ports from the UDP header
			key.dst.port = bpf_ntohs(udph->dest);
			event.src.proto = key.dst.proto = IPPROTO_UDP;
			sockets_key_for_md.proto = IPPROTO_UDP;
		}
		else 
		{
			return TC_OK;
		}
	}	
	else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) 									// IPv6 Processing
	{
		ip6h = (struct ipv6hdr *)(eth + 1);

		/* Check if the IPv6 headers are invalid */
		if ((void *)(ip6h + 1)  > data_end)
		{
			return TC_OK;
		}
		event.src.version = key.dst.version = 6;
		sockets_key_for_md.family = SE_AF_INET6;
		
		// Check if packets follow TCP protocol
		if (filter_tcp == true && ip6h->nexthdr == IPPROTO_TCP) 
		{
			read_ipv6_address(&event, &key, ip6h);

			struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)  return TC_OK; 							 // Packet is too short, ignore
			event.src.proto = key.dst.proto = IPPROTO_TCP;
			event.src.port = bpf_ntohs(tcph->source);
			event.src.port = bpf_ntohs(tcph->dest);
			sockets_key_for_md.proto = IPPROTO_TCP;
		} 
		else if (filter_udp == true && ip6h->nexthdr == IPPROTO_UDP)
		{
			struct udphdr *udph = (struct udphdr *)(ip6h + 1);
			if ((void *)(udph + 1) > data_end)  return TC_OK;  							  // Packet is too short, ignore
			event.src.port = bpf_ntohs(udph->source);
			key.dst.port = bpf_ntohs(udph->dest);
			event.src.proto = key.dst.proto = IPPROTO_UDP;
			sockets_key_for_md.proto = IPPROTO_UDP;
		}
		else
		{
			return TC_OK;
		}
	} 
	else
	{
		return TC_OK;	// Letting them pass through the without further processing
	}
	
	/* Data collection using the socket enricher, we use the key from the map
	to collect information regarding pid, mntns_id, tid, ppid etc */
	sockets_key_for_md.port = key.dst.port;
	struct sockets_value *skb_val = bpf_map_lookup_elem(&gadget_sockets, &sockets_key_for_md);
	if (skb_val != NULL) {
		event.mntns_id = skb_val->mntns;
		event.pid = skb_val->pid_tgid >> 32;
		event.tid = (__u32)skb_val->pid_tgid;
		event.ppid = skb_val->ppid;
		__builtin_memcpy(&event.comm, skb_val->task,
				sizeof(event.comm));
		__builtin_memcpy(&event.pcomm, skb_val->ptask,
				sizeof(event.pcomm));
		event.uid = (__u32)skb_val->uid_gid;
		event.gid = (__u32)(skb_val->uid_gid >> 32);
	}


	/*  
		We know for a fact that the packets we are tracing
		are TCP packets/UDP and the dst.proto would be IPPROTO_TCP,
		else we would have ignored it anyways.

		Secondly, for now we are only focusing on filtering
		by IPv4 address.

		We drop all the packets if the parameters of the 
		filter IP are default values
	 */

	filter_ip.addr_raw.v4 = bpf_ntohl((a << 24) | (b << 16) | (c << 8) | d);
	filter_ip.port = port;
	filter_ip.proto = IPPROTO_TCP;
	filter_ip.version = 4;
	event.filter_ipv4 = filter_ip;
	event.timestamp_raw = bpf_ktime_get_boot_ns();

	// Get a random 32-bit unsigned integer
    __u32 rand_num = bpf_get_prandom_u32();
    // Set the threshold using the loss_percentage
    volatile __u64 threshold = (volatile __u64)((volatile __u64)loss_percentage * (__u64)0xFFFFFFFF)/100; // loss_percentage% of UINT32_MAX

	event_map_val = bpf_map_lookup_elem(&events_map,&key);


	/* To cover different cases where the IP and port pair are given */
	// If both IP and port are 0, then drop loss% of all packets
	if(a == 0 && b == 0 && c == 0 && d == 0 && port == 0)
	{
		return drop_packet(rand_num,threshold, event_map_val,&event, &key);
	} 
	// If the IP is non 0 and port is 0, then drop all packets to any port for that IP
	else if ((a != 0 || b != 0 || c != 0 || d == 0) && port == 0) 
	{
		if(key.dst.addr_raw.v4 == filter_ip.addr_raw.v4)
		{
			drop_packet(rand_num,threshold, event_map_val,&event, &key);
		}
	}
	// If IP is zero and port is non zero, then drop all packets to the port
	else if(a == 0 && b == 0 && c == 0 && d == 0 && port != 0){
		
		if(key.dst.port == filter_ip.port)
		{
			drop_packet(rand_num,threshold, event_map_val,&event, &key);
		}
	}
	// If both are non zero
	else
	{
		if(key.dst.addr_raw.v4 == filter_ip.addr_raw.v4 && key.dst.port == filter_ip.port){
			drop_packet(rand_num,threshold, event_map_val,&event, &key);
		}
	}
	
	return TC_OK;
}


char __license[] SEC("license") = "GPL";	