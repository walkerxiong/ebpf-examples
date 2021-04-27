#include "linux/bpf.h"
#include "linux/if_ether.h"
#include "linux/if_packet.h"
#include "netinet/in.h"
#include "linux/ip.h"
#include "bpf_helpers.h"
#include "arpa/inet.h"
#include "bpf_endian.h"


struct bpf_map_def SEC("maps") matches = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 16,
};

struct blacklist_key {
    __u32 prefixlen;
    __u32 data;
};

// https://github.com/torvalds/linux/blob/master/kernel/bpf/lpm_trie.c
struct bpf_map_def SEC("maps") blacklist_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct blacklist_key),
    .value_size = sizeof(__u32),
    .max_entries = 16,
    .map_flags = BPF_F_NO_PREALLOC,
} ;

SEC("xdp")
int firewall(struct xdp_md *ctx)
{
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end){
        return XDP_ABORTED;
    }

    // only ipv4 supported  
    if (eth->h_proto != htons(ETH_P_IP)){
        return XDP_PASS;
    }

    data += sizeof(*eth);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end){
        return XDP_ABORTED;
    }
    
    struct blacklist_key key;
    key.prefixlen = 32;
    key.data = ip->saddr;

    __u64 *rule_idx = bpf_map_lookup_elem(&blacklist_map,&key); 
    if(rule_idx){
        __u32 index = *(__u32*)rule_idx;
        __u64 *counter = bpf_map_lookup_elem(&matches,&index);
        if (counter){
            (*counter) ++ ;
        }
        return XDP_DROP;
    }
    return XDP_PASS;

}

char _license[] SEC("license") = "GPLv2";
