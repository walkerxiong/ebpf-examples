#include "linux/bpf.h"
#include "linux/if_ether.h"
#include "linux/if_packet.h"
#include "netinet/in.h"
#include "linux/ip.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

typedef struct in_addr ipv4_addr_t;


struct bpf_map_def SEC("maps") matches = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 16,
};

struct bpf_map_def SEC("maps") blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = 16,
} ;

SEC("xdp")
int firewall(struct xdp_md *ctx)
{
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end){
        return XDP_ABORTED;
    }

    // only ipv4 supported  
    if (eth->h_proto != __bpf_constant_htons(ETH_P_IP)){
        return XDP_PASS;
    }

    data += sizeof(*eth);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end){
        return XDP_ABORTED;
    }
    
    struct {
        __u32 prefixlen;
        __u32 saddr;
    } key;
    key.prefixlen = 32;
    key.saddr = ip->saddr;

    __u64 *rule_idx = bpf_map_lookup_elem(&blacklist,&key); 
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
