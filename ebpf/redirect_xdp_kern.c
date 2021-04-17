#include "linux/bpf.h"
#include "linux/if_ether.h"
#include "linux/ip.h"
#include "netinet/in.h"
#include "memory.h"
#include "bpf_helpers.h"

#define AF_NET  4

struct rt_item {
    int ifindex;
    char eth_src[ETH_ALEN];
    char eth_dst[ETH_ALEN];
};

struct bpf_map_def SEC("maps") rtcache_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct rt_item),
    .max_entries = 64,
};

 struct bpf_map_def SEC("maps") if_derect = {
     .type =  BPF_MAP_TYPE_DEVMAP,
     .key_size = sizeof(__u32),
     .value_size = sizeof(__u32),
     .max_entries = 64,
 };

SEC("xdp")
int redirect(struct xdp_md *ctx){
    // ethernet
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data;
    struct  rt_item *pitem = NULL;

    if (data + sizeof(*eth) > data_end){
        bpf_printk("malformed eth data \n");
        return XDP_DROP;
    }

    // icmp package
    if (eth->h_proto != htons(ETH_P_IP)){
        bpf_printk("invalid ip \n");
        return XDP_PASS;
    }
    data += sizeof(*eth);
    if (data + sizeof(*ip) > data_end){
        bpf_printk("malformed ip data \n");
        return XDP_DROP;
    }

    if(ip->protocol != htons(IPPROTO_ICMP)){
        bpf_printk("invalid icmp \n");
        return XDP_PASS;
    }

    pitem = bpf_map_lookup_elem(&rtcache_map,&ip->daddr);

    if(pitem){
        memcpy(eth->h_dest,pitem->eth_dst,ETH_ALEN);
        memcpy(eth->h_source,pitem->eth_src,ETH_ALEN);
        bpf_trace_printk("fast path %d \n",pitem->ifindex);
        return bpf_redirect_map(&if_derect,pitem->ifindex,0);
    }

    struct bpf_fib_lookup fib_param;
    // fill with zeroes
    memset(&fib_param,0,sizeof(fib_param));
    
    fib_param.family = AF_NET;
    fib_param.ipv4_dst = ip->saddr;
    fib_param.ipv4_src = ip->daddr;
    fib_param.ifindex = ctx->ingress_ifindex;

    bpf_printk("route lookup dst %d \n",fib_param.ipv4_dst);

    int rc = bpf_fib_lookup(ctx,&fib_param,sizeof(fib_param),0);

    switch (rc)
    {
    case BPF_FIB_LKUP_RET_SUCCESS:
        /* code */
        break;
    case BPF_FIB_LKUP_RET_NO_NEIGH:
        bpf_printk("Passing packet, lookup returned %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
        return XDP_PASS;
    default:
        bpf_printk("Dropping packet\n");
        return XDP_DROP;
    }
    // cached route
    struct rt_item nitem;
    memset(&nitem,0,sizeof(nitem));
    memcpy(&nitem.eth_dst,fib_param.dmac,ETH_ALEN);
    memcpy(&nitem.eth_src,fib_param.smac,ETH_ALEN);
    nitem.ifindex = fib_param.ifindex;
    bpf_map_update_elem(&rtcache_map,&fib_param.ifindex,&nitem,BPF_ANY);
    __u32 oldipdst = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = oldipdst;    

    memcpy(eth->h_dest,fib_param.dmac,ETH_ALEN);
    memcpy(eth->h_source,fib_param.smac,ETH_ALEN);
    bpf_trace_printk("slow path %d",fib_param.ifindex);
    return bpf_redirect_map(&if_derect,fib_param.ifindex,0);
}

char __license[] SEC("license") = "GPL";