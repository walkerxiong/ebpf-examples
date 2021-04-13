#include "linux/bpf.h"
#include "linux/if_ether.h"
#include "linux/ip.h"
#include "linux/in.h"
#include "memory.h"
#include "bpf_helpers.h"

#define AF_NET  4

SEC("xdp")
int redirect(struct xdp_md *ctx){
    // ethernet
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end){
        return XDP_PASS;
    }

    // icmp package
    if (eth->h_proto != htons(ETH_P_IP)){
        return XDP_PASS;
    }
    data += sizeof(*eth);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end){
        return XDP_PASS;
    }

    if(ip->protocol != htons(IPPROTO_ICMP)){
        return XDP_PASS;
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

    if (rc == BPF_FIB_LKUP_RET_NO_NEIGH){
        return XDP_PASS;
    }

    if(rc != BPF_FIB_LKUP_RET_SUCCESS){
        bpf_printk("drop packages\n");
        return XDP_DROP;
    } 

    
}