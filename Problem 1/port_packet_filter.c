#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} port_map SEC(".maps");

// adding another map to count the number of packets dropped
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_counter SEC(".maps");

SEC("xdp")
int xdp_filter_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = (struct ethhdr *)data;

    if ((void *)(eth + 1) > data_end)
    {
        // check for verifier
        return XDP_DROP;
    }

    if (eth->h_proto != __bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
    {
        return XDP_PASS;
    }
    __u32 key = 0;
    __u32 *port = (__u32 *)bpf_map_lookup_elem(&port_map, &key);
    if (port && tcph->dest == __bpf_htons(*port))
    {
        bpf_printk("Dropped packet on port %d\n", *port);

        // and also incrementing the counter for number of packets
        // dropped
        __u64 *counter = bpf_map_lookup_elem(&drop_counter, &key);
        if (counter)
        {
            __sync_fetch_and_add(counter, 1);
        }

        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
