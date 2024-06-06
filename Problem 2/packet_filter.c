/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>

// Structure to hold process information
struct data_t
{
    __u32 pid;             // Process ID
    char program_name[16]; // Process name
};

// Function to compare two strings up to a specified length
static __always_inline int str_compare(const char *s1, const char *s2, __u32 n)
{
    for (__u32 i = 0; i < n; i++)
    {
        if (s1[i] != s2[i])
        {
            return 1; // Strings are not equal
        }
    }
    return 0; // Strings are equal
}

// Map to store the allowed port number
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} port_map SEC(".maps");

// Map to store the process name to be allowed
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} process_name_map SEC(".maps");

// Map to count the number of dropped packets
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} drop_counter SEC(".maps");

// XDP program to filter packets based on process name and port
SEC("cgroup_skb/ingress")
int block_process_ports(struct __sk_buff *skb)
{
    __u32 ipsize = 0;
    void *data = (void *)(long)(skb->data);
    void *data_end = (void *)(long)(skb->data_end);
    struct ethhdr *eth = data;

    // Verify Ethernet header
    if (data + sizeof(*eth) > data_end)
    {
        return BPF_DROP;
    }

    // Only handle IPv4 packets
    if (eth->h_proto != __bpf_htons(ETH_P_IP))
    {
        return BPF_OK;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    ipsize = sizeof(*eth) + sizeof(struct iphdr);
    if (data + ipsize > data_end)
    {
        return BPF_DROP;
    }

    // Only handle TCP packets
    if (ip->protocol != IPPROTO_TCP)
    {
        return BPF_OK;
    }

    struct tcphdr *th = (struct tcphdr *)(ip + 1);
    if ((void *)(th + 1) > data_end)
    {
        return BPF_DROP;
    }

    // Get the PID and program name
    struct data_t program;
    program.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&program.program_name, sizeof(program.program_name));

    // Check if the process name matches "myprocess"
    if (str_compare(program.program_name, "myprocess", sizeof("myprocess") - 1) == 0)
    {
        // Allow traffic only on port 4040
        if (th->dest != __bpf_htons(4040))
        {
            // Increment the drop counter
            __u32 key = 0;
            __u64 *counter = bpf_map_lookup_elem(&drop_counter, &key);
            if (counter)
            {
                __sync_fetch_and_add(counter, 1);
            }
            return BPF_DROP;
        }
    }

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
