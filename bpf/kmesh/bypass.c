#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define MAX_ENTRIES 256

enum {
    BYPASS_FALSE = 0,
    BYPASS_TRUE = 1,
};

struct bpf_map_def SEC("maps") bypass_fliter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = MAX_ENTRIES,
};

SEC("socket_bypass")
int bypass(struct __sk_buff *skb) {
    struct iphdr iph;
    __u32 pod_ip;
    if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET) < 0) {
        return BYPASS_FALSE;
    }

    if (skb->pkt_type == PACKET_HOST) {
        pod_ip = iph.daddr;
    } else if (skb->pkt_type = PACKET_OUTGOING) {
        pod_ip = iph.saddr;
    }

    __u8 *bypass_flag = bpf_map_lookup_elem(&bypass_fliter_map, &pod_ip);
    if (bypass_flag && *bypass_flag == 1) {
        return BYPASS_TRUE;
    }

    return BYPASS_FALSE;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;