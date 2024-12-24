//PA#4 - Nimish
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#define UDP_PORT 12345 // Target UDP port
#define BUFFER_SIZE 128 // Reduced payload size to avoid stack overflow
#define MODULO_BASE 23u
#define GENERATOR_VAL 5u

// Use __u32 for alignment
static int first_rx_flag = 1; // Initialized to true
static int first_tx_flag = 1; // Initialized to true
static __u32 local_secret = 0;
static __u32 local_pub_key = 0;
static __u32 shared_secret = 0;
static __u32 remote_pub_key = 0;

static __always_inline __u32 compute_mod_key(__u32 base) {
    __u64 mod_key = 1;
    bpf_printk("base=%u,local_secret=%u", base, local_secret);
    __u32 limit = local_secret;
    bpf_printk("limit=%u", limit);
    int count = 0;
    for (; count < limit && count < BUFFER_SIZE - 1; count++) {
        __u64 temp_key = (mod_key * base) % MODULO_BASE;
        bpf_printk("temp_key=%llu", temp_key);
        mod_key = temp_key;
        bpf_printk("%d", count);
    }
    return (__u32)mod_key;
}

static __always_inline int handle_udp(struct __sk_buff *ctx, const char *dir, int tx_flag) {
    void *packet_end = (void *)(__u64)ctx->data_end;
    void *packet_data = (void *)(__u64)ctx->data;

    struct ethhdr *eth_hdr = packet_data;
    if ((void *)(eth_hdr + 1) > packet_end)
        return TC_ACT_OK;

    if (eth_hdr->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip_hdr = (void *)(eth_hdr + 1);
    if ((void *)(ip_hdr + 1) > packet_end)
        return TC_ACT_OK;

    if (ip_hdr->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    struct udphdr *udp_hdr = (void *)(ip_hdr + 1);
    if ((void *)(udp_hdr + 1) > packet_end)
        return TC_ACT_OK;

    if (udp_hdr->dest != bpf_htons(UDP_PORT))
        return TC_ACT_OK;

    char *packet_payload = (void *)(udp_hdr + 1);
    if (packet_payload >= (char *)packet_end)
        return TC_ACT_OK;

    char debug_buf[BUFFER_SIZE] = {};
    int idx = 0;

    if (local_secret == 0) {
        // Generate a new `local_secret` if not set
        __u32 rand_key = bpf_get_prandom_u32();
        bpf_printk("Generated random key: %u", rand_key);

        rand_key = rand_key % MODULO_BASE;
        if (rand_key == 0) {
            rand_key = 1;
        }
        bpf_printk("Key after modulo operation: %u", rand_key);

        bpf_printk("Old local_secret value: %u", local_secret);
        local_secret = rand_key;
        bpf_printk("New local_secret value set: %u", local_secret);
    }
    if (local_secret != 0 && local_pub_key == 0) {
        local_pub_key = compute_mod_key(GENERATOR_VAL);
        bpf_printk("local_pub_key=%u", local_pub_key);
    }

    if (tx_flag == 0 && first_rx_flag) {
        first_rx_flag = 0;
        remote_pub_key = packet_payload[0] % MODULO_BASE;
        bpf_printk("remote_pub_key=%u", remote_pub_key);
        return TC_ACT_OK;
    }
    if (packet_payload + 1 >= (char *)packet_end) {
        return TC_ACT_OK;
    }

    if (tx_flag == 1 && first_tx_flag) {
        first_tx_flag = 0;
        packet_payload[0] = local_pub_key;
        packet_payload[1] = '\n';
        return TC_ACT_OK;
    }
    if (shared_secret == 0 && remote_pub_key != 0 && local_pub_key != 0) {
        shared_secret = compute_mod_key(remote_pub_key);
        bpf_printk("shared_secret=%u", shared_secret);
    }
    if (shared_secret != 0) {
        for (; packet_payload + idx < (char *)packet_end && idx < BUFFER_SIZE - 1; idx++) {
            debug_buf[idx] = packet_payload[idx];
            if (packet_payload[idx] != '\n') {
                packet_payload[idx] ^= shared_secret;
            }
        }
        debug_buf[idx] = '\0';

        bpf_printk("Dir: %s, Payload: %s, shared_secret:%u", dir, debug_buf, shared_secret);
    }
    return TC_ACT_OK;
}
/// @tchook {"ifindex":2, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int ingress_handler(struct __sk_buff *ctx) {
    return handle_udp(ctx, "INGRESS", 0);
}
/// @tchook {"ifindex":2, "attach_point":"BPF_TC_EGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int egress_handler(struct __sk_buff *ctx) {
    return handle_udp(ctx, "EGRESS", 1);
}

char __license[] SEC("license") = "GPL";