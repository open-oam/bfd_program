#include "bpf_helpers.h"
#include "bfd.h"

// #include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <netinet/udp.h>


#include <stddef.h>

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define BFD_MIN_PKT_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct bfd_control))

// #define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))

// #define ICMP_PKT_SIZE sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)

// #define ICMP_ECHO_LEN 64

// struct icmphdr_t {
//     __u8 type;
//     __u8 code;
//     __u16 checksum;
//     __u16 id;
//     __u16 sequence;
//     __u32 orig_time;
//     __u32 rec_time;     // Unused
//     __u32 trans_time;   // Unused
// };

BPF_MAP_DEF(program_info) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};
BPF_MAP_ADD(program_info);

BPF_MAP_DEF(session_map) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct bfd_session),
    .max_entries = 256,
};
BPF_MAP_ADD(session_map);
struct bfd_session {
    __u8 state;
    __u32 my_discriminator;
    __u32 your_discriminator;
    __u32 min_tx;
    __u32 min_rx;
    __u32 echo_rx;
};

//Perf event map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);

//Perf event map value
struct perf_event_item {
    // __u32 orig_time;
    // __u64 rec_time;

    __u8 reason;
    
    __u8 diagnostic;
    __u32 my_discriminator;
    __u32 your_discriminator;
};

_Static_assert(sizeof(struct perf_event_item) == 9, "wrong size of perf_event_item");

// __u16 calc_checksum_diff_u8(__u16 old_checksum, __u8 old_value, __u8 new_value, __u32 value_offset)
// {

//     if (new_value == old_value)
//         return old_checksum;
//     int offset = 8 * (value_offset % 2);

//     if (new_value > old_value)
//     {
//         int modifier = ((int)new_value - (int)old_value) << offset;
//         __u32 checksum = (__u32)old_checksum - modifier;
//         checksum = (checksum & 0xffff) + (checksum >> 16);
//         return checksum;
//     }
//     else if (old_value > new_value)
//     {
//         int modifier = ((int)old_value - (int)new_value) << offset;
//         __u32 checksum = (__u32)old_checksum + modifier;
//         checksum = (checksum & 0xffff) + (checksum >> 16);
//         return checksum;
//     }
//     return -1;
// }

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    
    // Set data pointers to context
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    //Verifier check for packet size 
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct bfd_control) > data_end)
        return XDP_PASS;


    struct ethhdr *eth_header = data;

    if (eth_header->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip_header = data + sizeof(struct ethhdr);

    if (ip_header->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    struct bfd_control *bfd_control_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    // Check that there actually is a BFD packet
    if (bfd_control_header->version != 1 || bfd_control_header->length != BFD_SIZE)
        return XDP_PASS;

    // generate timestamp
    __u64 rec_time = bpf_ktime_get_ns();

    // Check for request to start session
    if (bfd_control_header->state == STATE_INIT && bfd_control_header->diagnostic == DIAG_NONE && bfd_control_header->poll == 1 && bfd_control_header->final == 0){
        
        // Generate discriminator
        __u32 my_discriminator = bpf_get_prandom_u32();

        struct bfd_session *session_info = bpf_map_lookup_elem(&session_map, &my_discriminator);
        if (session_info != NULL){
           my_discriminator = bpf_get_prandom_u32();
        }
        
        // create new session map
        struct bfd_session new_session = {
            .state = STATE_INIT,
            .my_discriminator = my_discriminator,
            .your_discriminator = bfd_control_header->my_disc,
            .min_rx = bfd_control_header->required_rx,
            .min_tx = bfd_control_header->desired_tx,
            .echo_rx = bfd_control_header->required_echo_rx
        };
        
        *session_info = new_session;

        bfd_control_header->state = STATE_INIT;    
        bfd_control_header->final = 1;
        bfd_control_header->cpi = 1;
        bfd_control_header->auth_present = 0;
        bfd_control_header->demand = 0;
        bfd_control_header->multipoint = 0;
        bfd_control_header->detect_multi = 0;
        bfd_control_header->length = BFD_SIZE;
        bfd_control_header->your_disc = bfd_control_header->my_disc;
        bfd_control_header->my_disc = my_discriminator;
    
        //  modify tx/rx intervals here based on program_info map

        struct perf_event_item event = {
            .reason = REQUEST_SESSION_POLL,
            .diagnostic = DIAG_NONE,
            .my_discriminator = my_discriminator,
            .your_discriminator = session_info->your_discriminator
        };
        
        __u64 flags = BPF_F_CURRENT_CPU;
        bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));

    } 
    else if (bfd_control_header->state == STATE_INIT && bfd_control_header->diagnostic == DIAG_NONE && bfd_control_header->poll == 1 && bfd_control_header->final == 1)
    {
        // Lookup session
        __u32 my_discriminator = bfd_control_header->your_disc;
        struct bfd_session *session_info = bpf_map_lookup_elem(&session_map, &my_discriminator);

        if (session_info == NULL){
            return XDP_PASS;
        }

        // add new discriminator to session map
        session_info->your_discriminator = bfd_control_header->my_disc;

        bfd_control_header->state = STATE_INIT;
        bfd_control_header->poll = 0;
        bfd_control_header->cpi = 1;
        bfd_control_header->auth_present = 0;
        bfd_control_header->demand = 0;
        bfd_control_header->multipoint = 0;
        bfd_control_header->detect_multi = 0;
        bfd_control_header->length = BFD_SIZE;
        bfd_control_header->your_disc = bfd_control_header->my_disc;
        bfd_control_header->my_disc = my_discriminator;

        // Send perf event
        struct perf_event_item event = {
            .reason = RESPONSE_SESSION_PF,
            .diagnostic = DIAG_NONE,
            .my_discriminator = my_discriminator,
            .your_discriminator = session_info->your_discriminator
        };

        __u64 flags = BPF_F_CURRENT_CPU;
        bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));
    }
    else if (bfd_control_header->state == STATE_INIT && bfd_control_header->diagnostic == DIAG_NONE && bfd_control_header->poll == 0 && bfd_control_header->final == 1) {

        // Look up session map
        __u32 my_discriminator = bfd_control_header->your_disc;
        struct bfd_session *session_info = bpf_map_lookup_elem(&session_map, &my_discriminator);

        // Check that discriminators are valid
        if (bfd_control_header->my_disc != session_info->your_discriminator) {
            return XDP_PASS;
        }

        // Send perf event
        struct perf_event_item event = {
            .reason = REQUEST_SESSION_FINAL,
            .diagnostic = DIAG_NONE,
            .my_discriminator = my_discriminator,
            .your_discriminator = session_info->your_discriminator};

        __u64 flags = BPF_F_CURRENT_CPU;
        bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));

        // No more response packets needed 
        return XDP_DROP;
    }
    else
    {
        return XDP_PASS;
    }

    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];
    memcpy(src_mac, eth_header->h_source, ETH_ALEN);
    memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);

    //Swap MAC addresses
    memcpy(eth_header->h_dest, src_mac, ETH_ALEN);
    memcpy(eth_header->h_source, dst_mac, ETH_ALEN);

    //Get IP addresses
    __u32 src_ip = ip_header->saddr;
    __u32 dst_ip = ip_header->daddr;

    // //Swap IP addresses
    ip_header->saddr = dst_ip;
    ip_header->daddr = src_ip;

    // Swap udp ports
    __u16 src_port = udp_header->uh_sport;
    __u16 dst_port = udp_header->uh_dport;

    udp_header->uh_sport = dst_port;
    udp_header->uh_dport = src_port;

    // TODO get iface from map program_info 
    return bpf_redirect(0, 0);
    }

char _license[] SEC("license") = "GPL";