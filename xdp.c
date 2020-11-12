#define DEBUG
#include "xdp_prog.h"


BPF_MAP_DEF(program_info) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};
BPF_MAP_ADD(program_info);

struct bfd_session {
    __u8 state : 2,
        remote_state : 2,
        demand : 1,
        remote_demand : 1,
        unused : 2;
    __u8 diagnostic;
    __u8 detect_multi;
    __u32 local_disc;
    __u32 remote_disc;
    __u32 min_tx;
    __u32 remote_min_tx;
    __u32 min_rx;
    __u32 remote_min_rx;
    __u32 echo_rx;
    __u32 remote_echo_rx;
};

BPF_MAP_DEF(session_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct bfd_session),
    .max_entries = 256,
};
BPF_MAP_ADD(session_map);


//Perf event map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);

//Perf event map value
struct perf_event_item {
    __u8 diagnostic;
    __u8 new_remote_state;
    __u16 flags;
    __u32 local_disc;
    __u32 src_ip;
    __u32 timestamp;
    __u32 new_remote_disc;
    __u32 new_remote_min_tx;
    __u32 new_remote_min_rx;
    __u32 new_remote_echo_rx;
};
_Static_assert(sizeof(struct perf_event_item) == 32, "wrong size of perf_event_item");



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
    // Get context pointers
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Assign ethernet header
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    struct ethhdr *eth_header = data;

    // Check for and assign IP header
    if (eth_header->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr)  > data_end)
        return XDP_PASS;
    struct iphdr *ip_header = data + sizeof(struct ethhdr);

    __u16 ip_id = ___constant_swab16(ip_header->id);
    bpf_printk("IP Packet recieved. ID: %u\n", ip_id);

    // Check for and assign UDP header
    if (ip_header->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct udphdr *udp_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    bpf_printk("Checking UDP\n");

    // Check UDP destination port
    __u32 key = PROGKEY_PORT;
    __u32 *dst_port = bpf_map_lookup_elem(&program_info, &key);
    if (dst_port == NULL)
        return XDP_ABORTED;

    if (udp_header->dest != ___constant_swab16(*dst_port))
        return XDP_PASS;

    bpf_printk("UDP packet destined for program\n");

    ////////////////////
    //                //
    //    BFD ECHO    //
    //                //
    ////////////////////

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct bfd_echo) > data_end)
        return XDP_DROP;

    bpf_printk("Didn't pass verifier\n");    

    if (udp_header->len == ___constant_swab16(sizeof(struct udphdr) + sizeof(struct bfd_echo))) {
        struct bfd_echo *echo_packet = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

        bpf_printk("Packet identified: Echo\n");

        if (echo_packet->bfd_version != 1) {
            return XDP_DROP;
        }
        
        // If packet is a reply to echo
        if (echo_packet->reply) {
            
            bpf_printk("Echo packet is reply\n");

            __u32 my_discriminator = echo_packet->your_disc;

            if (echo_packet->code == ECHO_TRACE) {
                // Trace functionality
            }

            // Check that session and discriminators are valid
            struct bfd_session *session_info = bpf_map_lookup_elem(&session_map, &my_discriminator);
            if (session_info == NULL)
                return XDP_ABORTED;
            if (echo_packet->my_disc != session_info->remote_disc) {
                return XDP_DROP;
            }

            bpf_printk("PERF: echo packet recieved\n");

            // Send perf event to manager
            struct perf_event_item event = {
                .flags = FG_RECIEVE_ECHO,
                .local_disc = my_discriminator,
                .src_ip = ___constant_swab32(ip_header->saddr)
            };

            if (echo_packet->code == ECHO_TIMESTAMP) {
                event.timestamp = echo_packet->timestamp;
            }

            __u64 flags = BPF_F_CURRENT_CPU;
            bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));

            return XDP_DROP;
        } 
        else {

            bpf_printk("Echo packet is response\n");

            if (echo_packet->code == ECHO_TIMESTAMP) {
                // Timestamp functionality
            }
            else if (echo_packet->code == ECHO_TRACE) {
                // Trace functionality
            }

            bpf_printk("Replying to echo packet\n");

            // Flip discriminators
            __u32 temp_disc = echo_packet->my_disc;
            echo_packet->my_disc = echo_packet->your_disc;
            echo_packet->your_disc = temp_disc;

            // Update echo packet reply flag
            echo_packet->reply = 1;

            // Swap MAC addresses
            __u8 temp_mac[ETH_ALEN];
            memcpy(temp_mac, eth_header->h_source, ETH_ALEN);
            memcpy(eth_header->h_source, eth_header->h_dest, ETH_ALEN);
            memcpy(eth_header->h_dest, temp_mac, ETH_ALEN);

            // Swap IP addresses
            __u32 temp_ip = ip_header->daddr;
            ip_header->daddr = ip_header->saddr;
            ip_header->saddr = temp_ip;

            // Swap udp ports
            __u16 temp_port = udp_header->uh_sport;
            udp_header->uh_sport = udp_header->uh_dport;
            udp_header->uh_dport = temp_port;

            // Redirect packet
            __u32 key = PROGKEY_IFINDEX;
            __u32 *ifindex = bpf_map_lookup_elem(&program_info, &key);
            if (ifindex == NULL)
                return XDP_ABORTED;
            return bpf_redirect(*ifindex, 0);
        }
    }

    ///////////////////////
    //                   //
    //    BFD CONTROL    //
    //                   //
    ///////////////////////

    bpf_printk("Checking for BFD Control\n");


    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct bfd_control) > data_end)
        return XDP_PASS;

    bpf_printk("Didn't pass verifier\n");

    if (udp_header->len == ___constant_swab16(sizeof(struct udphdr) + sizeof(struct bfd_control))) {
        struct bfd_control *control_packet = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

        bpf_printk("Packet Identified: Control\n");

        // Check BFD version
        if (control_packet->version != 1)
            return XDP_DROP;

        // Check length field
        if (control_packet->auth_present) {
            return XDP_DROP;
        } else {
            if (control_packet->length != sizeof(struct bfd_control))
                return XDP_DROP;
        }

        // Check actual packet size
        if (data_end - (void *)control_packet != control_packet->length)
            return XDP_DROP;

        // Check various fields
        if (!control_packet->detect_multi || control_packet->multipoint || !control_packet->my_disc)
            return XDP_DROP;

        // If our disc is not set without wishing to create session
        if (!control_packet->your_disc && control_packet->state != STATE_DOWN && control_packet->diagnostic != DIAG_NONE && !control_packet->poll)
            return XDP_DROP;

        struct perf_event_item event = {
            .src_ip = ip_header->saddr
        };

        bpf_printk("Control packet tests passed\n");

        __u8 flag_byte = control_packet->multipoint << 7 | control_packet->demand << 6 | control_packet->auth_present << 5
                        | control_packet->cpi << 4 | control_packet->final << 3 | control_packet->poll << 2 | control_packet->state;

        bpf_printk("BPF Flags: %x\n", flag_byte);


        //If packet requires a response
        if (control_packet->poll) {

            bpf_printk("Control packet poll set\n");

            // Check for active request to create a session
            if (!control_packet->your_disc) {
                bpf_printk("Control packet session creation request\n");

                // Generate discriminator
                __u32 my_discriminator = bpf_get_prandom_u32();
                bpf_printk("Random disc: %i\n", my_discriminator);

                // Set perf event fields
                event.flags = FG_CREATE_SESSION;
                event.local_disc = my_discriminator;
                event.new_remote_state = STATE_DOWN;
                event.diagnostic = control_packet->diagnostic,
                event.new_remote_disc = ___constant_swab32(control_packet->my_disc);
                event.new_remote_echo_rx = ___constant_swab32(control_packet->required_echo_rx);
                event.new_remote_min_rx = ___constant_swab32(control_packet->required_rx);
                event.new_remote_min_tx = ___constant_swab32(control_packet->desired_tx);

                bpf_printk("PERF: create session\n");

                // Send perf event
                __u64 flags = BPF_F_CURRENT_CPU;
                bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));
                
                // Mangle packet for response
                control_packet->state = STATE_INIT;
                control_packet->final = 1;
                control_packet->poll = 0;
                control_packet->cpi = 1;
                control_packet->auth_present = 0;
                control_packet->demand = 0;
                control_packet->multipoint = 0;
                control_packet->diagnostic = DIAG_NONE;
                __u32 key = PROGKEY_DETECT_MULTI;
                __u32 *value = bpf_map_lookup_elem(&program_info, &key);
                if (value == NULL)
                    return XDP_ABORTED;
                control_packet->detect_multi = *(__u32 *)value;
                control_packet->length = sizeof(struct bfd_control);
                control_packet->your_disc = ___constant_swab32(my_discriminator);
                key = PROGKEY_MIN_TX;
                value = bpf_map_lookup_elem(&program_info, &key);
                if (value == NULL)
                    return XDP_ABORTED;
                control_packet->desired_tx = ___constant_swab32(*(__u32 *)value);
                key = PROGKEY_MIN_RX;
                value = bpf_map_lookup_elem(&program_info, &key);
                if (value == NULL)
                    return XDP_ABORTED;
                control_packet->required_rx = ___constant_swab32(*(__u32 *)value);
                key = PROGKEY_MIN_ECHO_RX;
                value = bpf_map_lookup_elem(&program_info, &key);
                if (value == NULL)
                    return XDP_ABORTED;
                control_packet->required_echo_rx = ___constant_swab32(*(__u32 *)value);
            } 
            else { 
                
                bpf_printk("PERF: normal poll packet\n");

                // Find what changed and report to manager
                __u32 key = ___constant_swab32(control_packet->your_disc);
                bpf_printk("Session key: %i\n", key);
                struct bfd_session *current_session = bpf_map_lookup_elem(&session_map, &key);
                if (current_session == NULL) {
                    bpf_printk("Poll packet, current session NULL\n");
                    return XDP_ABORTED;
                }

                event.flags = 0;
                event.diagnostic = control_packet->diagnostic;
                event.local_disc = ___constant_swab32(control_packet->your_disc);

                if (control_packet->state != current_session->remote_state){
                    event.new_remote_state = control_packet->state;
                    event.flags = event.flags | FG_CHANGED_STATE;
                }
                if (control_packet->my_disc != ___constant_swab32(current_session->remote_disc)){
                    event.new_remote_disc = ___constant_swab32(control_packet->my_disc);
                    event.flags = event.flags | FG_CHANGED_DISC;
                }
                if (control_packet->desired_tx != ___constant_swab32(current_session->remote_min_tx)) {
                    event.new_remote_min_tx = ___constant_swab32(control_packet->desired_tx);
                    event.flags = event.flags | FG_CHANGED_TIMING;
                }
                if (control_packet->required_rx != ___constant_swab32(current_session->remote_min_rx)) {
                    event.new_remote_min_rx = ___constant_swab32(control_packet->required_rx);
                    event.flags = event.flags | FG_CHANGED_TIMING;
                }
                if (control_packet->required_echo_rx != ___constant_swab32(current_session->remote_echo_rx)) {
                    event.new_remote_echo_rx = ___constant_swab32(control_packet->required_echo_rx);
                    event.flags = event.flags | FG_CHANGED_TIMING;
                }
        
                __u64 flags = BPF_F_CURRENT_CPU;
                bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));

                control_packet->diagnostic = current_session->diagnostic;
                if (current_session->state == STATE_INIT && control_packet->state == STATE_UP)
                    control_packet->state = STATE_UP;
                else
                    control_packet->state = current_session->state;
                control_packet->poll = 0;
                control_packet->final = 1;
                control_packet->cpi = 1;
                control_packet->auth_present = 0;
                control_packet->demand = current_session->demand;
                control_packet->multipoint = 0;
                control_packet->detect_multi = current_session->detect_multi;
                control_packet->length = sizeof(struct bfd_control);
                control_packet->desired_tx = ___constant_swab32(current_session->min_tx);
                control_packet->required_rx = ___constant_swab32(current_session->min_rx);
                control_packet->required_echo_rx = ___constant_swab32(current_session->echo_rx);

            }

            bpf_printk("Poll packet being retransmitted\n");

            // Flip discriminators
            __u32 temp_disc = control_packet->my_disc;
            control_packet->my_disc = control_packet->your_disc;
            control_packet->your_disc = temp_disc;

            // Swap MAC addresses
            __u8 temp_mac[ETH_ALEN];
            memcpy(temp_mac, eth_header->h_source, ETH_ALEN);
            memcpy(eth_header->h_source, eth_header->h_dest, ETH_ALEN);
            memcpy(eth_header->h_dest, temp_mac, ETH_ALEN);

            // Swap IP addresses
            __u32 temp_ip = ip_header->daddr;
            ip_header->daddr = ip_header->saddr;
            ip_header->saddr = temp_ip;

            // Swap udp ports
            __u16 temp_port = udp_header->uh_sport;
            udp_header->uh_sport = udp_header->uh_dport;
            udp_header->uh_dport = temp_port;

            // Redirect packet
            __u32 key = PROGKEY_IFINDEX;
            __u32 *ifindex = bpf_map_lookup_elem(&program_info, &key);
            if (ifindex == NULL)
                return XDP_ABORTED;
            return bpf_redirect(*ifindex, 0);
        }
        else if (control_packet->final == 1) {

            bpf_printk("Control packet final set\n");

            int state = control_packet->state;
            bpf_printk("State: %i\n", state);

            // Set perf event fields
            event.flags = FG_RECIEVE_FINAL;
            event.local_disc = ___constant_swab32(control_packet->your_disc);
            event.new_remote_disc = ___constant_swab32(control_packet->my_disc);
            event.new_remote_state = control_packet->state;
            event.diagnostic = control_packet->diagnostic;
            event.new_remote_echo_rx = ___constant_swab32(control_packet->required_echo_rx);
            event.new_remote_min_rx = ___constant_swab32(control_packet->required_rx);
            event.new_remote_min_tx = ___constant_swab32(control_packet->desired_tx);

            // Send perf event
            __u64 flags = BPF_F_CURRENT_CPU;
            bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));
                
            return XDP_DROP;
        }
        else {

            bpf_printk("Control packet Async packet\n");

            __u32 key = control_packet->your_disc;
            struct bfd_session *current_session = bpf_map_lookup_elem(&session_map, &key);
            if (current_session == NULL)
                return XDP_ABORTED;
            
            event.flags = FG_RECIEVE_CONTROL;
            event.local_disc = ___constant_swab32(control_packet->your_disc);
            event.diagnostic = control_packet->diagnostic;

            bpf_printk("PERF: async\n");

            __u64 flags = BPF_F_CURRENT_CPU;
            bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));

            // Asynchronus mode BFD control packet response
            control_packet->diagnostic = current_session->diagnostic;
            control_packet->state = current_session->state;
            control_packet->poll = 0;
            control_packet->final = 0;
            control_packet->cpi = 1;
            control_packet->auth_present = 0;
            control_packet->demand = current_session->demand;
            control_packet->multipoint = 0;
            control_packet->detect_multi = current_session->detect_multi;
            control_packet->length = sizeof(struct bfd_control);
            control_packet->desired_tx = ___constant_swab32(current_session->min_tx);
            control_packet->required_rx = ___constant_swab32(current_session->min_rx);
            control_packet->required_echo_rx = ___constant_swab32(current_session->echo_rx);

            // Flip discriminators
            __u32 temp_disc = control_packet->my_disc;
            control_packet->my_disc = control_packet->your_disc;
            control_packet->your_disc = temp_disc;

            // Swap MAC addresses
            __u8 temp_mac[ETH_ALEN];
            memcpy(temp_mac, eth_header->h_source, ETH_ALEN);
            memcpy(eth_header->h_source, eth_header->h_dest, ETH_ALEN);
            memcpy(eth_header->h_dest, temp_mac, ETH_ALEN);

            // Swap IP addresses
            __u32 temp_ip = ip_header->daddr;
            ip_header->daddr = ip_header->saddr;
            ip_header->saddr = temp_ip;

            // Swap udp ports
            __u16 temp_port = udp_header->uh_sport;
            udp_header->uh_sport = udp_header->uh_dport;
            udp_header->uh_dport = temp_port;

            // Redirect packet
            key = PROGKEY_IFINDEX;
            __u32 *ifindex = bpf_map_lookup_elem(&program_info, &key);
            if (ifindex == NULL)
                return XDP_ABORTED;
            return bpf_redirect(*ifindex, 0);
        }
    }

    bpf_printk("default drop\n");

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";