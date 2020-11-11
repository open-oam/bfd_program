#include "bpf_helpers.h"

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    return XDP_DROP;
}