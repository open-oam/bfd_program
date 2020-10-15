#ifndef _XDP_PROG_H
#define _XDP_PROG_H

#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <netinet/udp.h>
#include <stddef.h>

#include "bpf_helpers.h"
#include "bfd.h"


/* BFD primary perf event flags */
#define FG_RECIEVE_CONTROL  0x00
#define FG_RECIEVE_ECHO     0x01
#define FG_RECIEVE_FINAL    0x02
#define FG_CREATE_SESSION   0x04
#define FG_TEARDOWN_SESSION 0x08

/* BFD perf event bitwise OR flags */
#define FG_CHANGED_STATE    0x10
#define FG_CHANGED_DEMAND   0x20
#define FG_CHANGED_DISC     0x40
#define FG_CHANGED_TIMING   0x80


/* Program Info BPF Map keys */
#define PROGKEY_PORT 1
#define PROGKEY_IFINDEX 2
#define PROGKEY_MIN_RX 3
#define PROGKEY_MIN_TX 4
#define PROGKEY_MIN_ECHO_RX 5
#define PROGKEY_DETECT_MULTI 6


#endif