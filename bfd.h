#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

#include <asm-generic/int-ll64.h>
#include <asm/types.h>

#ifndef _BFD_H
#define _BFD_H

#define BFD_SIZE sizeof(struct bfd_control)

// Perf event reasons
#define REQUEST_SESSION_POLL 0
#define REQUEST_SESSION_FINAL 1

/* Diagnostic Codes */
#define DIAG_NONE                       0
#define DIAG_DETECT_TIME_EXPIRE         1
#define DIAG_ECHO_FAILED                2
#define DIAG_NEIGH_SIG_DOWN             3
#define DIAG_FORWARD_PLANE_RST          4
#define DIAG_PATH_DOWN                  5
#define DIAG_CONCAT_PATH_DOWN           6
#define DIAG_ADMIN_DOWN                 7
#define DIAG_REV_CONCAT_PATH_DOWN       8

/* BFD States */
#define STATE_ADMIN_DOWN    0
#define STATE_DOWN          1
#define STATE_INIT          2
#define STATE_UP            3

/* Auth Types */


struct bfd_control {
    __u8    version:3,
            diagnostic:5;

    __u8    state:2,
            poll:1,
            final:1,
            cpi:1,
            auth_present:1,
            demand:1,
            multipoint:1;

    __u8 detect_multi;
    __u8 length;
    __u32 my_disc;
    __u32 your_disc;
    __u32 desired_tx;
    __u32 required_rx;
    __u32 required_echo_rx;
};

#endif              //_BFD_H
#endif              //_LINUX_TYPES_H