#pragma once

#include <stdint.h>

#ifndef __u64
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef int64_t __s64;
#endif

struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};

struct seccomp_notif {
    __u64 id;
    __u32 pid;
    __u32 flags;
    struct seccomp_data data;
};

struct seccomp_notif_resp {
    __u64 id;
    __s64 val;
    __s32 error;
    __u32 flags;
};

struct seccomp_notif_sizes {
    __u16 seccomp_notif;
    __u16 seccomp_notif_resp;
    __u16 seccomp_data;
};

#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_GET_NOTIF_SIZES 3

#define SECCOMP_FILTER_FLAG_NEW_LISTENER 0x20
#define SECCOMP_FILTER_FLAG_TSYNC 0x4000
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH 0x8000
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV 0x10000

#define SECCOMP_RET_USER_NOTIF 0x7fc00000
#define SECCOMP_RET_LOG 0x7ffc0000
#define SECCOMP_RET_TRACE 0x7ff00000
#define SECCOMP_RET_ALLOW 0x7fff0000
#define SECCOMP_RET_KILL 0x00000000

#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 0x01

#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IOCTL_NOTIF_RECV 0
#define SECCOMP_IOCTL_NOTIF_SEND 1
#define SECCOMP_IOCTL_NOTIF_ID_VALID 2
#define SECCOMP_IOCTL_NOTIF_SET_FLAGS 3
#define SECCOMP_IOCTL_NOTIF_ADDFD 4

#define SECCOMP_ADDFD_FLAG_SETFD 0x01
#define SECCOMP_ADDFD_FLAG_SEND 0x02

struct seccomp_notif_addfd {
    __u64 id;
    __u32 flags;
    __u32 srcfd;
    __u32 newfd;
    __u32 newfd_flags;
};
