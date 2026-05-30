// Test compatibility header
// Provides stubs for Android/Linux-specific features when
// compiling unit tests on macOS (host machine).

#ifndef TEST_COMPAT_H
#define TEST_COMPAT_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

// Stub out Android logging
#ifndef ANDROID_LOG_DEBUG
#define ANDROID_LOG_DEBUG 3
#endif
#ifndef ANDROID_LOG_INFO
#define ANDROID_LOG_INFO 4
#endif
#ifndef ANDROID_LOG_WARN
#define ANDROID_LOG_WARN 5
#endif
#ifndef ANDROID_LOG_ERROR
#define ANDROID_LOG_ERROR 6
#endif
#ifndef ANDROID_LOG_VERBOSE
#define ANDROID_LOG_VERBOSE 2
#endif

static inline int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    (void)prio; (void)tag;
    va_list args;
    va_start(args, fmt);
    int ret = vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    return ret;
}

// Stub Linux-specific ioctl / seccomp types
#ifndef _LINUX_SECCOMP_H
struct seccomp_notif { __u64 id; __u32 pid; __u32 flags; struct seccomp_data data; };
struct seccomp_notif_resp { __u64 id; __s32 val; __u32 error; __u32 flags; };
struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; };
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER 0x20
#endif

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000
#endif

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IOCTL_NOTIF_RECV 0
#define SECCOMP_IOCTL_NOTIF_SEND 1
#define SECCOMP_IOCTL_NOTIF_ID_VALID 2
#endif

// Stub linux/audit.h
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 (183 | 0x40000000)
#endif
#ifndef AUDIT_ARCH_X86_64
#define AUDIT_ARCH_X86_64 (62 | 0x40000000)
#endif
#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif
#ifndef EM_X86_64
#define EM_X86_64 62
#endif

// Stub linux/filter.h
struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; };
struct sock_fprog { unsigned short len; struct sock_filter *filter; };

#ifndef BPF_LD
#define BPF_LD 0x00
#endif
#ifndef BPF_W
#define BPF_W 0x00
#endif
#ifndef BPF_ABS
#define BPF_ABS 0x20
#endif
#ifndef BPF_JMP
#define BPF_JMP 0x05
#endif
#ifndef BPF_JEQ
#define BPF_JEQ 0x10
#endif
#ifndef BPF_K
#define BPF_K 0x00
#endif
#ifndef BPF_RET
#define BPF_RET 0x06
#endif
#ifndef BPF_ALU
#define BPF_ALU 0x04
#endif
#ifndef BPF_AND
#define BPF_AND 0x50
#endif

// Stub linux/unistd.h
#ifndef __NR_seccomp
#define __NR_seccomp 277
#endif

// Stub syscall if not on Linux
#ifndef __NR_getdents64
#define __NR_getdents64 61
#endif

#ifndef SYS_getcpu
#define SYS_getcpu 168
#endif

// Stub eventfd and timerfd
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK 0x800
#endif

#ifndef TFD_NONBLOCK
#define TFD_NONBLOCK 0x800
#endif

// arpa/inet.h stubs for macOS compatibility with Linux headers
#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef SO_REUSEADDR
#define SO_REUSEADDR 2
#endif

// Missing linux/sched.h constants
#ifndef CLONE_VM
#define CLONE_VM 0x100
#endif
#ifndef CLONE_VFORK
#define CLONE_VFORK 0x4000
#endif

// Stub prctl constants
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif
#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif
#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif

#endif // TEST_COMPAT_H
