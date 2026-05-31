// SPDX-License-Identifier: MIT
//
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
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

// Ensure Linux kernel integer types are available
#ifndef __KERNEL__
#if !defined(__u8) && !defined(__U8_TYPE)
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;
#endif

#endif // __KERNEL__

// Provide sys/un.h for sockaddr_un (used by virtualizer_core.cpp)
#include <sys/un.h>

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

// Stub linux/filter.h (only if not already defined by our linux/filter.h stub)
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

// Stub syscall if not on Linux
#ifndef SYS_getcpu
#define SYS_getcpu 168
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
