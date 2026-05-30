#ifndef VIRTUALIZER_H
#define VIRTUALIZER_H

#define VIRTUALIZER_VERSION_MAJOR 1
#define VIRTUALIZER_VERSION_MINOR 0
#define VIRTUALIZER_VERSION_PATCH 0
#define VIRTUALIZER_VERSION "1.0.0"

#define VIRT_DEBUG_MODE 0

#define VIRT_ENV_MAGISK    1
#define VIRT_ENV_KERNELSU  2
#define VIRT_ENV_APATCH    3
#define VIRT_ENV_UNKNOWN   0

#define VIRT_SUPPORTED_ENVS \
    "Magisk 27.0+, KernelSU (with ZygiskNext), APatch (with ZygiskNext)"

#include <android/log.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/limits.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <signal.h>
#include <time.h>
#include <sched.h>
#include <poll.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstdarg>
#include <csetjmp>
#include <climits>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include <cassert>
#include <new>
#include <type_traits>
#include <utility>
#include <algorithm>
#include <sys/utsname.h>

#define VIRT_LOG_TAG "Virtualizer"

#define VIRT_LOG_LEVEL_NONE    0
#define VIRT_LOG_LEVEL_ERROR   1
#define VIRT_LOG_LEVEL_WARN    2
#define VIRT_LOG_LEVEL_INFO    3
#define VIRT_LOG_LEVEL_DEBUG   4
#define VIRT_LOG_LEVEL_TRACE   5

#ifndef VIRT_LOG_LEVEL
#define VIRT_LOG_LEVEL VIRT_LOG_LEVEL_DEBUG
#endif

#define VIRT_LOGD(...) do { \
    if (VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_DEBUG) \
        __android_log_print(ANDROID_LOG_DEBUG, VIRT_LOG_TAG, __VA_ARGS__); \
} while (0)

#define VIRT_LOGI(...) do { \
    if (VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_INFO) \
        __android_log_print(ANDROID_LOG_INFO, VIRT_LOG_TAG, __VA_ARGS__); \
} while (0)

#define VIRT_LOGW(...) do { \
    if (VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_WARN) \
        __android_log_print(ANDROID_LOG_WARN, VIRT_LOG_TAG, __VA_ARGS__); \
} while (0)

#define VIRT_LOGE(...) do { \
    if (VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_ERROR) \
        __android_log_print(ANDROID_LOG_ERROR, VIRT_LOG_TAG, __VA_ARGS__); \
} while (0)

#define VIRT_LOGT(...) do { \
    if (VIRT_LOG_LEVEL >= VIRT_LOG_LEVEL_TRACE) \
        __android_log_print(ANDROID_LOG_VERBOSE, VIRT_LOG_TAG, __VA_ARGS__); \
} while (0)

#define ARRAY_COUNT(x)          (sizeof(x) / sizeof((x)[0]))
#define VIRT_MIN(a,b)           ((a) < (b) ? (a) : (b))
#define VIRT_MAX(a,b)           ((a) > (b) ? (a) : (b))
#define VIRT_CLAMP(x,lo,hi)     ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))
#define VIRT_ALIGN_UP(x,a)      (((x) + (a) - 1) & ~((uint64_t)(a) - 1ULL))
#define VIRT_ALIGN_DOWN(x,a)    ((x) & ~((uint64_t)(a) - 1ULL))
#define VIRT_IS_ALIGNED(x,a)    (((uint64_t)(x) & ((uint64_t)(a) - 1ULL)) == 0)
#define VIRT_PTR_ADD(p,off)     ((void *)((uintptr_t)(p) + (uintptr_t)(off)))
#define VIRT_PTR_DIFF(a,b)      ((intptr_t)((uintptr_t)(a) - (uintptr_t)(b)))
#define VIRT_PAGE_ALIGN(x)      VIRT_ALIGN_UP(x, 4096ULL)
#define VIRT_PAGE_COUNT(x)      ((x) / 4096 + !!((x) % 4096))
#define VIRT_ROUND_DOWN(x,m)    ((x) & ~((m)-1))
#define VIRT_MASK_ISSET(v,m)    (((v) & (m)) == (m))
#define VIRT_MASK_SET(v,m)      ((v) |= (m))
#define VIRT_MASK_CLEAR(v,m)    ((v) &= ~(m))
#define VIRT_MASK_TOGGLE(v,m)   ((v) ^= (m))
#define VIRT_NS_PER_SEC         1000000000ULL
#define VIRT_NS_PER_MS          1000000ULL
#define VIRT_NS_PER_US          1000ULL
#define VIRT_US_PER_MS          1000ULL
#define VIRT_MS_PER_SEC         1000ULL
#define VIRT_PAGE_SIZE          4096
#define VIRT_HANDLER_STACK_SIZE (256 * 1024)
#define VIRT_PATH_BUF_SIZE      4096
#define VIRT_TMP_BUF_SIZE       8192
#define VIRT_PROC_NAME_MAX      256
#define VIRT_MAX_ENVIRON_ENTRIES 64
#define VIRT_MAX_RULES          1024
#define VIRT_MAX_CACHED_PATHS   8192
#define VIRT_MAX_STATS_HISTORY  3600
#define VIRT_NOTIF_FD_TIMEOUT_MS 5000
#define VIRT_WATCHDOG_INTERVAL_NS (10ULL * VIRT_NS_PER_SEC)
#define VIRT_CACHE_TTL_NS       (5ULL * VIRT_NS_PER_SEC)
#define VIRT_ANTI_TAMPER_INTERVAL_NS (5ULL * VIRT_NS_PER_SEC)
#define VIRT_HEALTH_REPORT_INTERVAL 5000
#define VIRT_STATS_REPORT_INTERVAL  5000
#define VIRT_EVENT_RING_SIZE    1024
#define VIRT_MAX_FAKE_FILES     64
#define VIRT_MAX_CONNECT_RULES  64
#define VIRT_MAX_FAKE_MAPS_LINES 256
#define VIRT_MAX_THREADS        512
#define VIRT_MAX_LISTENERS      256
#define VIRT_MAX_DEPENDENCY_CHAIN 16
#define VIRT_SIGNAL_STACK_SIZE  (32 * 1024)

#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 (EM_AARCH64 | 0x40000000)
#endif

#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

#ifndef AUDIT_ARCH_X86_64
#define AUDIT_ARCH_X86_64 (EM_X86_64 | 0x40000000)
#endif

#ifndef EM_X86_64
#define EM_X86_64 62
#endif

#ifndef SYS_getcpu
#define SYS_getcpu 168
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER 0x20
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 0x4000
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH 0x8000
#endif

#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV 0x10000
#endif

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000
#endif

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 0x01
#endif

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IOCTL_NOTIF_RECV        _IOR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND        _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID    _IOR(SECCOMP_IOC_MAGIC, 2, __u64)
#define SECCOMP_IOCTL_NOTIF_SET_FLAGS   _IOW(SECCOMP_IOC_MAGIC, 3, __u64)
#endif

#ifndef __NR_seccomp
#define __NR_seccomp 277
#endif

#ifndef __NR_openat
#define __NR_openat 56
#endif

#ifndef __NR_openat2
#define __NR_openat2 293
#endif

#ifndef __NR_readlinkat
#define __NR_readlinkat 78
#endif

#ifndef __NR_readlink
#define __NR_readlink 89
#endif

#ifndef __NR_faccessat
#define __NR_faccessat 48
#endif

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

#ifndef __NR_newfstatat
#define __NR_newfstatat 79
#endif

#ifndef __NR_statx
#define __NR_statx 291
#endif

#ifndef __NR_getdents64
#define __NR_getdents64 61
#endif

/* __NR_getdents not defined on ARM64 (only __NR_getdents64 exists) */
#if defined(__arm__) && !defined(__NR_getdents)
#define __NR_getdents 141
#elif defined(__i386__) && !defined(__NR_getdents)
#define __NR_getdents 141
#elif !defined(__NR_getdents)
/* Use same value as __NR_getdents64 on architectures where getdents doesn't exist */
#define __NR_getdents __NR_getdents64
#endif

#ifndef __NR_connect
#define __NR_connect 203
#endif

#ifndef __NR_socket
#define __NR_socket 198
#endif

#ifndef __NR_ioctl
#define __NR_ioctl 29
#endif

#ifndef __NR_prctl
#define __NR_prctl 167
#endif

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 310
#endif

#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 311
#endif

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

#ifndef __NR_mmap
#define __NR_mmap 222
#endif

#ifndef __NR_munmap
#define __NR_munmap 215
#endif

#ifndef __NR_mprotect
#define __NR_mprotect 226
#endif

#ifndef __NR_pkey_mprotect
#define __NR_pkey_mprotect 288
#endif

#ifndef __NR_madvise
#define __NR_madvise 233
#endif

#ifndef __NR_mlock
#define __NR_mlock 228
#endif

#ifndef __NR_munlock
#define __NR_munlock 229
#endif

#ifndef __NR_mlockall
#define __NR_mlockall 230
#endif

#ifndef __NR_pread64
#define __NR_pread64 67
#endif

#ifndef __NR_pwrite64
#define __NR_pwrite64 68
#endif

#ifndef __NR_preadv
#define __NR_preadv 69
#endif

#ifndef __NR_pwritev
#define __NR_pwritev 70
#endif

#ifndef __NR_sendfile
#define __NR_sendfile 71
#endif

#ifndef __NR_dup
#define __NR_dup 23
#endif

#ifndef __NR_dup3
#define __NR_dup3 24
#endif

#ifndef __NR_fcntl
#define __NR_fcntl 25
#endif

#ifndef __NR_flock
#define __NR_flock 32
#endif

#ifndef __NR_fsync
#define __NR_fsync 82
#endif

#ifndef __NR_fdatasync
#define __NR_fdatasync 83
#endif

#ifndef __NR_truncate
#define __NR_truncate 45
#endif

#ifndef __NR_ftruncate
#define __NR_ftruncate 46
#endif

#ifndef __NR_symlinkat
#define __NR_symlinkat 36
#endif

#ifndef __NR_linkat
#define __NR_linkat 37
#endif

#ifndef __NR_unlinkat
#define __NR_unlinkat 35
#endif

#ifndef __NR_renameat
#define __NR_renameat 38
#endif

#ifndef __NR_mkdirat
#define __NR_mkdirat 34
#endif

#ifndef __NR_mknodat
#define __NR_mknodat 33
#endif

#ifndef __NR_chdir
#define __NR_chdir 49
#endif

#ifndef __NR_fchdir
#define __NR_fchdir 50
#endif

#ifndef __NR_getcwd
#define __NR_getcwd 17
#endif

#ifndef __NR_statfs
#define __NR_statfs 43
#endif

#ifndef __NR_fstatfs
#define __NR_fstatfs 44
#endif

#ifndef __NR_access
#define __NR_access 47
#endif

#ifndef __NR_pipe2
#define __NR_pipe2 59
#endif

#ifndef __NR_clone
#define __NR_clone 220
#endif

#ifndef __NR_fork
#define __NR_fork 1079
#endif

#ifndef __NR_vfork
#define __NR_vfork 1079
#endif

#ifndef __NR_exit
#define __NR_exit 93
#endif

#ifndef __NR_exit_group
#define __NR_exit_group 94
#endif

#ifndef __NR_kill
#define __NR_kill 129
#endif

#ifndef __NR_tkill
#define __NR_tkill 130
#endif

#ifndef __NR_tgkill
#define __NR_tgkill 131
#endif

#ifndef __NR_nanosleep
#define __NR_nanosleep 101
#endif

#ifndef __NR_clock_nanosleep
#define __NR_clock_nanosleep 115
#endif

#ifndef __NR_getpid
#define __NR_getpid 172
#endif

#ifndef __NR_getppid
#define __NR_getppid 173
#endif

#ifndef __NR_gettid
#define __NR_gettid 178
#endif

#ifndef __NR_sched_setscheduler
#define __NR_sched_setscheduler 144
#endif

#ifndef __NR_sched_getscheduler
#define __NR_sched_getscheduler 145
#endif

#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity 122
#endif

#ifndef __NR_sched_getaffinity
#define __NR_sched_getaffinity 123
#endif

#ifndef __NR_sched_yield
#define __NR_sched_yield 124
#endif

#ifndef __NR_sched_setattr
#define __NR_sched_setattr 146
#endif

#ifndef __NR_sched_getattr
#define __NR_sched_getattr 147
#endif

#ifndef __NR_setpriority
#define __NR_setpriority 140
#endif

#ifndef __NR_getpriority
#define __NR_getpriority 141
#endif

#ifndef __NR_setrlimit
#define __NR_setrlimit 164
#endif

#ifndef __NR_getrlimit
#define __NR_getrlimit 163
#endif

#ifndef __NR_getrusage
#define __NR_getrusage 165
#endif

#ifndef __NR_times
#define __NR_times 153
#endif

#ifndef __NR_gettimeofday
#define __NR_gettimeofday 169
#endif

#ifndef __NR_settimeofday
#define __NR_settimeofday 170
#endif

#ifndef __NR_clock_gettime
#define __NR_clock_gettime 113
#endif

#ifndef __NR_clock_settime
#define __NR_clock_settime 114
#endif

#ifndef __NR_clock_getres
#define __NR_clock_getres 114
#endif

#ifndef __NR_timer_create
#define __NR_timer_create 104
#endif

#ifndef __NR_timer_settime
#define __NR_timer_settime 105
#endif

#ifndef __NR_timer_gettime
#define __NR_timer_gettime 106
#endif

#ifndef __NR_timer_getoverrun
#define __NR_timer_getoverrun 107
#endif

#ifndef __NR_timer_delete
#define __NR_timer_delete 111
#endif

#ifndef __NR_signalfd4
#define __NR_signalfd4 289
#endif

#ifndef __NR_eventfd2
#define __NR_eventfd2 290
#endif

#ifndef __NR_epoll_create1
#define __NR_epoll_create1 20
#endif

#ifndef __NR_epoll_ctl
#define __NR_epoll_ctl 21
#endif

#ifndef __NR_epoll_pwait
#define __NR_epoll_pwait 22
#endif

#ifndef __NR_inotify_init1
#define __NR_inotify_init1 26
#endif

#ifndef __NR_inotify_add_watch
#define __NR_inotify_add_watch 27
#endif

#ifndef __NR_inotify_rm_watch
#define __NR_inotify_rm_watch 28
#endif

#ifndef __NR_pselect6
#define __NR_pselect6 72
#endif

#ifndef __NR_ppoll
#define __NR_ppoll 73
#endif

#ifndef __NR_recvfrom
#define __NR_recvfrom 207
#endif

#ifndef __NR_sendto
#define __NR_sendto 206
#endif

#ifndef __NR_recvmsg
#define __NR_recvmsg 212
#endif

#ifndef __NR_sendmsg
#define __NR_sendmsg 211
#endif

#ifndef __NR_accept4
#define __NR_accept4 242
#endif

#ifndef __NR_bind
#define __NR_bind 200
#endif

#ifndef __NR_listen
#define __NR_listen 201
#endif

#ifndef __NR_getsockname
#define __NR_getsockname 204
#endif

#ifndef __NR_getpeername
#define __NR_getpeername 205
#endif

#ifndef __NR_setsockopt
#define __NR_setsockopt 208
#endif

#ifndef __NR_getsockopt
#define __NR_getsockopt 209
#endif

#ifndef __NR_shutdown
#define __NR_shutdown 210
#endif

enum VIRT_SYSCALL_NR : int {
    VIRT_NR_faccessat       = 48,
    VIRT_NR_openat          = 56,
    VIRT_NR_readlinkat      = 78,
    VIRT_NR_newfstatat      = 79,
    VIRT_NR_readlink        = 89,
    VIRT_NR_connect         = 203,
    VIRT_NR_mmap            = 222,
    VIRT_NR_mprotect        = 226,
    VIRT_NR_statx           = 291,
    VIRT_NR_openat2         = 293,
    VIRT_NR_process_vm_readv  = 310,
    VIRT_NR_process_vm_writev = 311,
    VIRT_NR_faccessat2      = 439,
    VIRT_NR_getdents64      = 61,
    VIRT_NR_socket          = 198,
    VIRT_NR_ioctl           = 29,
    VIRT_NR_prctl           = 167,
    VIRT_NR_clone3          = 435,
    VIRT_NR_exit_group      = 94,
    VIRT_NR_getdents        = 78,
    VIRT_NR_clone           = 220,
    VIRT_NR_fstatfs         = 44,
    VIRT_NR_statfs          = 43,
    VIRT_NR_pread64         = 67,
    VIRT_NR_pwrite64        = 68,
    VIRT_NR_fsync           = 82,
    VIRT_NR_fdatasync       = 83,
    VIRT_NR_dup3            = 24,
    VIRT_NR_pipe2           = 59,
    VIRT_NR_munmap          = 215,
    VIRT_NR_madvise         = 233,
    VIRT_NR_mlock           = 228,
    VIRT_NR_munlock         = 229,
    VIRT_NR_sched_yield     = 124,
    VIRT_NR_nanosleep       = 101,
    VIRT_NR_clock_gettime   = 113,
    VIRT_NR_getpid          = 172,
    VIRT_NR_gettid          = 178,
    VIRT_NR_exit            = 93,
};

enum VIRT_MATCH_TYPE : int {
    VIRT_MATCH_EXACT        = 0,
    VIRT_MATCH_PREFIX       = 1,
    VIRT_MATCH_SUFFIX       = 2,
    VIRT_MATCH_SUBSTRING    = 3,
    VIRT_MATCH_GLOB         = 4,
    VIRT_MATCH_REGEX        = 5,
    VIRT_MATCH_ALWAYS       = 6,
    VIRT_MATCH_NEVER        = 7,
    VIRT_MATCH_COUNT        = 8
};

enum VIRT_ACTION : int {
    VIRT_ACTION_ALLOW            = 0,
    VIRT_ACTION_BLOCK_ENOENT     = 1,
    VIRT_ACTION_BLOCK_EACCES     = 2,
    VIRT_ACTION_BLOCK_EPERM      = 3,
    VIRT_ACTION_BLOCK_ENXIO      = 4,
    VIRT_ACTION_BLOCK_EIO        = 5,
    VIRT_ACTION_BLOCK_EROFS      = 6,
    VIRT_ACTION_REDIRECT_PATH    = 7,
    VIRT_ACTION_FAKE_CONTENT     = 8,
    VIRT_ACTION_FAKE_EMPTY       = 9,
    VIRT_ACTION_FAKE_MAPS        = 10,
    VIRT_ACTION_FAKE_STATUS      = 11,
    VIRT_ACTION_PASS_THROUGH     = 12,
    VIRT_ACTION_COUNT            = 13
};

enum VIRT_SCOPE : int {
    VIRT_SCOPE_PROCESS      = 0,
    VIRT_SCOPE_THREAD       = 1,
    VIRT_SCOPE_ALL          = 2,
    VIRT_SCOPE_COUNT        = 3
};

enum VIRT_SYSCALL_CATEGORY : int {
    VIRT_CAT_FILE_READ      = 0,
    VIRT_CAT_FILE_WRITE     = 1,
    VIRT_CAT_FILE_META      = 2,
    VIRT_CAT_PROC           = 3,
    VIRT_CAT_NETWORK        = 4,
    VIRT_CAT_MEMORY         = 5,
    VIRT_CAT_EXEC           = 6,
    VIRT_CAT_DEBUG          = 7,
    VIRT_CAT_OTHER          = 8,
    VIRT_CAT_COUNT          = 9
};

enum VIRT_FILTER_MODE : int {
    VIRT_FILTER_MODE_BPF_STATIC  = 0,
    VIRT_FILTER_MODE_BPF_DYNAMIC = 1,
    VIRT_FILTER_MODE_BPF_PERF    = 2,
    VIRT_FILTER_MODE_COUNT       = 3
};

enum VIRT_HANDLER_STATE : int {
    VIRT_HANDLER_UNINITIALIZED  = 0,
    VIRT_HANDLER_INITIALIZING   = 1,
    VIRT_HANDLER_RUNNING        = 2,
    VIRT_HANDLER_PAUSED         = 3,
    VIRT_HANDLER_CRASHED        = 4,
    VIRT_HANDLER_SHUTDOWN       = 5,
    VIRT_HANDLER_STATE_COUNT    = 6
};

#define VIRT_OK             0
#define VIRT_ERR_NOMEM      -1   // Out of memory
#define VIRT_ERR_INVAL      -2   // Invalid argument
#define VIRT_ERR_NODEV      -3   // No device (seccomp not available)
#define VIRT_ERR_AGAIN      -4   // Try again
#define VIRT_ERR_TIMEOUT    -5   // Operation timed out
#define VIRT_ERR_CANCELED   -6   // Operation canceled
#define VIRT_ERR_NOTSUP     -7   // Not supported
#define VIRT_ERR_BPF        -8   // BPF compilation error
#define VIRT_ERR_SECCOMP    -9   // Seccomp syscall error
#define VIRT_ERR_HANDLER    -10  // Handler thread error
#define VIRT_ERR_CONFIG     -11  // Configuration error
#define VIRT_ERR_IO         -12  // I/O error
#define VIRT_ERR_CORRUPT    -13  // Corrupted data
#define VIRT_ERR_BUSY       -14  // Resource busy
#define VIRT_ERR_EXIST      -15  // Already exists
// Backward-compatibility aliases
#define VIRT_ERR_GENERIC    -99
#define VIRT_ERR_NOSYS      -98
#define VIRT_ERR_PERM       -97
#define VIRT_ERR_NOENT      -96
#define VIRT_ERR_INTR       -95
#define VIRT_ERR_OVERFLOW   -94
#define VIRT_ERR_LIMIT      -93
#define VIRT_ERR_DEADLK     -92
#define VIRT_ERR_AGAIN_RETRY -91

static inline const char *virt_strerror(int err) {
    switch (err) {
        case VIRT_ERR_NOMEM:    return "Out of memory";
        case VIRT_ERR_INVAL:    return "Invalid argument";
        case VIRT_ERR_NODEV:    return "Seccomp not available";
        case VIRT_ERR_AGAIN:    return "Try again";
        case VIRT_ERR_TIMEOUT:  return "Operation timed out";
        case VIRT_ERR_CANCELED: return "Operation canceled";
        case VIRT_ERR_NOTSUP:   return "Not supported";
        case VIRT_ERR_BPF:      return "BPF compilation error";
        case VIRT_ERR_SECCOMP:  return "Seccomp syscall error";
        case VIRT_ERR_HANDLER:  return "Handler thread error";
        case VIRT_ERR_CONFIG:   return "Configuration error";
        case VIRT_ERR_IO:       return "I/O error";
        case VIRT_ERR_CORRUPT:  return "Corrupted data";
        case VIRT_ERR_BUSY:     return "Resource busy";
        case VIRT_ERR_EXIST:    return "Already exists";
        default:                return "Unknown error";
    }
}

enum VIRT_PROCESS_PROFILE : int {
    VIRT_PROFILE_UNKNOWN        = 0,
    VIRT_PROFILE_GAME           = 1,
    VIRT_PROFILE_BROWSER        = 2,
    VIRT_PROFILE_SOCIAL         = 3,
    VIRT_PROFILE_PAYMENT        = 4,
    VIRT_PROFILE_BANKING        = 5,
    VIRT_PROFILE_STORE          = 6,
    VIRT_PROFILE_LAUNCHER       = 7,
    VIRT_PROFILE_SYSTEM         = 8,
    VIRT_PROFILE_ANTICHEAT      = 9,
    VIRT_PROFILE_COUNT          = 10
};

typedef struct VIRT_SyscallStats {
    uint64_t total_calls;
    uint64_t blocked_calls;
    uint64_t allowed_calls;
    uint64_t continued_calls;
    uint64_t fallback_calls;
    uint64_t error_calls;
    uint64_t per_syscall[512];
    uint64_t per_action[VIRT_ACTION_COUNT];
    uint64_t per_category[VIRT_CAT_COUNT];
    uint64_t total_latency_ns;
    uint64_t max_latency_ns;
    uint64_t min_latency_ns;
    uint64_t last_reset_tp;
    uint64_t handler_lifespan_ns;
    double   avg_latency_ns;
    double   calls_per_sec;
    double   blocked_percent;
    double   avg_blocked_latency_ns;
    double   avg_passthrough_latency_ns;
    uint32_t window_seconds;
    struct {
        uint64_t timestamp;
        uint64_t calls;
        uint64_t blocked;
        uint64_t avg_latency;
    } history[VIRT_MAX_STATS_HISTORY];
    uint32_t history_index;
    uint32_t history_count;
} VIRT_SyscallStats;

typedef struct VIRT_Rule {
    char     pattern[VIRT_PATH_BUF_SIZE];
    uint32_t pattern_len;
    int      match_type;
    int      action;
    int      scope;
    int      category;
    uint32_t priority;
    uint32_t flags;
    char     redirect_target[VIRT_PATH_BUF_SIZE];
    char     fake_content_path[VIRT_PATH_BUF_SIZE];
    uint64_t created_ns;
    uint64_t hit_count;
    uint64_t last_hit_ns;
    int      ref_count;
    bool     enabled;
    bool     is_default;
    bool     is_system;
} VIRT_Rule;

typedef struct VIRT_Config {
    char config_path[VIRT_PATH_BUF_SIZE];
    char rules_path[VIRT_PATH_BUF_SIZE];
    char rules_json_path[VIRT_PATH_BUF_SIZE];
    char fake_maps_path[VIRT_PATH_BUF_SIZE];
    char fake_status_path[VIRT_PATH_BUF_SIZE];
    bool enable_file_decoy;
    char log_tag[64];
    int  log_level;
    int  filter_mode;
    int  default_action;
    bool enable_stats;
    bool enable_cache;
    bool enable_watchdog;
    bool enable_anti_tamper;
    bool enable_proc_hiding;
    bool enable_fake_content;
    bool enable_timing_jitter;
    bool enable_thread_sync;
    bool enable_kernel_compat;
    bool enable_self_diagnostics;
    bool enable_event_ring;
    bool enable_trie_index;
    bool enable_latency_tracking;
    bool enable_per_syscall_stats;
    bool enable_periodic_reporting;
    bool enable_signal_safety;
    uint32_t cache_size;
    uint32_t stats_window_sec;
    uint32_t watchdog_interval_sec;
    uint32_t max_rules;
    uint32_t handler_stack_size;
    uint32_t notif_timeout_ms;
    uint32_t timing_jitter_us;
    uint32_t jitter_range_us;
    uint32_t reconnect_delay_ms;
    uint32_t max_consecutive_errors;
    uint32_t max_event_ring_entries;
} VIRT_Config;

typedef struct VIRT_CacheEntry {
    char     path[VIRT_PATH_BUF_SIZE];
    uint32_t path_len;
    bool     is_sensitive;
    int      action;
    uint64_t cached_at_ns;
    uint64_t hit_count;
    uint64_t ttl_ns;
    bool     valid;
} VIRT_CacheEntry;

typedef struct VIRT_SyscallEvent {
    uint64_t id;
    uint32_t pid;
    uint32_t tid;
    int      syscall_nr;
    uint64_t args[6];
    uint64_t timestamp_ns;
    char     path_buf[VIRT_PATH_BUF_SIZE];
    int      path_len;
    bool     path_readable;
    int      resolved_action;
    uint64_t process_time_ns;
    uint64_t total_latency_ns;
    bool     used_continue;
    bool     used_fallback;
    int      response_error;
    int      response_val;
} VIRT_SyscallEvent;

typedef struct VIRT_EventRing {
    VIRT_SyscallEvent events[VIRT_EVENT_RING_SIZE];
    uint32_t write_pos;
    uint32_t read_pos;
    uint32_t count;
    bool     overflow;
} VIRT_EventRing;

typedef struct VIRT_HealthStatus {
    int  handler_state;
    int  notify_fd;
    int  last_error;
    uint64_t uptime_ns;
    uint64_t processed_events;
    uint64_t blocked_events;
    uint64_t error_count;
    uint64_t consecutive_errors;
    uint32_t active_threads;
    uint32_t active_rules;
    uint32_t cache_hit_rate;
    uint32_t active_listeners;
    uint32_t total_listeners;
    int  last_errno;
    bool fd_valid;
    bool thread_alive;
    bool kernel_continue;
    bool tsync_active;
    char last_error_msg[256];
    struct timespec last_heartbeat;
    double avg_latency_ns;
    double max_latency_ns;
    double min_latency_ns;
    uint64_t continue_fallbacks;
    uint64_t total_events;
    uint64_t total_blocked;
} VIRT_HealthStatus;

typedef struct ShadowLibraryMirror {
    uintptr_t execution_base;
    uintptr_t pristine_base;
    size_t    segment_size;
    bool      initialized;
} ShadowLibraryMirror;

typedef struct VIRT_ThreadMonitor {
    pid_t     tid;
    char      name[64];
    uint64_t  created_ns;
    uint64_t  last_seen_ns;
    uint64_t  syscall_count;
    bool      has_seccomp;
    bool      is_alive;
    int       priority;
    int       policy;
    int       cpu;
    uint64_t  total_latency_ns;
    uint64_t  blocked_count;
} VIRT_ThreadMonitor;

typedef struct VIRT_AntiTamperState {
    bool initialized;
    bool integrity_ok;
    bool debugger_detected;
    bool hook_detected;
    bool ptrace_detected;
    bool memory_modified;
    bool code_page_writable;
    uint64_t last_check_ns;
    uint64_t check_interval_ns;
    uint32_t integrity_failures;
    uint32_t consecutive_failures;
    uintptr_t module_base;
    size_t   module_size;
    uint32_t text_hash;
    uint32_t rodta_hash;
    uint32_t rodata_hash;
    uint32_t expected_text_hash;
    uint32_t expected_rodta_hash;
    uint32_t expected_rodata_hash;
    uint32_t total_checks;
    uint32_t total_alerts;
    uint32_t detected_hooks;
    uint32_t detected_debuggers;
    uint32_t detected_ptrace;
    int      last_check_result;
} VIRT_AntiTamperState;

typedef struct VIRT_ProcHiderState {
    bool initialized;
    bool hide_maps;
    bool hide_fd;
    bool hide_status;
    bool hide_stat;
    bool hide_mountinfo;
    bool hide_cmdline;
    bool hide_environ;
    bool hide_limits;
    bool hide_smaps;
    bool hide_smaps_rollup;
    bool hide_numamaps;
    bool hide_oom;
    bool hide_sched;
    bool hide_cgroup;
    bool hide_attr;
    bool hide_task;
    bool fake_maps_content;
    bool fake_status_content;
    bool fake_cmdline_content;
    uint32_t hidden_fds[64];
    uint32_t hidden_fd_count;
    uint32_t hidden_pids[64];
    uint32_t hidden_pid_count;
    uint32_t hidden_tids[64];
    uint32_t hidden_tid_count;
    char proc_name_fake[VIRT_PROC_NAME_MAX];
    char cmdline_fake[VIRT_PATH_BUF_SIZE];
    struct {
        char name[64];
        char state[16];
        char ppid[16];
        char uid[16];
        char gid[16];
        char tgid[16];
        char tracerpid[16];
        char fdcount[16];
        char threads[16];
        char vmpeak[32];
        char vmsize[32];
        char vmrss[32];
        char threads_str[16];
    } fake_status_fields;
} VIRT_ProcHiderState;

typedef struct VIRT_FakeFile {
    char     path[VIRT_PATH_BUF_SIZE];
    char     content[8192];
    uint32_t content_len;
    uint32_t hit_count;
    bool     enabled;
} VIRT_FakeFile;

typedef struct VIRT_FakeMapsLine {
    uintptr_t start;
    uintptr_t end;
    char      perms[8];
    uint64_t  offset;
    uint32_t  major;
    uint32_t  minor;
    uint64_t  inode;
    char      pathname[256];
    bool      enabled;
} VIRT_FakeMapsLine;

typedef struct VIRT_FakeMapsContent {
    VIRT_FakeMapsLine lines[VIRT_MAX_FAKE_MAPS_LINES];
    uint32_t line_count;
    bool     enabled;
    uint64_t hit_count;
    uint64_t last_generated_ns;
} VIRT_FakeMapsContent;

typedef struct VIRT_SeccompFilterProfile {
    int    syscall_nr;
    int    category;
    bool   intercept;
    char   name[32];
} VIRT_SeccompFilterProfile;

/* linux_dirent64 may not be defined in NDK headers */
#ifndef HAVE_LINUX_DIRENT64
#define HAVE_LINUX_DIRENT64
struct linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};
#endif

/* seccomp_notif and seccomp_notif_resp are defined in <linux/seccomp.h>
 * We only define SECCOMP_USER_NOTIF_FLAG_CONTINUE if missing. */
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 0x00000001
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV SECCOMP_IOC(0, 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_SEND
#define SECCOMP_IOCTL_NOTIF_SEND SECCOMP_IOC(1, 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_ID_VALID
#define SECCOMP_IOCTL_NOTIF_ID_VALID SECCOMP_IOC(2, 0)
#endif

typedef struct VIRT_GlobPattern {
    char     pattern[VIRT_PATH_BUF_SIZE];
    uint32_t pattern_len;
    bool     has_wildcard;
    bool     has_doublestar;
    uint32_t prefix_len;
    uint32_t suffix_len;
    char     literal_prefix[VIRT_PATH_BUF_SIZE];
    char     literal_suffix[VIRT_PATH_BUF_SIZE];
    uint32_t segment_count;
    struct {
        uint32_t start;
        uint32_t len;
        bool     is_wildcard;
        bool     is_starstar;
    } segments[64];
} VIRT_GlobPattern;

typedef struct VIRT_Watchdog {
    int          timer_fd;
    uint64_t     interval_ns;
    uint64_t     last_ping_ns;
    uint32_t     missed_pings;
    uint32_t     max_missed;
    bool         armed;
    bool         triggered;
    struct timespec deadline;
} VIRT_Watchdog;

typedef struct VIRT_TimingJitter {
    bool     enabled;
    uint32_t base_us;
    uint32_t range_us;
    uint64_t total_jitter_ns;
    uint32_t jitter_count;
    double   avg_jitter_ns;
    uint32_t max_jitter_us;
    uint32_t min_jitter_us;
} VIRT_TimingJitter;

typedef struct VIRT_KernelInfo {
    int    major;
    int    minor;
    int    patch;
    bool   has_user_notif;
    bool   has_continue;
    bool   has_tsync;
    bool   has_new_listener;
    bool   has_tsync_esrch;
    bool   has_log;
    bool   has_notif_sizes;
    int    features_mask;
    char   version_str[64];
    char   release_str[128];
} VIRT_KernelInfo;

typedef struct {
    char     hostname[256];
    uint16_t port;
    int      action;
    bool     has_port;
} VIRT_ConnectRule;

typedef struct VIRT_ProcessProfileInfo {
    char     name[VIRT_PROC_NAME_MAX];
    int      profile;
    int      uid;
    int      gid;
    bool     is_game;
    bool     is_browser;
    bool     is_banking;
    bool     is_debuggable;
    bool     has_anticheat;
    char     package_name[256];
    char     data_dir[VIRT_PATH_BUF_SIZE];
    char     se_info[256];
    uint32_t flags;
} VIRT_ProcessProfileInfo;

static const VIRT_SeccompFilterProfile DEFAULT_FILTER_PROFILES[] = {
    { __NR_openat,        VIRT_CAT_FILE_READ,  true,  "openat"        },
    { __NR_openat2,       VIRT_CAT_FILE_READ,  true,  "openat2"       },
    { __NR_readlinkat,    VIRT_CAT_FILE_READ,  true,  "readlinkat"    },
    { __NR_readlink,      VIRT_CAT_FILE_READ,  true,  "readlink"      },
    { __NR_newfstatat,    VIRT_CAT_FILE_META,  true,  "newfstatat"    },
    { __NR_statx,         VIRT_CAT_FILE_META,  true,  "statx"         },
    { __NR_faccessat,     VIRT_CAT_FILE_READ,  true,  "faccessat"     },
    { __NR_faccessat2,    VIRT_CAT_FILE_READ,  true,  "faccessat2"    },
    { __NR_getdents64,    VIRT_CAT_FILE_READ,  true,  "getdents64"    },
    { __NR_mmap,          VIRT_CAT_MEMORY,     true,  "mmap"          },
    { __NR_mprotect,      VIRT_CAT_MEMORY,     true,  "mprotect"      },
    { __NR_connect,       VIRT_CAT_NETWORK,    true,  "connect"       },
    { __NR_socket,        VIRT_CAT_NETWORK,    false, "socket"        },
    { __NR_ioctl,         VIRT_CAT_DEBUG,      false, "ioctl"         },
    { __NR_prctl,         VIRT_CAT_DEBUG,      true,  "prctl"         },
    { -1,                 VIRT_CAT_OTHER,      false, "terminator"    },
};

static const struct {
    int action;
    int errno_val;
    const char *name;
} ACTION_TABLE[] = {
    { VIRT_ACTION_ALLOW,         0,             "allow"          },
    { VIRT_ACTION_BLOCK_ENOENT,  ENOENT,        "block-enoent"   },
    { VIRT_ACTION_BLOCK_EACCES,  EACCES,        "block-eacces"   },
    { VIRT_ACTION_BLOCK_EPERM,   EPERM,         "block-eperm"    },
    { VIRT_ACTION_BLOCK_ENXIO,   ENXIO,         "block-enxio"    },
    { VIRT_ACTION_BLOCK_EIO,     EIO,           "block-eio"      },
    { VIRT_ACTION_BLOCK_EROFS,   EROFS,         "block-erofs"    },
    { VIRT_ACTION_PASS_THROUGH,  0,             "pass-through"   },
};

static const char *VIRT_CATEGORY_NAMES[VIRT_CAT_COUNT] = {
    "file_read", "file_write", "file_meta", "proc",
    "network", "memory", "exec", "debug", "other"
};

static const char *VIRT_MATCH_NAMES[VIRT_MATCH_COUNT] = {
    "exact", "prefix", "suffix", "substring",
    "glob", "regex", "always", "never"
};

static const char *VIRT_ACTION_NAMES[VIRT_ACTION_COUNT] = {
    "allow", "block-enoent", "block-eacces", "block-eperm",
    "block-enxio", "block-eio", "block-erofs",
    "redirect", "fake-content", "fake-empty",
    "fake-maps", "fake-status", "pass-through"
};

static const char *VIRT_HANDLER_STATE_NAMES[VIRT_HANDLER_STATE_COUNT] = {
    "uninitialized", "initializing", "running", "paused",
    "crashed", "shutdown"
};

static const char *VIRT_PROFILE_NAMES[VIRT_PROFILE_COUNT] = {
    "unknown", "game", "browser", "social",
    "payment", "banking", "store", "launcher",
    "system", "anticheat"
};

static const VIRT_Config VIRT_DEFAULT_CONFIG = {
    .config_path              = "/data/local/tmp/virtualizer/config.txt",
    .rules_path               = "",
    .rules_json_path          = "/data/local/tmp/virtualizer/rules.json",
    .fake_maps_path           = "/data/local/tmp/virtualizer/maps",
    .fake_status_path         = "/data/local/tmp/virtualizer/status",
    .enable_file_decoy        = false,
    .log_tag                  = "Virtualizer",
    .log_level                = VIRT_LOG_LEVEL_INFO,
    .filter_mode              = VIRT_FILTER_MODE_BPF_STATIC,
    .default_action           = VIRT_ACTION_PASS_THROUGH,
    .enable_stats             = true,
    .enable_cache             = true,
    .enable_watchdog          = true,
    .enable_anti_tamper       = true,
    .enable_proc_hiding       = true,
    .enable_fake_content      = true,
    .enable_timing_jitter     = false,
    .enable_thread_sync       = true,
    .enable_kernel_compat     = true,
    .enable_self_diagnostics  = true,
    .enable_event_ring        = true,
    .enable_trie_index        = true,
    .enable_latency_tracking  = true,
    .enable_per_syscall_stats = true,
    .enable_periodic_reporting = true,
    .enable_signal_safety     = true,
    .cache_size               = VIRT_MAX_CACHED_PATHS,
    .stats_window_sec         = 60,
    .watchdog_interval_sec    = 5,
    .max_rules                = VIRT_MAX_RULES,
    .handler_stack_size       = VIRT_HANDLER_STACK_SIZE,
    .notif_timeout_ms         = VIRT_NOTIF_FD_TIMEOUT_MS,
    .timing_jitter_us         = 0,
    .jitter_range_us          = 0,
    .reconnect_delay_ms       = 1000,
    .max_consecutive_errors   = 10,
    .max_event_ring_entries   = VIRT_EVENT_RING_SIZE,
};

static const char *VIRT_DEFAULT_BLOCKED_PATTERNS[] = {
    /* Only root/detection paths blocked.
     /proc paths are NOT blocked (would break apps). */
    "/su",
    "/su/su",
    "/magisk",
    "/sbin/.magisk",
    "/sbin/.magisk.img",
    "/sbin/magisk",
    "/sbin/magic_mask",
    "/sbin/su",
    "/data/adb",
    "/data/adb/magisk",
    "/data/adb/modules",
    "/data/adb/su",
    "/data/adb/service.d",
    "/data/adb/post-fs-data.d",
    "/data/adb/modules_update",
    "/data/adb/ksu",
    "/data/adb/ap",
    "/data/adb/modules/zygisk-virtualizer",
    "/data/adb/magisk.img",
    "/data/adb/magisk.db",
    "/system/bin/su",
    "/system/xbin/su",
    "/system/bin/debuggerd",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/app/Kingroot.apk",
    "/system/app/KingUser.apk",
    "/system/etc/init.d",
    "/system/etc/super.d",
    "/system/framework/core-libart.jar",
    "/system/lib64/libsupol.so",
    "/system/lib/libsupol.so",
    "/init.rc",
    "/init.super.rc",
    "/init.magisk.rc",
    "/persist/property",
    "/data/property",
    "/dbdata/property",
    "/cache/recovery",
    "/cache/magisk.log",
    "/dev/com.koushikdutta.superuser",
    "/dev/socket/zygote",
    "/dev/socket/zygote_secondary",
    "/dev/socket/ksu",
    "DexposedBridge",
    "xposed",
    "XposedBridge",
    "de.robv.android.xposed",
    "frida",
    "gum-js-loop",
    "frida-helper",
    "frida-server",
    "frida-agent",
    "libfrida",
    "libgadget",
    "frida-gadget",
    "frida-gadget.so",
    "com.saurik.substrate",
    "cydia",
    "substrate",
    "libsubstrate.so",
    "libsubstrated.so",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.topjohnwu.magisk",
    "com.kingroot.master",
    "com.kingo.root",
    "com.qihoo.permmgr",
    "com.dianxinos.superuser",
    "com.ramdroid.rootqueries",
    "com.topjohnwu.snet",
    "com.scottyab.rootbeer",
    "/proc/self/pagemap",
    "/proc/self/smaps",
    "/proc/self/smaps_rollup",
    "/proc/self/wchan",
    "/proc/self/io",
    "/proc/self/oom_score",
    "/proc/self/oom_score_adj",
    "/proc/self/mem",
    "/proc/self/personality",
    "/proc/self/stack",
    "/proc/self/syscall",
    "/proc/self/coredump_filter",
    "/proc/self/task/",
    "/sys/kernel/security/",
    "/sys/fs/selinux/",
    "/proc/self/mountinfo",
    "/proc/self/mounts",
    "/proc/self/exe",
    NULL,
};

static const char *VIRT_FAKE_MAPS_CONTENT[] = {
    "557e8000-558e9000 r-xp 00000000 fe:00 12345     /system/bin/app_process64",
    "558e9000-558ea000 r--p 00101000 fe:00 12345     /system/bin/app_process64",
    "558ea000-558ec000 rw-p 00102000 fe:00 12345     /system/bin/app_process64",
    "558ec000-558f0000 rw-p 00000000 00:00 0         [anon:.bss]",
    "7c000000-7c032000 r-xp 00000000 fe:00 67890     /system/lib64/linker64",
    "7c032000-7c034000 r--p 00031000 fe:00 67890     /system/lib64/linker64",
    "7c034000-7c038000 rw-p 00033000 fe:00 67890     /system/lib64/linker64",
    "7c038000-7c03d000 rw-p 00000000 00:00 0         [anon:linker_alloc]",
    "7c03d000-7c0a7000 r-xp 00000000 fe:00 67891     /system/lib64/libc.so",
    "7c0a7000-7c0ab000 r--p 00069000 fe:00 67891     /system/lib64/libc.so",
    "7c0ab000-7c0ac000 rw-p 0006d000 fe:00 67891     /system/lib64/libc.so",
    "7c0ac000-7c0b1000 rw-p 00000000 00:00 0         [anon:libc_malloc]",
    "7c0b1000-7c0d3000 r-xp 00000000 fe:00 67892     /system/lib64/libm.so",
    "7c0d3000-7c0d4000 r--p 00021000 fe:00 67892     /system/lib64/libm.so",
    "7c0d4000-7c0d5000 rw-p 00022000 fe:00 67892     /system/lib64/libm.so",
    "7c0d5000-7c0d7000 r-xp 00000000 fe:00 67893     /system/lib64/libdl.so",
    "7c0d7000-7c0d8000 r--p 00001000 fe:00 67893     /system/lib64/libdl.so",
    "7c0d8000-7c0d9000 rw-p 00002000 fe:00 67893     /system/lib64/libdl.so",
    "7c0d9000-7c153000 r-xp 00000000 fe:00 67894     /system/lib64/libandroid_runtime.so",
    "7c153000-7c159000 r--p 00079000 fe:00 67894     /system/lib64/libandroid_runtime.so",
    "7c159000-7c15e000 rw-p 0007f000 fe:00 67894     /system/lib64/libandroid_runtime.so",
    "7c15e000-7c192000 r-xp 00000000 fe:00 67895     /system/lib64/libc++.so",
    "7c192000-7c196000 r--p 00033000 fe:00 67895     /system/lib64/libc++.so",
    "7c196000-7c197000 rw-p 00037000 fe:00 67895     /system/lib64/libc++.so",
    "7c197000-7c202000 r-xp 00000000 fe:00 67896     /system/lib64/liblog.so",
    "7c202000-7c204000 r--p 0006a000 fe:00 67896     /system/lib64/liblog.so",
    "7c204000-7c205000 rw-p 0006c000 fe:00 67896     /system/lib64/liblog.so",
    "7c205000-7c23d000 r-xp 00000000 fe:00 67897     /system/lib64/libnativehelper.so",
    "7c23d000-7c240000 r--p 00037000 fe:00 67897     /system/lib64/libnativehelper.so",
    "7c240000-7c241000 rw-p 0003a000 fe:00 67897     /system/lib64/libnativehelper.so",
    "7c241000-7c251000 r-xp 00000000 fe:00 67898     /system/lib64/libz.so",
    "7c251000-7c252000 r--p 0000f000 fe:00 67898     /system/lib64/libz.so",
    "7c252000-7c253000 rw-p 00010000 fe:00 67898     /system/lib64/libz.so",
    "7c253000-7c28b000 r-xp 00000000 fe:00 67899     /system/lib64/libexpat.so",
    "7c28b000-7c28d000 r--p 00037000 fe:00 67899     /system/lib64/libexpat.so",
    "7c28d000-7c28e000 rw-p 00039000 fe:00 67899     /system/lib64/libexpat.so",
    "7c28e000-7c2b7000 r-xp 00000000 fe:00 67900     /system/lib64/libwilhelm.so",
    "7c2b7000-7c2b9000 r--p 00028000 fe:00 67900     /system/lib64/libwilhelm.so",
    "7c2b9000-7c2ba000 rw-p 0002a000 fe:00 67900     /system/lib64/libwilhelm.so",
    "7c2ba000-7c415000 r-xp 00000000 fe:00 67901     /system/lib64/libicuuc.so",
    "7c415000-7c426000 r--p 0015a000 fe:00 67901     /system/lib64/libicuuc.so",
    "7c426000-7c429000 rw-p 0016b000 fe:00 67901     /system/lib64/libicuuc.so",
    "7c429000-7c438000 r-xp 00000000 fe:00 67902     /system/lib64/libnativebridge.so",
    "7c438000-7c43a000 r--p 0000e000 fe:00 67902     /system/lib64/libnativebridge.so",
    "7c43a000-7c43b000 rw-p 00010000 fe:00 67902     /system/lib64/libnativebridge.so",
    "7c43b000-7d243000 r-xp 00000000 fe:00 67903     /system/framework/arm64/boot.oat",
    "7d243000-7d2ed000 r--p 00e07000 fe:00 67903     /system/framework/arm64/boot.oat",
    "7d2ed000-7d2f1000 rw-p 00eb1000 fe:00 67903     /system/framework/arm64/boot.oat",
    "7d2f1000-7d3f1000 rw-p 00000000 00:00 0         [anon:dalvik-alloc-space]",
    "7d3f1000-7d471000 rw-p 00000000 00:00 0         [anon:dalvik-main-space]",
    "7d471000-7d4f1000 rw-p 00000000 00:00 0         [anon:dalvik-non-moving-space]",
    "7d4f1000-7d4f2000 ---p 00000000 00:00 0         [anon:signal_page]",
    "7d4f2000-7d531000 rw-p 00000000 00:00 0         [anon:thread_db]",
    "7d531000-7d534000 r-xp 00000000 00:00 0         [vdso]",
    "7d534000-7d53e000 rw-p 00000000 00:00 0         [stack:1002]",
    "7d53e000-7d542000 rw-p 00000000 00:00 0         [stack:1003]",
    "7d542000-7d546000 rw-p 00000000 00:00 0         [stack:1004]",
    "7de00000-7de04000 rw-p 00000000 00:00 0         [anon:scudo:primary]",
    "7de04000-7de31000 rw-p 00000000 00:00 0         [anon:scudo:secondary]",
    "7de31000-7df00000 rw-p 00000000 00:00 0         [anon:scudo:metadata]",
    "7e000000-7f000000 rw-p 00000000 00:00 0         [anon:dalvik-jit-code-cache]",
    "7ffbe000-7ffe0000 rw-p 00000000 00:00 0         [stack]",
    "7ffe0000-7ffe1000 r-xp 00000000 00:00 0         [vdso]",
    NULL,
};

static const char *VIRT_FAKE_STATUS_CONTENT[] = {
    "Name:   app_process64",
    "State:  S (sleeping)",
    "Tgid:   12345",
    "Ngid:   0",
    "Pid:    12345",
    "PPid:   1",
    "TracerPid:      0",
    "Uid:   10123   10123   10123   10123",
    "Gid:   10123   10123   10123   10123",
    "FDSize:        128",
    "Groups:        3001 9997 20123",
    "NStgid: 12345",
    "NSpid:  12345",
    "NSpgid: 12345",
    "NSsid:  12345",
    "VmPeak:        2345678 kB",
    "VmSize:        2345678 kB",
    "VmLck:         0 kB",
    "VmPin:         0 kB",
    "VmHWM:         345678 kB",
    "VmRSS:         345678 kB",
    "RssAnon:       310000 kB",
    "RssFile:        35678 kB",
    "RssShmem:       0 kB",
    "VmData:        567890 kB",
    "VmStk:         132 kB",
    "VmExe:         12 kB",
    "VmLib:         78901 kB",
    "VmPTE:         789 kB",
    "VmSwap:        0 kB",
    "HugetlbPages:  0 kB",
    "CoreDumping:   0",
    "THP_enabled:   1",
    "Threads:       18",
    "SigQ:   0/24680",
    "SigPnd: 0000000000000000",
    "ShdPnd: 0000000000000000",
    "SigBlk: 0000000000001204",
    "SigIgn: 0000000000001006",
    "SigCgt: 00000001800044e7",
    "CapInh: 0000000000000000",
    "CapPrm: 0000000000000000",
    "CapEff: 0000000000000000",
    "CapBnd: 0000000000000000",
    "CapAmb: 0000000000000000",
    "NoNewPrivs:     1",
    "Seccomp:        0",
    "Speculation_Store_Bypass:       thread vulnerable",
    "SpeculationIndirectBranch:      always enabled",
    "Cpus_allowed:   ff",
    "Cpus_allowed_list:      0-7",
    "Mems_allowed:   1",
    "Mems_allowed_list:      0",
    "voluntary_ctxt_switches:        18456",
    "nonvoluntary_ctxt_switches:     3241",
    NULL,
};

static int __attribute__((unused)) virterror_from_errno(void) {
    switch (errno) {
        case ENOMEM: return VIRT_ERR_NOMEM;
        case EINVAL: return VIRT_ERR_INVAL;
        case ENODEV: return VIRT_ERR_NODEV;
        case ENOSYS: return VIRT_ERR_NOSYS;
        case EAGAIN: return VIRT_ERR_AGAIN;
        case EBUSY:  return VIRT_ERR_BUSY;
        case EPERM:  return VIRT_ERR_PERM;
        case EOPNOTSUPP: return VIRT_ERR_NOTSUP;
        case ENOENT: return VIRT_ERR_NOENT;
        case EEXIST: return VIRT_ERR_EXIST;
        case EINTR:  return VIRT_ERR_INTR;
        case ETIMEDOUT: return VIRT_ERR_TIMEOUT;
        case EOVERFLOW: return VIRT_ERR_OVERFLOW;
        case ECANCELED: return VIRT_ERR_CANCELED;
        case EMFILE:  return VIRT_ERR_LIMIT;
        case ENFILE:  return VIRT_ERR_LIMIT;
        case EDEADLK: return VIRT_ERR_DEADLK;
        default: return VIRT_ERR_GENERIC;
    }
}

static inline uint64_t virt_gettime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline uint64_t virt_gettime_us(void) {
    return virt_gettime_ns() / 1000ULL;
}

static inline uint64_t virt_gettime_ms(void) {
    return virt_gettime_ns() / 1000000ULL;
}

static inline uint64_t virt_gettime_realtime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline bool virt_is_syscall_intercepted(int nr) {
    switch (nr) {
        case __NR_openat:
        case __NR_openat2:
        case __NR_readlinkat:
        case __NR_readlink:
        case __NR_newfstatat:
        case __NR_statx:
        case __NR_faccessat:
        case __NR_faccessat2:
        case __NR_getdents64:
        case __NR_mmap:
        case __NR_mprotect:
        case __NR_connect:
            return true;
        default:
            return false;
    }
}

static inline const char *virt_syscall_name(int nr) {
    switch (nr) {
        case __NR_openat:     return "openat";
        case __NR_openat2:    return "openat2";
        case __NR_readlinkat: return "readlinkat";
        case __NR_readlink:   return "readlink";
        case __NR_newfstatat: return "newfstatat";
        case __NR_statx:      return "statx";
        case __NR_faccessat:  return "faccessat";
        case __NR_faccessat2: return "faccessat2";
        case __NR_getdents64: return "getdents64";
        case __NR_mmap:       return "mmap";
        case __NR_mprotect:   return "mprotect";
        case __NR_connect:    return "connect";
        case __NR_socket:     return "socket";
        case __NR_ioctl:      return "ioctl";
        case __NR_prctl:      return "prctl";
        case __NR_clone3:     return "clone3";
        case __NR_clone:      return "clone";
        case __NR_exit_group: return "exit_group";
        case __NR_exit:       return "exit";
#if defined(__NR_getdents) && __NR_getdents != __NR_getdents64
        case __NR_getdents:   return "getdents";
#endif
        case __NR_fsync:      return "fsync";
        case __NR_pread64:    return "pread64";
        case __NR_pwrite64:   return "pwrite64";
        case __NR_nanosleep:  return "nanosleep";
        case __NR_clock_gettime: return "clock_gettime";
        case __NR_getpid:     return "getpid";
        case __NR_gettid:     return "gettid";
        case __NR_munmap:     return "munmap";
        case __NR_madvise:    return "madvise";
        case __NR_fstatfs:    return "fstatfs";
        case __NR_statfs:     return "statfs";
        case __NR_fcntl:      return "fcntl";
        case __NR_dup3:       return "dup3";
        default:              return "unknown";
    }
}

static inline int virt_errno_for_action(int action) {
    for (size_t i = 0; i < ARRAY_COUNT(ACTION_TABLE); i++) {
        if (ACTION_TABLE[i].action == action)
            return -ACTION_TABLE[i].errno_val;
    }
    return -ENOENT;
}

static inline bool virt_str_empty(const char *s) {
    return !s || !s[0];
}

static inline bool virt_mem_is_zero(const void *ptr, size_t len) {
    const unsigned char *p = (const unsigned char *)ptr;
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0) return false;
    }
    return true;
}

static inline uint32_t virt_hash_djb2(const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    uint32_t hash = 5381;
    for (size_t i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + (uint32_t)p[i];
    return hash;
}

static inline uint32_t virt_hash_fnv1a(const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint32_t)p[i];
        hash *= 16777619U;
    }
    return hash;
}

static inline pid_t virt_gettid(void) {
    return (pid_t)syscall(__NR_gettid);
}

static inline pid_t virt_getpid(void) {
    return (pid_t)syscall(__NR_getpid);
}

static inline int virt_getcpu(unsigned *cpu, unsigned *node) {
    return (int)syscall(__NR_getcpu, cpu, node, NULL);
}

static inline void virt_nanosleep_us(uint64_t us) {
    struct timespec ts = {
        .tv_sec = (time_t)(us / 1000000ULL),
        .tv_nsec = (long)((us % 1000000ULL) * 1000ULL),
    };
    nanosleep(&ts, NULL);
}

static inline void virt_nanosleep_ns(uint64_t ns) {
    struct timespec ts = {
        .tv_sec = (time_t)(ns / 1000000000ULL),
        .tv_nsec = (long)(ns % 1000000000ULL),
    };
    nanosleep(&ts, NULL);
}

int virt_trie_insert(const char *path, int action, uint32_t priority);
int virt_trie_lookup(const char *path, size_t path_len, int *out_action);
int virt_trie_build_default(void);
void virt_trie_destroy(void);
uint32_t virt_trie_get_node_count(void);

void virt_bloom_add(const char *pattern);
int virt_bloom_check(const char *str, uint32_t len);

int virt_glob_compile(const char *pattern, VIRT_GlobPattern *out);
bool virt_glob_match(const VIRT_GlobPattern *gp, const char *str, size_t len);
bool virt_path_match(const char *path, size_t path_len,
                     const char *pattern, int match_type);
int virt_config_load(const char *path, VIRT_Config *cfg);
int virt_config_validate(VIRT_Config *cfg);
int virt_run_self_test(void);
int virt_config_generate_default(const char *path);
int virt_stats_init(VIRT_SyscallStats *stats);
int virt_stats_record(VIRT_SyscallStats *stats, int syscall,
                      int action, uint64_t latency);
int virt_stats_snapshot(const VIRT_SyscallStats *stats,
                        char *buf, size_t buf_size);
int virt_proc_hider_init(VIRT_ProcHiderState *state);
int virt_proc_hider_add_fd(VIRT_ProcHiderState *state, int fd);
int virt_proc_hider_remove_fd(VIRT_ProcHiderState *state, int fd);
int virt_proc_hider_add_pid(VIRT_ProcHiderState *state, pid_t pid);
int virt_proc_hider_remove_pid(VIRT_ProcHiderState *state, pid_t pid);
int virt_proc_hider_add_tid(VIRT_ProcHiderState *state, pid_t tid);
int virt_proc_hider_check_fd_path(VIRT_ProcHiderState *state, const char *path,
                                   uint32_t path_len);
int virt_proc_hider_filter_dirents(VIRT_ProcHiderState *state,
                                    const char *dirents, uint32_t dirents_len,
                                    char *out, uint32_t *out_len);
int virt_cache_lookup(VIRT_CacheEntry *cache, uint32_t cache_count,
                      const char *path, uint32_t path_len);
int virt_cache_insert(VIRT_CacheEntry *cache, uint32_t *cache_count,
                      uint32_t cache_max, const char *path,
                      uint32_t path_len, bool sensitive, int action);
int virt_cache_invalidate(VIRT_CacheEntry *cache, uint32_t *cache_count,
                          const char *path);
int virt_cache_flush(VIRT_CacheEntry *cache, uint32_t *cache_count);
int virt_rules_add(VIRT_Rule *rules, uint32_t *rule_count,
                   uint32_t max_rules, const VIRT_Rule *rule);
int virt_rules_remove(VIRT_Rule *rules, uint32_t *rule_count,
                      uint32_t index);
int virt_rules_lookup(const VIRT_Rule *rules, uint32_t rule_count,
                      const char *path, uint32_t path_len,
                      int *out_action);
int virt_rules_sort(VIRT_Rule *rules, uint32_t rule_count);
int virt_rules_load_defaults(VIRT_Rule *rules, uint32_t *rule_count,
                             uint32_t max_rules);
int virt_rules_load_json(const char *filepath, VIRT_Rule *rules,
                         uint32_t *rule_count, uint32_t max_rules);
int virt_rules_count_by_action(const VIRT_Rule *rules, uint32_t rule_count,
                               int action);
int virt_rules_count_by_category(const VIRT_Rule *rules, uint32_t rule_count,
                                 int category);
int virt_anti_tamper_init(VIRT_AntiTamperState *state);
int virt_anti_tamper_check(VIRT_AntiTamperState *state);
int virt_anti_tamper_detect_debugger(void);
int virt_anti_tamper_detect_ptrace(void);
int virt_anti_tamper_detect_hook(void);
int virt_anti_tamper_check_memory(VIRT_AntiTamperState *state);
int virt_anti_tamper_check_code(VIRT_AntiTamperState *state);
int virt_seccomp_get_features(int *out_features);
int virt_seccomp_install_static(VIRT_Config *cfg,
                                 VIRT_SeccompFilterProfile *profiles,
                                 int profile_count);
int virt_seccomp_install_static_default(VIRT_Config *cfg);
int virt_seccomp_create_decoy_files(void);
bool virt_decoy_file_create(const char *path, const char *const *lines);
extern const char *VIRT_DECOY_MAPS_PATH;
extern const char *VIRT_DECOY_STATUS_PATH;
extern const char *VIRT_DECOY_CMDLINE_PATH;
extern const char *VIRT_DECOY_ENVIRON_PATH;
int virt_seccomp_read_path(struct seccomp_notif *req,
                             char *buf, size_t buf_size,
                             uint64_t path_addr);
void virt_handle_prctl(struct seccomp_notif *req,
                       struct seccomp_notif_resp *resp);
long virt_seccomp_execute_syscall(struct seccomp_notif *req);
int virt_seccomp_handler_loop(void *arg);
int virt_seccomp_check_notif_id_valid(int notify_fd, uint64_t id);
uint64_t virt_seccomp_get_event_count(void);
uint64_t virt_seccomp_get_error_count(void);
uint64_t virt_seccomp_get_continue_fallback_count(void);
uint64_t virt_seccomp_get_avg_latency_ns(void);
bool virt_seccomp_has_continue(void);
uint32_t virt_seccomp_get_active_listeners(void);
uint32_t virt_seccomp_get_total_listeners(void);
int virt_watchdog_init(VIRT_Watchdog *wd, uint64_t interval_ns,
                        uint32_t max_misses);
int virt_watchdog_arm(VIRT_Watchdog *wd);
int virt_watchdog_disarm(VIRT_Watchdog *wd);
int virt_watchdog_ping(VIRT_Watchdog *wd);
int virt_watchdog_check(VIRT_Watchdog *wd);
int virt_health_check(VIRT_HealthStatus *status);
int virt_health_report(const VIRT_HealthStatus *status,
                        char *buf, size_t buf_size);
int virt_jitter_apply(VIRT_TimingJitter *jitter);
int virt_thread_monitor_init(void);
int virt_thread_monitor_register(pid_t tid, const char *name);
int virt_thread_monitor_update(pid_t tid, bool has_seccomp);
int virt_thread_monitor_get_count(void);
int virt_thread_monitor_get_info(int index, VIRT_ThreadMonitor *out);
int virt_event_ring_init(VIRT_EventRing *ring);
int virt_event_ring_push(VIRT_EventRing *ring, const VIRT_SyscallEvent *evt);
int virt_event_ring_pop(VIRT_EventRing *ring, VIRT_SyscallEvent *evt);
int virt_event_ring_peek(const VIRT_EventRing *ring, uint32_t offset,
                          VIRT_SyscallEvent *evt);
uint32_t virt_event_ring_count(const VIRT_EventRing *ring);
int virt_kernel_probe(VIRT_KernelInfo *info);
int virt_process_profile_detect(VIRT_ProcessProfileInfo *info);
int virt_init_shadow_library(const char *lib_name);
const ShadowLibraryMirror *virt_get_shadow_mirror(void);
int virt_safe_strncpy(char *dst, const char *src, size_t dst_size);
int virt_safe_strcat(char *dst, const char *src, size_t dst_size);
void virt_print_hexdump(const void *data, size_t len, const char *label);

int virt_add_connect_rule(const char *hostname, uint16_t port, int action);
int virt_check_connect(const char *hostname, uint16_t port);
int virt_init_default_connect_rules(void);

int virt_detect_environment(void);
int virt_check_environment_support(void);

int virt_anti_tamper_loop(void *arg);
int virt_spoof_uname(struct utsname *uts);
int virt_is_safe_mode(void);
void virt_log_event(const char *event_type, const char *path, int action);
int virt_stats_dump_to_file(const char *filepath, const VIRT_SyscallStats *stats);
int virt_reload_rules(VIRT_Rule *rules, uint32_t *rule_count, uint32_t max_rules);

int virt_mask_cmdline(const char *input, uint32_t input_len,
                      char *output, uint32_t output_size);
int virt_mask_environ(char *buffer, uint32_t buffer_size);

#endif /* VIRTUALIZER_H */