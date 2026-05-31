/*
 * SPDX-License-Identifier: MIT
 *
 * zygisk_entry.cpp - Universal Syscall Virtualization Framework
 * Zygisk Module Entry Point
 *
 * Architecture Overview
 * =====================
 * This module integrates with Magisk Zygisk to provide per-process
 * system call virtualization via SECCOMP_RET_USER_NOTIF.
 *
 * ARM64 Syscall Convention:
 *   x8  = syscall number (NR)
 *   x0-x5 = arguments 0-5
 *   x0  = return value on exit (negative = errno)
 *
 * Syscall Numbers (ARM64):
 *   faccessat    = 48   (int dirfd, const char *path, int mode, int flags)
 *   openat       = 56   (int dirfd, const char *path, int flags, mode_t mode)
 *   readlinkat   = 78   (int dirfd, const char *path, char *buf, size_t bufsiz)
 *   newfstatat   = 79   (int dirfd, const char *path, struct stat *buf, int flag)
 *   readlink     = 89   (const char *path, char *buf, size_t bufsiz)
 *   getdents64   = 61   (int fd, struct linux_dirent64 *dirp, size_t count)
 *   connect      = 203  (int fd, const struct sockaddr *addr, socklen_t addrlen)
 *   mmap         = 222  (void *addr, size_t len, int prot, int flags, int fd, off_t off)
 *   statx        = 291  (int dirfd, const char *path, int flags, unsigned mask, struct statx *buf)
 *   openat2      = 293  (int dirfd, const char *path, struct open_how *how, size_t usize)
 *   faccessat2   = 439  (int dirfd, const char *path, int mode, int flags)
 *
 * Seccomp User Notification (Linux 5.0+):
 *   The SECCOMP_RET_USER_NOTIF action causes the kernel to:
 *   1. Block the calling task in an interruptible wait
 *   2. Create a notification event on the listener fd
 *   3. The listener receives struct seccomp_notif via ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV)
 *   4. The listener responds via ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND) with:
 *      - resp.error = -errno to make syscall fail with that error
 *      - resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE to let syscall proceed (kernel 5.11+)
 *
 * BPF Filter Architecture (seccomp_data offsets):
 *   offset 0:  int nr              (4 bytes, syscall number)
 *   offset 4:  __u32 arch          (4 bytes, AUDIT_ARCH_AARCH64 = 0xC00000B7)
 *   offset 8:  __u64 instruction_pointer  (8 bytes)
 *   offset 16: __u64 args[0-5]     (48 bytes, syscall arguments)
 *
 * seccomp_notif layout (struct):
 *   offset 0:  __u64 id            (8 bytes, unique notification id)
 *   offset 8:  __u32 pid           (4 bytes, tid of blocked task)
 *   offset 12: __u32 flags         (4 bytes, flags)
 *   offset 16: struct seccomp_data (80 bytes, see above)
 *
 * seccomp_notif_resp layout (struct):
 *   offset 0:  __u64 id            (8 bytes, matches notification id)
 *   offset 8:  __s64 val           (8 bytes, return value)
 *   offset 16: __s32 error         (4 bytes, negative errno or 0)
 *   offset 20: __u32 flags         (4 bytes, CONTINUE flag)
 *
 * Process Lifecycle:
 *   1. onLoad() - Called once per module during zygote init
 *   2. preAppSpecialize() - Called in forked child before app init
 *      a. Extract process name from Zygisk args
 *      b. Filter system processes (system_server, com.android.systemui)
 *      c. Install seccomp BPF filter via SECCOMP_SET_MODE_FILTER
 *      d. Spawn detached notification handler thread
 *   3. postAppSpecialize() - Called after app initialization
 *
 * Thread Safety:
 *   - BPF filter installed before handler thread creation
 *   - Handler thread is the sole consumer of the notification fd
 *   - Global state (g_*) accessed atomically
 *   - Each app process has exactly one handler thread
 *
 * Error Recovery:
 *   - Failed seccomp installation: app continues unimpeded
 *   - Handler thread crash: notification fd closed, kernel unblocks waiting tasks
 *   - Kernel doesn't support CONTINUE: automatic fallback to direct re-execution
 *   - notify_fd ENOENT: target process has exited, handler exits cleanly
 *
 * Integration Points:
 *   virtualizer.h   - Shared types, constants, API declarations
 *   seccomp_engine.cpp - BPF filter management, notification handling
 *   virtualizer_core.cpp - Path matching, rules, stats, anti-tamper
 */

#include "virtualizer.h"
#include "zygisk.hpp"
#include <jni.h>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <pthread.h>

#define VIRT_ZYGISK_LOG_TAG "ZygiskVirtualizer"

#define VIRT_ZYGISK_LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, VIRT_ZYGISK_LOG_TAG, __VA_ARGS__)
#define VIRT_ZYGISK_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  VIRT_ZYGISK_LOG_TAG, __VA_ARGS__)
#define VIRT_ZYGISK_LOGW(...) __android_log_print(ANDROID_LOG_WARN,  VIRT_ZYGISK_LOG_TAG, __VA_ARGS__)
#define VIRT_ZYGISK_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, VIRT_ZYGISK_LOG_TAG, __VA_ARGS__)

static const char *VIRT_EXCLUDED_PROCESSES[] = {
    "com.google.android.gms.unstable",
    "com.google.android.gms.persistent",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.chrome",
    "com.android.chrome:sandboxed_process",
    NULL,
};

static bool g_virt_initialized = false;
static uint32_t g_virt_module_load_count = 0;
static uint32_t g_virt_app_count = 0;
static uint32_t g_virt_system_skip_count = 0;
static uint32_t g_virt_excluded_skip_count = 0;
static uint32_t g_virt_fail_count = 0;

static bool virt_is_zygote_process(void) {
    uid_t uid = getuid();
    /* UID > 0 and < 10000: system process, not a zygote context */
    if (uid > 0 && uid < 10000) return false;
    /* UID >= 10000: definite app process */
    if (uid >= 10000) return false;

    /* UID == 0: we are root. On standard Magisk, this is the real
     * zygote. On Kitsune, EVERY forked child also has UID 0 during
     * onLoad. Use a file-based marker to disambiguate: the first
     * process (real zygote) creates the file; subsequent processes
     * (forked children on Kitsune) see it and know they aren't the
     * zygote. */
    static const char *marker = "/data/local/tmp/.virt_zygote_marker";
    struct stat st;
    if (stat(marker, &st) == 0) {
        /* File exists: we are NOT the first init */
        return false;
    }
    /* File doesn't exist: try to create it atomically */
    int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd >= 0) {
        close(fd);
        return true;  /* First init = real zygote */
    }
    /* Creation failed (race with another process): we are not the zygote */
    return false;
}

/* System UIDs: UID 0 = root/zygote, UIDs 1-9999 = system processes */
static bool virt_is_system_process_by_uid(uid_t uid) {
    return uid > 0 && uid < 10000;
}

static bool virt_is_in_list(const char *name, const char **list) {
    if (!name || !name[0] || !list) return false;
    for (size_t i = 0; list[i] != NULL; i++) {
        if (strcmp(name, list[i]) == 0) return true;
    }
    return false;
}

static bool virt_is_zygote_cmdline(const char *name) {
    if (!name || !name[0]) return false;
    if (strstr(name, "_zygote") != NULL) return true;
    if (strstr(name, "webview_zygote") != NULL) return true;
    return false;
}

static bool virt_is_excluded_process(const char *name) {
    if (!name || !name[0]) return false;
    if (virt_is_zygote_cmdline(name)) return true;
    if (strstr(name, "com.android.chrome:sandboxed_process") != NULL ||
        strstr(name, "com.google.android.webview:sandboxed_process") != NULL ||
        strstr(name, ":isolation") != NULL ||
        strstr(name, ":isolated") != NULL) {
        return true;
    }
    return virt_is_in_list(name, VIRT_EXCLUDED_PROCESSES);
}

static void virt_get_process_name(char *buf, size_t buf_size) {
    buf[0] = '\0';
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) {
        VIRT_ZYGISK_LOGD("get_process_name: cannot open cmdline");
        return;
    }
    ssize_t n = read(fd, buf, buf_size - 1);
    close(fd);
    if (n <= 0) {
        buf[0] = '\0';
        return;
    }
    buf[n] = '\0';
    /* cmdline is NUL-separated; first entry is the process name */
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == '\0') { buf[i] = '/'; break; }
    }
}

static void *virt_seccomp_handler_launcher(void *arg);

static void __attribute__((unused)) virt_log_app_stats(void) {
    VIRT_ZYGISK_LOGI(
        "Global stats: loaded=%u apps=%u skipped_sys=%u skipped_excl=%u failed=%u",
        g_virt_module_load_count,
        g_virt_app_count,
        g_virt_system_skip_count,
        g_virt_excluded_skip_count,
        g_virt_fail_count
    );
}

class VirtualizerZygiskModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        (void)api;
        (void)env;
        g_virt_module_load_count++;
        g_virt_initialized = true;

        int features = 0;
        virt_seccomp_get_features(&features);

        int rt_env = virt_detect_environment();
        VIRT_ZYGISK_LOGI("Runtime environment: %s",
            rt_env == VIRT_ENV_MAGISK ? "Magisk" :
            rt_env == VIRT_ENV_KERNELSU ? "KernelSU" :
            rt_env == VIRT_ENV_APATCH ? "APatch" : "Unknown");

        if (virt_is_safe_mode()) {
            VIRT_ZYGISK_LOGW("Safe mode detected — disabling seccomp virtualization");
            return;
        }

        VIRT_ZYGISK_LOGI(
            "Virtualizer v%s loaded (load_count=%u, kernel_features=0x%x, env=%s)",
            VIRTUALIZER_VERSION,
            g_virt_module_load_count,
            features,
            VIRT_SUPPORTED_ENVS
        );

#if VIRT_DEBUG_MODE
        VIRT_ZYGISK_LOGI("DEBUG_MODE enabled, running self-test");
        int self_test_failed = virt_run_self_test();
        if (self_test_failed > 0) {
            VIRT_ZYGISK_LOGW("Self-test: %d tests failed", self_test_failed);
        } else {
            VIRT_ZYGISK_LOGI("Self-test: all tests passed");
        }
#endif

        if (!(features & 1)) {
            VIRT_ZYGISK_LOGW("SECCOMP_RET_USER_NOTIF not available, virtualization disabled");
            return;
        }
        if (!(features & 2)) {
            VIRT_ZYGISK_LOGW("SECCOMP_FILTER_FLAG_NEW_LISTENER not available, virtualization disabled");
            return;
        }

        uid_t uid = getuid();
        char proc_name[VIRT_PROC_NAME_MAX];
        virt_get_process_name(proc_name, sizeof(proc_name));

        /* Skip system and excluded processes first */
        if (virt_is_system_process_by_uid(uid)) {
            VIRT_ZYGISK_LOGI("Skipping system process (uid=%u): %s", uid, proc_name);
            g_virt_system_skip_count++;
            return;
        }
        if (virt_is_excluded_process(proc_name)) {
            VIRT_ZYGISK_LOGI("Skipping excluded process: %s", proc_name);
            g_virt_excluded_skip_count++;
            return;
        }
        if (uid >= 10000 && uid < 100000) {
            /* App process: install seccomp */
            goto install_seccomp;
        }

        /* UID == 0: check if we're the real zygote or a forked child */
        if (virt_is_zygote_process()) {
            VIRT_ZYGISK_LOGI("Real zygote detected (uid=0, first init), deferring");
            return;
        }

install_seccomp:
        VIRT_ZYGISK_LOGI("onLoad: name=%s uid=%u", proc_name, uid);
        g_virt_app_count++;

        /* Create decoy files BEFORE seccomp install — the handler thread
         * inherits the filter and would deadlock trying to create them. */
        virt_seccomp_create_decoy_files();

        VIRT_Config cfg = VIRT_DEFAULT_CONFIG;
        int fd = virt_seccomp_install_static_default(&cfg);
        if (fd < 0) {
            VIRT_ZYGISK_LOGE("seccomp install failed for %s: %s", proc_name, strerror(errno));
            g_virt_fail_count++;
            return;
        }

        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        size_t stack_size = (size_t)VIRT_CLAMP(
            (int)cfg.handler_stack_size, 65536, 8388608
        );
        pthread_attr_setstacksize(&attr, stack_size);
        int tret = pthread_create(&thread, &attr,
                                  virt_seccomp_handler_launcher,
                                  (void *)(intptr_t)fd);
        pthread_attr_destroy(&attr);
        if (tret != 0) {
            VIRT_ZYGISK_LOGE("Handler thread creation failed for %s: %s",
                             proc_name, strerror(tret));
            close(fd);
            g_virt_fail_count++;
            return;
        }

        virt_seccomp_start_handler_monitor(fd);

        VIRT_ZYGISK_LOGI("Virtualization active for %s (fd=%d, stack=%zuKB)",
                         proc_name, fd, stack_size / 1024);
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        (void)args;
        if (g_virt_app_count > 0) return;
        /* For standard Magisk: onLoad skipped (zygote UID=0),
         * preAppSpecialize runs in child (app UID). */
        uid_t uid = getuid();
        if (virt_is_system_process_by_uid(uid)) return;
        if (uid < 10000) return;

        char proc_name[VIRT_PROC_NAME_MAX];
        virt_get_process_name(proc_name, sizeof(proc_name));
        if (virt_is_excluded_process(proc_name)) return;

        VIRT_ZYGISK_LOGI("preAppSpecialize: name=%s uid=%u", proc_name, uid);

        /* Apply package-specific profile if one exists */
        VIRT_Config cfg = VIRT_DEFAULT_CONFIG;
        VIRT_PackageProfile *profile = virt_config_find_package_profile(&cfg, proc_name);
        if (profile) {
            VIRT_ZYGISK_LOGI("Applying profile for %s (flags=0x%04x)",
                             proc_name, profile->profile_flags);
            if (profile->profile_flags & VIRT_PROFILE_STRICT) {
                cfg.filter_mode = VIRT_FILTER_MODE_BPF_DYNAMIC;
            }
            if (profile->profile_flags & VIRT_PROFILE_AGGRESSIVE) {
                cfg.filter_mode = VIRT_FILTER_MODE_BPF_DYNAMIC;
                cfg.enable_anti_tamper = true;
                cfg.enable_self_diagnostics = true;
            }
            if (profile->profile_flags & VIRT_PROFILE_STEALTH) {
                cfg.enable_timing_jitter = true;
                cfg.enable_proc_hiding = true;
            }
            if (profile->profile_flags & VIRT_PROFILE_LEGACY) {
                cfg.enable_kernel_compat = true;
                cfg.enable_thread_sync = false;
            }
            if (profile->profile_flags & VIRT_PROFILE_GAME) {
                cfg.cache_size = VIRT_MAX_CACHED_PATHS;
            }
            if (profile->profile_flags & VIRT_PROFILE_ANTI_CHEAT) {
                cfg.enable_anti_tamper = true;
                cfg.enable_self_diagnostics = true;
                cfg.enable_latency_tracking = true;
            }
        }

        virt_seccomp_create_decoy_files();

        int fd = virt_seccomp_install_static_default(&cfg);
        if (fd < 0) { g_virt_fail_count++; return; }

        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        size_t stack_size = (size_t)VIRT_CLAMP((int)cfg.handler_stack_size, 65536, 8388608);
        pthread_attr_setstacksize(&attr, stack_size);
        if (pthread_create(&thread, &attr, virt_seccomp_handler_launcher, (void *)(intptr_t)fd) != 0) {
            close(fd);
            g_virt_fail_count++;
            return;
        }
        pthread_attr_destroy(&attr);
        g_virt_app_count++;

        virt_seccomp_start_handler_monitor(fd);

        VIRT_ZYGISK_LOGI("Virtualization active for %s (fd=%d)", proc_name, fd);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        (void)args;
    }
};

static void *virt_seccomp_handler_launcher(void *arg) {
    int fd = (int)(intptr_t)arg;
    VIRT_ZYGISK_LOGI("Handler thread started (fd=%d)", fd);
    virt_seccomp_handler_loop((void *)(intptr_t)fd);
    VIRT_ZYGISK_LOGI("Handler thread exiting (fd=%d)", fd);
    return NULL;
}

REGISTER_ZYGISK_MODULE(VirtualizerZygiskModule)

/*
 * Implementation Notes
 * ====================
 *
 * [BPF Filter Design]
 * The BPF filter uses a directed acyclic graph structure:
 *
 *   [0] LD arch (offset 4)
 *   [1] JEQ AARCH64 -> skip 1, fall through to [2]
 *   [2] RET ALLOW (non-AARCH64)
 *   [3] LD syscall nr (offset 0)
 *   [4-12] JEQ chain for each target syscall
 *   [N] RET ALLOW (no match)
 *   [N+1] RET USER_NOTIF (match)
 *
 * The jump offsets in the JEQ instructions are computed as:
 *   jt = (number_of_remaining_checks) + 1
 * This ensures all unmatched checks are skipped in one jump.
 *
 * [Notification Lifecycle]
 * 1. App thread calls e.g. openat("/proc/self/maps", ...)
 * 2. Kernel BPF filter returns SECCOMP_RET_USER_NOTIF
 * 3. Kernel blocks app thread, creates notification event
 * 4. Handler thread receives event via ioctl NOTIF_RECV
 * 5. Handler reads path via process_vm_readv
 * 6. Handler resolves rule: match /proc/self/maps -> BLOCK_ENOENT
 * 7. Handler responds with resp.error = -ENOENT
 * 8. Kernel unblocks app thread, openat returns -1, errno = ENOENT
 *
 * [Path Virtualization Strategy]
 * Paths are categorized and handled with specific actions:
 *   PROC paths:  /proc/self/maps, /proc/self/status -> FAKE_CONTENT or ENOENT
 *   ROOT paths:  /su, /magisk, /data/adb -> ENOENT
 *   HOOK paths:  frida, xposed, substrate -> ENOENT
 *   Other paths: pass through (CONTINUE) or direct re-execution
 *
 * [Kernel Compatibility]
 * Kernel 5.0:    SECCOMP_RET_USER_NOTIF available
 * Kernel 5.11:   SECCOMP_USER_NOTIF_FLAG_CONTINUE available
 * Kernel 5.0-5.10: Direct re-execution fallback
 *   The handler re-executes the syscall and returns the result.
 *   For readlinkat/newfstatat/statx: results written via process_vm_writev
 *
 * [Anti-Detection Measures]
 * - Zero ptrace usage (no PTRACE_TRACEME, no PTRACE_SYSCALL)
 * - Handler thread named "seccomp-virt" (not suspicious)
 * - Timing jitter option to prevent latency-based detection
 * - Fake /proc/self/maps content generation
 * - Fake /proc/self/status with TracerPid = 0
 * - Cache-based resolution for O(1) path lookup after first miss
 *
 * [Thread Model]
 * Main thread (app):      Runs normally, seccomp-filtered
 * Handler thread:         ioctl wait loop, no seccomp filter
 * Filter applies:         Per-thread (SECCOMP_FILTER_FLAG_TSYNC optional)
 *   Without TSYNC:        Only main thread is filtered
 *   With TSYNC:           All threads (past and future) are filtered
 *
 * [File Descriptor Management]
 * The notification fd is:
 * - Created by seccomp() syscall with O_CLOEXEC
 * - Owned exclusively by the handler thread
 * - Not visible in the app's fd table (handled by proc virtualizer)
 * - Automatically closed when handler thread exits
 * - Automatically invalidated by kernel when target process exits
 */