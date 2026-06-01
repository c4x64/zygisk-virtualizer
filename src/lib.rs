// SPDX-License-Identifier: MIT

// Zygisk Virtualizer — seccomp-based syscall interception for ARM64 Android
//
// Hooks sensitive file reads (maps, status, su, magisk, frida, xposed) via
// SECCOMP_RET_USER_NOTIF and redirects them to clean decoy files using
// SECCOMP_IOCTL_NOTIF_ADDFD. Includes PR_GET_SECCOMP spoofing and
// /proc fd hiding for anti-cheat evasion.

#![allow(non_camel_case_types, dead_code, non_upper_case_globals)]

use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

pub mod core;
pub mod seccomp;

// ═══════════════════════════════════════════════════════════════════
// ARM64 syscall numbers
// Source: Linux kernel arch/arm64/include/asm/unistd.h
// ═══════════════════════════════════════════════════════════════════
const SYS_ioctl: i64 = 29; // fs/ioctl.c
const SYS_faccessat: i64 = 48; // fs/open.c
const SYS_openat: i64 = 56; // fs/open.c
const SYS_getdents64: i64 = 61; // fs/readdir.c
const SYS_readlinkat: i64 = 78; // fs/stat.c
const SYS_newfstatat: i64 = 79; // fs/stat.c
const SYS_readlink: i64 = 89; // fs/stat.c
const SYS_exit_group: i64 = 94; // kernel/exit.c
const SYS_nanosleep: i64 = 101; // kernel/time/hrtimer.c
const SYS_clock_gettime: i64 = 113; // kernel/time/posix-timers.c
const SYS_ptrace: i64 = 117; // kernel/ptrace.c
const SYS_uname: i64 = 160; // kernel/sys.c
const SYS_prctl: i64 = 167; // kernel/sys.c
const SYS_getpid: i64 = 172; // kernel/sys.c
const SYS_gettid: i64 = 178; // kernel/sys.c
const SYS_socket: i64 = 198; // net/socket.c
const SYS_connect: i64 = 203; // net/socket.c
const SYS_mmap: i64 = 222; // mm/mmap.c
const SYS_mprotect: i64 = 226; // mm/mprotect.c
const SYS_eventfd2: i64 = 290; // fs/eventfd.c
const SYS_openat2: i64 = 293; // fs/open.c
const SYS_process_vm_readv: i64 = 310; // mm/process_vm_access.c
const SYS_process_vm_writev: i64 = 311; // mm/process_vm_access.c
const SYS_timerfd_create: i64 = 283; // fs/timerfd.c
const SYS_statx: i64 = 291; // fs/stat.c
const SYS_seccomp: i64 = 277; // kernel/seccomp.c
const SYS_clone3: i64 = 435; // kernel/fork.c

// ═══════════════════════════════════════════════════════════════════
// Seccomp constants
// Source: linux/seccomp.h
// ═══════════════════════════════════════════════════════════════════
const SECCOMP_SET_MODE_FILTER: c_int = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 0x00000020;
const SECCOMP_FILTER_FLAG_TSYNC: u64 = 0x00004000;
const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u64 = 0x00008000;
const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u64 = 0x00010000;

const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_KILL: u32 = 0x00000000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;

const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 0x01;

// IOCTL codes for seccomp notify fd.
// _IOWR('!', 0, struct seccomp_notif)         → 0xc0502100
// _IOWR('!', 1, struct seccomp_notif_resp)    → 0xc0182101
// _IOR( '!', 2, __u64)                        → 0x80042102
// _IOWR('!', 3, struct seccomp_notif_addfd)   → 0xc0182103
const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xc0502100;
const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xc0182101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = 0x80042102;
const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0xc0182103;

const SECCOMP_ADDFD_FLAG_SEND: u32 = 0x02;

// Source: linux/audit.h — EM_AARCH64 (183) | 0x40000000
const AUDIT_ARCH_AARCH64: u32 = 0xC00000B7;

// Source: linux/prctl.h
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_GET_SECCOMP: c_int = 31;

// ═══════════════════════════════════════════════════════════════════
// File operation constants
// Source: Linux include/uapi/asm-generic/fcntl.h
// ═══════════════════════════════════════════════════════════════════
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0x40;
const O_TRUNC: c_int = 0x200;
const O_EXCL: c_int = 0x80;
const O_CLOEXEC: c_int = 0x80000;
const O_DIRECTORY: c_int = 0x10000;
const O_NOFOLLOW: c_int = 0x20000;

// Source: include/uapi/linux/fcntl.h
const AT_FDCWD: c_int = -100;
const AT_EMPTY_PATH: c_int = 0x1000;

// ═══════════════════════════════════════════════════════════════════
// Android log priorities
// Source: android/log.h
// ═══════════════════════════════════════════════════════════════════
const ANDROID_LOG_DEBUG: c_int = 3;
const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_WARN: c_int = 5;
const ANDROID_LOG_ERROR: c_int = 6;

// ═══════════════════════════════════════════════════════════════════
// BPF instruction / seccomp notification structs
// Source: linux/filter.h, linux/seccomp.h
// ═══════════════════════════════════════════════════════════════════

/// BPF filter instruction (8 bytes) — linux/filter.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_filter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// BPF program (filter + length) — linux/filter.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_fprog {
    pub len: u16,
    pub filter: *const sock_filter,
}

/// seccomp notification event — linux/seccomp.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct seccomp_data {
    pub nr: c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6usize],
}

/// seccomp notification — linux/seccomp.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct seccomp_notif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: seccomp_data,
}

/// seccomp notification response — linux/seccomp.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct seccomp_notif_resp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// seccomp ADDFD request — linux/seccomp.h (Linux 5.8+)
/// sizeof = 24 bytes → _IOC_SIZE(0xc0182103) = 0x18
#[repr(C)]
#[derive(Copy, Clone)]
pub struct seccomp_notif_addfd {
    pub id: u64,
    pub flags: u32,
    pub fd: u32,
    pub ioctl: u32,
    pub new_fd: u32,
}

// ═══════════════════════════════════════════════════════════════════
// linux_dirent64 — linux/dirent.h
// ═══════════════════════════════════════════════════════════════════
#[repr(C)]
#[derive(Copy, Clone)]
pub struct linux_dirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 0],
}

// ═══════════════════════════════════════════════════════════════════
// iovec — linux/uio.h (used by process_vm_readv/writev)
// ═══════════════════════════════════════════════════════════════════
#[repr(C)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

// ═══════════════════════════════════════════════════════════════════
// Log tag
// ═══════════════════════════════════════════════════════════════════
const TAG: *const c_char = b"RustVirt\0" as *const u8 as *const c_char;

// ═══════════════════════════════════════════════════════════════════
// FFI declarations (Android NDK + Linux syscall helpers)
// ═══════════════════════════════════════════════════════════════════
extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;

    fn getuid() -> u32;
    fn getpid() -> u32;
    fn gettid() -> u32;
    fn prctl(option: c_int, a2: c_ulong, a3: c_ulong, a4: c_ulong, a5: c_ulong) -> c_int;
    fn access(path: *const c_char, mode: c_int) -> c_int;
    fn stat(path: *const c_char, buf: *mut c_void) -> c_int;
    fn open(path: *const c_char, flags: c_int, mode: c_uint) -> c_int;
    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: c_uint) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int;
    fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
    fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int;
    fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
    fn syscall(nr: i64, ...) -> i64;
    fn memset(s: *mut c_void, c: c_int, n: usize) -> *mut c_void;
    fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
}

// ═══════════════════════════════════════════════════════════════════
// Log helper functions
// ═══════════════════════════════════════════════════════════════════

fn log_v(fmt: *const c_char, a: u32, b: u32) {
    unsafe {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, fmt, a, b);
    }
}
fn log_d(fmt: *const c_char, a: u32, b: u32) {
    unsafe {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, fmt, a, b);
    }
}
fn log_i(msg: *const c_char) {
    unsafe {
        __android_log_print(ANDROID_LOG_INFO, TAG, msg);
    }
}
fn log_2u(fmt: *const c_char, a: u32, b: u32) {
    unsafe {
        __android_log_print(ANDROID_LOG_INFO, TAG, fmt, a, b);
    }
}
fn log_w(msg: *const c_char) {
    unsafe {
        __android_log_print(ANDROID_LOG_WARN, TAG, msg);
    }
}
fn log_e(msg: *const c_char) {
    unsafe {
        __android_log_print(ANDROID_LOG_ERROR, TAG, msg);
    }
    unsafe {
        __android_log_print(ANDROID_LOG_ERROR, TAG, b"\0" as *const u8 as *const c_char);
    }
}

// ═══════════════════════════════════════════════════════════════════
// process_vm_readv / process_vm_writev wrappers
// ═══════════════════════════════════════════════════════════════════

fn process_vm_readv(
    pid: u32,
    local_iov: *const iovec,
    liovcnt: c_ulong,
    remote_iov: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> isize {
    unsafe {
        syscall(
            SYS_process_vm_readv,
            pid as i64,
            local_iov as i64,
            liovcnt as i64,
            remote_iov as i64,
            riovcnt as i64,
            flags as i64,
        ) as isize
    }
}

fn process_vm_writev(
    pid: u32,
    local_iov: *const iovec,
    liovcnt: c_ulong,
    remote_iov: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> isize {
    unsafe {
        syscall(
            SYS_process_vm_writev,
            pid as i64,
            local_iov as i64,
            liovcnt as i64,
            remote_iov as i64,
            riovcnt as i64,
            flags as i64,
        ) as isize
    }
}

// ═══════════════════════════════════════════════════════════════════
// Zygisk ABI types
// Source: zygisk.hpp (Magisk) with ZygiskApiTable / Module / ABI structs
// ═══════════════════════════════════════════════════════════════════

#[repr(C)]
pub struct JNIEnv([u8; 0]);

#[repr(C)]
pub struct JNINativeMethod {
    pub name: *const u8,
    pub signature: *const u8,
    pub fn_ptr: *mut c_void,
}

/// Arguments for preAppSpecialize — mirrors zygisk.hpp AppSpecializeArgs
#[repr(C)]
pub struct AppSpecializeArgs {
    pub size: usize,
    pub uid: u32,
    pub pid: u32,
    pub app_data_dir: *const u8,
    pub nice_name: *const u8,
    pub process_name: *const u8,
    pub app_data_dir_java: *mut c_void,
    pub package_name: *const u8,
}

/// Arguments for preServerSpecialize — zygisk.hpp ServerSpecializeArgs
#[repr(C)]
pub struct ServerSpecializeArgs {
    pub size: usize,
    pub uid: u32,
    pub pid: u32,
    pub process_name: *const u8,
}

/// VTable for ModuleBase — each slot is called by Zygisk through thunks
#[repr(C)]
pub struct ModuleBaseVtable {
    pub on_load: Option<unsafe extern "C" fn(*mut ModuleBase, *mut ApiTable, *mut JNIEnv)>,
    pub pre_app_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *mut AppSpecializeArgs)>,
    pub post_app_specialize:
        Option<unsafe extern "C" fn(*mut ModuleBase, *const AppSpecializeArgs)>,
    pub pre_server_specialize:
        Option<unsafe extern "C" fn(*mut ModuleBase, *mut ServerSpecializeArgs)>,
    pub post_server_specialize:
        Option<unsafe extern "C" fn(*mut ModuleBase, *const ServerSpecializeArgs)>,
}

/// ModuleBase — first field is the vtable pointer
#[repr(C)]
pub struct ModuleBase {
    pub vtable: *const ModuleBaseVtable,
}

/// ModuleAbi — the struct returned by zygisk_module_entry
/// Contains the API version, implementation pointer, and method slots.
#[repr(C)]
pub struct ModuleAbi {
    pub api_version: i64,
    pub impl_: *mut ModuleBase,
    pub pre_app_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *mut AppSpecializeArgs)>,
    pub post_app_specialize:
        Option<unsafe extern "C" fn(*mut ModuleBase, *const AppSpecializeArgs)>,
    pub pre_server_specialize:
        Option<unsafe extern "C" fn(*mut ModuleBase, *mut ServerSpecializeArgs)>,
    pub post_server_specialize:
        Option<unsafe extern "C" fn(*mut ModuleBase, *const ServerSpecializeArgs)>,
}

/// ApiTable — filled in by Zygisk at module registration time
#[repr(C)]
pub struct ApiTable {
    pub impl_: *mut c_void,
    pub register_module: Option<unsafe extern "C" fn(*mut ApiTable, *mut ModuleAbi) -> bool>,
    pub hook_jni_native_methods:
        Option<unsafe extern "C" fn(*mut JNIEnv, *const u8, *const JNINativeMethod, i32)>,
    pub plt_hook_register:
        Option<unsafe extern "C" fn(u64, u64, *const u8, *mut c_void, *mut *mut c_void)>,
    pub exempt_fd: Option<unsafe extern "C" fn(i32) -> bool>,
    pub plt_hook_commit: Option<unsafe extern "C" fn() -> bool>,
    pub connect_companion: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    pub set_option: Option<unsafe extern "C" fn(*mut c_void, u32)>,
    pub get_module_dir: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    pub get_flags: Option<unsafe extern "C" fn(*mut c_void) -> u32>,
}

const ZYGISK_API_VERSION: i64 = 16;

// ═══════════════════════════════════════════════════════════════════
// Stat counters (atomic to survive concurrent access in forked children)
// ═══════════════════════════════════════════════════════════════════
static LOAD_COUNT: AtomicU32 = AtomicU32::new(0);
static APP_COUNT: AtomicU32 = AtomicU32::new(0);
static FAIL_COUNT: AtomicU32 = AtomicU32::new(0);
static EXCLUDED_COUNT: AtomicU32 = AtomicU32::new(0);
static SYSTEM_COUNT: AtomicU32 = AtomicU32::new(0);

// ═══════════════════════════════════════════════════════════════════
// Environment detection constants
// ═══════════════════════════════════════════════════════════════════
const VIRT_ENV_UNKNOWN: i32 = 0;
const VIRT_ENV_MAGISK: i32 = 1;
const VIRT_ENV_KERNELSU: i32 = 2;
const VIRT_ENV_APATCH: i32 = 3;

// ═══════════════════════════════════════════════════════════════════
// Constructor (.init_array)
// ═══════════════════════════════════════════════════════════════════

#[used]
#[link_section = ".init_array"]
static CONSTRUCTOR: unsafe extern "C" fn() = ctor_fn;

unsafe extern "C" fn ctor_fn() {
    let path = b"/data/local/tmp/rust_virt_ctor\0";
    let fd = open(
        path.as_ptr() as *const c_char,
        O_WRONLY | O_CREAT | O_TRUNC,
        0o644,
    );
    if fd >= 0 {
        write(
            fd,
            b"rust_virt_ctor init\n\0" as *const u8 as *const c_void,
            18,
        );
        close(fd);
    }
    __android_log_print(
        ANDROID_LOG_INFO,
        TAG,
        b"LIB LOADED uid=%d pid=%d\0" as *const u8 as *const c_char,
        getuid(),
        getpid(),
    );
}

// ═══════════════════════════════════════════════════════════════════
// Utility functions
// ═══════════════════════════════════════════════════════════════════

/// Read /proc/self/cmdline into a buffer, null-terminated.
/// Replaces embedded NUL bytes after the first with '/' for readability.
fn virt_get_process_name(buf: &mut [u8]) {
    let fd = unsafe {
        open(
            b"/proc/self/cmdline\0".as_ptr() as *const c_char,
            O_RDONLY,
            0,
        )
    };
    if fd < 0 {
        return;
    }
    let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len() - 1) };
    unsafe {
        close(fd);
    }
    if n <= 0 {
        return;
    }
    let n = n as usize;
    buf[n] = 0;
    // Replace first embedded NUL with '/' so we can treat it as a C string.
    for i in 0..n {
        if buf[i] == 0 {
            buf[i] = b'/';
            break;
        }
    }
}

/// Detect if we are running in the zygote process using a file-marker at
/// /data/local/tmp/.virt_zygote_marker.
///
/// - uid != 0 → not zygote.
/// - If the marker already exists (stat succeeds) → another process (the real
///   zygote) created it first → we are a forked child.
/// - Otherwise try to create it exclusively. Success → we are the zygote.
fn virt_is_zygote_process() -> bool {
    let uid = unsafe { getuid() };
    if uid > 0 && uid < 10000 {
        return false;
    }
    if uid >= 10000 {
        return false;
    }
    let marker = b"/data/local/tmp/.virt_zygote_marker\0";
    let mut st: [u8; 144] = [0; 144];
    if unsafe {
        stat(
            marker.as_ptr() as *const c_char,
            st.as_mut_ptr() as *mut c_void,
        )
    } == 0
    {
        // Marker exists — another zygote beat us to it.
        return false;
    }
    let fd = unsafe {
        open(
            marker.as_ptr() as *const c_char,
            O_WRONLY | O_CREAT | O_EXCL,
            0o644,
        )
    };
    if fd >= 0 {
        unsafe {
            close(fd);
        }
        return true;
    }
    false
}

/// Returns true if the UID identifies a system-level process (0 < uid < 10000).
fn virt_is_system_process_by_uid(uid: u32) -> bool {
    uid > 0 && uid < 10000
}

/// Check cmdline substrings for zygote-related names.
fn virt_is_zygote_cmdline(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    unsafe {
        if !strstr(name, b"_zygote\0".as_ptr() as *const c_char).is_null() {
            return true;
        }
        if !strstr(name, b"zygote\0".as_ptr() as *const c_char).is_null() {
            return true;
        }
        if !strstr(name, b"usap\0".as_ptr() as *const c_char).is_null() {
            return true;
        }
    }
    false
}

/// Check if the process should be excluded from seccomp interception.
///
/// Excludes Google Play services, Chrome/webview sandboxes, and isolation
/// processes (system_server, isolated/:isolation sandboxes).
fn virt_is_excluded_process(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    unsafe {
        if !strstr(name, b"_zygote\0".as_ptr() as *const c_char).is_null() {
            return true;
        }
        if !strstr(
            name,
            b"com.android.chrome:sandboxed_process\0".as_ptr() as *const c_char,
        )
        .is_null()
        {
            return true;
        }
        if !strstr(
            name,
            b"com.google.android.webview:sandboxed_process\0".as_ptr() as *const c_char,
        )
        .is_null()
        {
            return true;
        }
        if !strstr(name, b":isolation\0".as_ptr() as *const c_char).is_null() {
            return true;
        }
        if !strstr(name, b":isolated\0".as_ptr() as *const c_char).is_null() {
            return true;
        }
        // Exact-match against known GMS / system packages.
        let exact: &[&[u8]] = &[
            b"com.google.android.gms.unstable\0",
            b"com.google.android.gms.persistent\0",
            b"com.google.android.gms\0",
            b"com.android.chrome\0",
            b"system_server\0",
        ];
        for p in exact {
            if strcmp(name, p.as_ptr() as *const c_char) == 0 {
                return true;
            }
        }
    }
    false
}

/// Probe the environment to detect the root solution provider.
///
/// Checks for the presence of well-known marker directories:
///   /data/adb/magisk   → Magisk
///   /data/adb/ksu      → KernelSU
///   /data/apatch       → APatch
fn virt_detect_environment() -> i32 {
    unsafe {
        if access(b"/data/adb/magisk\0".as_ptr() as *const c_char, 0) == 0 {
            return VIRT_ENV_MAGISK;
        }
        if access(b"/data/adb/ksu\0".as_ptr() as *const c_char, 0) == 0 {
            return VIRT_ENV_KERNELSU;
        }
        if access(b"/data/apatch\0".as_ptr() as *const c_char, 0) == 0 {
            return VIRT_ENV_APATCH;
        }
    }
    VIRT_ENV_UNKNOWN
}

/// Determine whether the module has been disabled via safe-mode files.
fn virt_is_safe_mode() -> i32 {
    let flags: &[&[u8]] = &[
        b"/cache/.disable_magisk\0",
        b"/data/unencrypted/.disable_magisk\0",
        b"/persist/.disable_magisk\0",
        b"/data/adb/ksu/.disable_ksu\0",
        b"/data/local/tmp/.virt_disable\0",
    ];
    for p in flags {
        let mut st: [u8; 144] = [0; 144];
        if unsafe { stat(p.as_ptr() as *const c_char, st.as_mut_ptr() as *mut c_void) } == 0 {
            return 1;
        }
    }
    0
}

/// Seccomp feature probing stub — checks kernel support for user notification.
fn virt_seccomp_get_features() -> i32 {
    // Attempt to detect feature support via prctl or seccomp(SECCOMP_GET_ACTION_AVAIL).
    // Return non-zero bitmask: bit 0 = SECCOMP_FILTER_FLAG_NEW_LISTENER available.
    unsafe {
        let r = syscall(SYS_seccomp, 2i64, 0i64, 0i64); // SECCOMP_GET_ACTION_AVAIL
        if r == 0 {
            return 0x7b;
        }
    }
    0x7b
}

/// Install the seccomp filter using the default static BPF program and spawn
/// the notification handler thread.
///
/// Called for both regular app processes (uid 10000-99999) and forked root
/// processes (uid == 0, not zygote).
fn install_seccomp_full_pipeline() -> i32 {
    log_i(b"install_seccomp_full_pipeline: creating decoys\0".as_ptr() as *const c_char);
    seccomp::virt_seccomp_create_decoy_files();
    seccomp::virt_decoy_fd_preopen_all();

    let mut cfg = core::virt_config_default();
    core::virt_config_auto_tune(&mut cfg);
    core::virt_decoy_init(&cfg);

    let notify_fd = seccomp::virt_seccomp_install_static_default();
    if notify_fd < 0 {
        log_e(b"install_seccomp_full_pipeline: filter install FAILED\0".as_ptr() as *const c_char);
        return -1;
    }

    // Spawn the seccomp notification handler thread.
    let ret = seccomp::virt_seccomp_start_handler_monitor(notify_fd);
    if ret != 0 {
        log_w(
            b"install_seccomp_full_pipeline: handler thread spawn returned %d\0".as_ptr()
                as *const c_char,
        );
    }
    notify_fd
}

// ═══════════════════════════════════════════════════════════════════
// Module implementation — on_load_impl
// ═══════════════════════════════════════════════════════════════════

/// Called from onLoad — runs in every forked process and in the zygote
/// itself (depending on Magisk/Kitsune variant).
unsafe extern "C" fn on_load_impl(
    _module: *mut ModuleBase,
    _api: *mut ApiTable,
    _env: *mut JNIEnv,
) {
    let uid = getuid();
    let pid = getpid();
    LOAD_COUNT.fetch_add(1, Ordering::Relaxed);

    log_2u(
        b"onLoad ENTERED uid=%d pid=%d\0".as_ptr() as *const c_char,
        uid,
        pid,
    );

    // ── Feature probing ──────────────────────────────────────────
    let _features = virt_seccomp_get_features();
    log_2u(
        b"onLoad features=0x%x uid=%d\0".as_ptr() as *const c_char,
        _features as u32,
        uid,
    );

    // ── Environment detection ────────────────────────────────────
    let rt_env = virt_detect_environment();
    log_2u(
        b"onLoad env=%d uid=%d\0".as_ptr() as *const c_char,
        rt_env as u32,
        uid,
    );

    // ── Process name ─────────────────────────────────────────────
    let mut proc_name: [u8; 256] = [0; 256];
    virt_get_process_name(&mut proc_name);
    log_2u(
        b"onLoad proc=%s uid=%d\0".as_ptr() as *const c_char,
        proc_name.as_ptr() as u32,
        uid,
    );

    // ── Safe mode check ──────────────────────────────────────────
    if virt_is_safe_mode() != 0 {
        log_i(b"onLoad: safe mode, skipping\0".as_ptr() as *const c_char);
        return;
    }

    // ── System process skip (uid 1-9999) ─────────────────────────
    if virt_is_system_process_by_uid(uid) {
        SYSTEM_COUNT.fetch_add(1, Ordering::Relaxed);
        log_2u(
            b"onLoad: system uid=%d, skip\0".as_ptr() as *const c_char,
            uid,
            0,
        );
        return;
    }

    // ── Excluded process skip ────────────────────────────────────
    if virt_is_excluded_process(proc_name.as_ptr() as *const c_char) {
        EXCLUDED_COUNT.fetch_add(1, Ordering::Relaxed);
        log_i(b"onLoad: excluded process, skip\0".as_ptr() as *const c_char);
        return;
    }

    // ── App process (uid 10000-99999) ────────────────────────────
    if uid >= 10000 && uid < 100000 {
        APP_COUNT.fetch_add(1, Ordering::Relaxed);
        log_2u(
            b"onLoad: app uid=%d pid=%d installing seccomp\0".as_ptr() as *const c_char,
            uid,
            pid,
        );
        let fd = install_seccomp_full_pipeline();
        if fd >= 0 {
            log_2u(
                b"onLoad: seccomp active notify_fd=%d pid=%d\0".as_ptr() as *const c_char,
                fd as u32,
                pid,
            );
        } else {
            FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            log_e(b"onLoad: seccomp install FAILED for app\0".as_ptr() as *const c_char);
        }
        return;
    }

    // ── uid == 0: zygote or forked root process ─────────────────
    if uid == 0 {
        if virt_is_zygote_process() {
            log_i(
                b"onLoad: real zygote detected, deferring to preAppSpecialize\0".as_ptr()
                    as *const c_char,
            );
            return;
        }
        // Forked root process (uid==0, not zygote) — e.g. surfaceflinger,
        // servicemanager, or a Kitsune child process.
        APP_COUNT.fetch_add(1, Ordering::Relaxed);
        log_2u(
            b"onLoad: forked root proc uid=%d pid=%d installing seccomp\0".as_ptr()
                as *const c_char,
            uid,
            pid,
        );
        let fd = install_seccomp_full_pipeline();
        if fd >= 0 {
            log_2u(
                b"onLoad: seccomp active notify_fd=%d pid=%d\0".as_ptr() as *const c_char,
                fd as u32,
                pid,
            );
        } else {
            FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            log_e(b"onLoad: seccomp install FAILED for forked root\0".as_ptr() as *const c_char);
        }
        return;
    }

    log_2u(
        b"onLoad: unhandled uid=%d pid=%d\0".as_ptr() as *const c_char,
        uid,
        pid,
    );
}

// ═══════════════════════════════════════════════════════════════════
// Module implementation — pre_app_specialize_impl
// ═══════════════════════════════════════════════════════════════════

/// Called from preAppSpecialize — standard Magisk flow delivers app
/// specialization here rather than in onLoad.
unsafe extern "C" fn pre_app_specialize_impl(
    _module: *mut ModuleBase,
    args: *mut AppSpecializeArgs,
) {
    let uid = getuid();
    let pid = getpid();

    log_2u(
        b"preAppSpecialize ENTERED uid=%d pid=%d\0".as_ptr() as *const c_char,
        uid,
        pid,
    );

    // If onLoad already installed seccomp, skip.
    if APP_COUNT.load(Ordering::Relaxed) > 0 {
        log_i(
            b"preAppSpecialize: seccomp already active (installed in onLoad)\0".as_ptr()
                as *const c_char,
        );
        return;
    }

    // System processes should not be instrumented.
    if virt_is_system_process_by_uid(uid) {
        log_2u(
            b"preAppSpecialize: system uid=%d, skip\0".as_ptr() as *const c_char,
            uid,
            0,
        );
        return;
    }

    // Extract the process name from AppSpecializeArgs if available,
    // otherwise fall back to /proc/self/cmdline.
    let mut proc_name: [u8; 256] = [0; 256];
    if !args.is_null() {
        let pn = (*args).process_name;
        if !pn.is_null() {
            let mut i = 0usize;
            while i < 255 {
                let b = *(pn.add(i));
                proc_name[i] = b;
                if b == 0 {
                    break;
                }
                i += 1;
            }
        }
    }
    if proc_name[0] == 0 {
        virt_get_process_name(&mut proc_name);
    }

    // Check exclusion list.
    if virt_is_excluded_process(proc_name.as_ptr() as *const c_char) {
        log_i(b"preAppSpecialize: excluded process, skip\0".as_ptr() as *const c_char);
        EXCLUDED_COUNT.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // App process — install seccomp pipeline.
    if uid >= 10000 && uid < 100000 {
        APP_COUNT.fetch_add(1, Ordering::Relaxed);
        log_2u(
            b"preAppSpecialize: app uid=%d pid=%d installing seccomp\0".as_ptr() as *const c_char,
            uid,
            pid,
        );
        let fd = install_seccomp_full_pipeline();
        if fd >= 0 {
            log_2u(
                b"preAppSpecialize: seccomp active notify_fd=%d pid=%d\0".as_ptr() as *const c_char,
                fd as u32,
                pid,
            );
        } else {
            FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            log_e(b"preAppSpecialize: seccomp install FAILED\0".as_ptr() as *const c_char);
        }
        return;
    }

    log_2u(
        b"preAppSpecialize: unhandled uid=%d pid=%d\0".as_ptr() as *const c_char,
        uid,
        pid,
    );
}

// ═══════════════════════════════════════════════════════════════════
// VTable and module instance
// ═══════════════════════════════════════════════════════════════════

const MODULE_VTABLE: ModuleBaseVtable = ModuleBaseVtable {
    on_load: Some(
        on_load_impl as unsafe extern "C" fn(*mut ModuleBase, *mut ApiTable, *mut JNIEnv),
    ),
    pre_app_specialize: Some(
        pre_app_specialize_impl as unsafe extern "C" fn(*mut ModuleBase, *mut AppSpecializeArgs),
    ),
    post_app_specialize: None,
    pre_server_specialize: None,
    post_server_specialize: None,
};

static mut MODULE: ModuleBase = ModuleBase {
    vtable: &MODULE_VTABLE,
};

// ═══════════════════════════════════════════════════════════════════
// Thunk functions — dispatch through vtable
// ═══════════════════════════════════════════════════════════════════

unsafe extern "C" fn on_load_thunk(base: *mut ModuleBase, table: *mut ApiTable, env: *mut JNIEnv) {
    let v = &*(*base).vtable;
    if let Some(f) = v.on_load {
        f(base, table, env);
    }
}

unsafe extern "C" fn pre_app_specialize_thunk(base: *mut ModuleBase, args: *mut AppSpecializeArgs) {
    let v = &*(*base).vtable;
    if let Some(f) = v.pre_app_specialize {
        f(base, args);
    }
}

unsafe extern "C" fn post_app_specialize_thunk(
    base: *mut ModuleBase,
    args: *const AppSpecializeArgs,
) {
    let v = &*(*base).vtable;
    if let Some(f) = v.post_app_specialize {
        f(base, args);
    }
}

unsafe extern "C" fn pre_server_specialize_thunk(
    base: *mut ModuleBase,
    args: *mut ServerSpecializeArgs,
) {
    let v = &*(*base).vtable;
    if let Some(f) = v.pre_server_specialize {
        f(base, args);
    }
}

unsafe extern "C" fn post_server_specialize_thunk(
    base: *mut ModuleBase,
    args: *const ServerSpecializeArgs,
) {
    let v = &*(*base).vtable;
    if let Some(f) = v.post_server_specialize {
        f(base, args);
    }
}

// ═══════════════════════════════════════════════════════════════════
// ModuleAbi static — registered with Zygisk
// ═══════════════════════════════════════════════════════════════════

static mut ABI: ModuleAbi = ModuleAbi {
    api_version: ZYGISK_API_VERSION,
    impl_: ptr::null_mut(),
    pre_app_specialize: Some(
        pre_app_specialize_thunk as unsafe extern "C" fn(*mut ModuleBase, *mut AppSpecializeArgs),
    ),
    post_app_specialize: Some(
        post_app_specialize_thunk
            as unsafe extern "C" fn(*mut ModuleBase, *const AppSpecializeArgs),
    ),
    pre_server_specialize: Some(
        pre_server_specialize_thunk
            as unsafe extern "C" fn(*mut ModuleBase, *mut ServerSpecializeArgs),
    ),
    post_server_specialize: Some(
        post_server_specialize_thunk
            as unsafe extern "C" fn(*mut ModuleBase, *const ServerSpecializeArgs),
    ),
};

// ═══════════════════════════════════════════════════════════════════
// Handler launcher — bridge to seccomp::virt_seccomp_start_handler_monitor
// ═══════════════════════════════════════════════════════════════════

/// Launch the seccomp notification handler loop on a dedicated thread.
/// This is a thin wrapper that calls through to the seccomp module's
/// thread-spawning monitor function.
fn launch_handler(notify_fd: i32) -> i32 {
    log_2u(
        b"launch_handler: starting handler loop for fd=%d\0".as_ptr() as *const c_char,
        notify_fd as u32,
        0,
    );
    seccomp::virt_seccomp_start_handler_monitor(notify_fd)
}

// ═══════════════════════════════════════════════════════════════════
// Entry point — zygisk_module_entry
// ═══════════════════════════════════════════════════════════════════

/// Zygisk entry point called by Magisk to register the module.
///
/// 1. Registers the ModuleAbi with the Zygisk API table.
/// 2. Calls onLoad to trigger seccomp installation.
#[no_mangle]
pub unsafe extern "C" fn zygisk_module_entry(table: *mut ApiTable) -> *mut ModuleAbi {
    log_i(b"zygisk_module_entry ENTERED\0".as_ptr() as *const c_char);

    ABI.impl_ = &raw mut MODULE;

    let register = match (*table).register_module {
        Some(f) => f,
        None => {
            log_e(b"zygisk_module_entry: register_module is NULL\0".as_ptr() as *const c_char);
            return ptr::null_mut();
        }
    };

    if !register(table, &raw mut ABI) {
        log_e(b"zygisk_module_entry: register_module FAILED\0".as_ptr() as *const c_char);
        return ptr::null_mut();
    }

    log_i(b"zygisk_module_entry: registration OK\0".as_ptr() as *const c_char);

    // Manually invoke onLoad via vtable dispatch.
    on_load_thunk(&raw mut MODULE, table, ptr::null_mut());

    &raw mut ABI
}
