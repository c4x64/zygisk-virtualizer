// SPDX-License-Identifier: MIT
// Ported from seccomp_engine.cpp - Seccomp USER_NOTIF engine for Zygisk Virtualizer
#![allow(non_camel_case_types, dead_code, static_mut_refs, non_upper_case_globals)]

use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::mem::MaybeUninit;
use std::vec::Vec;

extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
    fn prctl(option: c_int, a2: c_ulong, a3: c_ulong, a4: c_ulong, a5: c_ulong) -> c_int;
    fn syscall(number: i64, ...) -> i64;
    fn clock_gettime(clk_id: i32, tp: *mut libc::timespec) -> i32;
    fn pthread_create(
        thread: *mut libc::pthread_t,
        attr: *const libc::pthread_attr_t,
        start_routine: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> i32;
}

const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_DEBUG: c_int = 3;
const ANDROID_LOG_WARN: c_int = 5;
const ANDROID_LOG_ERROR: c_int = 6;

const TAG: *const c_char = b"RustVirt\0" as *const u8 as *const c_char;

fn log_info(msg: *const c_char) {
    unsafe { __android_log_print(ANDROID_LOG_INFO, TAG, msg); }
}

fn log_debug(msg: *const c_char) {
    unsafe { __android_log_print(ANDROID_LOG_DEBUG, TAG, msg); }
}

fn log_warn(msg: *const c_char) {
    unsafe { __android_log_print(ANDROID_LOG_WARN, TAG, msg); }
}

fn log_error(msg: *const c_char) {
    unsafe { __android_log_print(ANDROID_LOG_ERROR, TAG, msg); }
}

fn log_2u(fmt: *const c_char, a: u32, b: u32) {
    unsafe { __android_log_print(ANDROID_LOG_INFO, TAG, fmt, a, b); }
}

fn log_sz(fmt: *const c_char, a: u32, b: usize) {
    unsafe { __android_log_print(ANDROID_LOG_INFO, TAG, fmt, a, b); }
}

// ─── Re-exported types from lib.rs ──────────────────────────────────
use super::{sock_filter, sock_fprog};

// ─── BPF instruction constants (not pub in lib.rs, defined locally) ─
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;

// ─── seccomp return action constants ────────────────────────────────
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL: u32 = 0x0000_0000;

// ─── Local syscall number constants (lib.rs has non-pub equivalents) ─
const SYS_OPENAT: i32 = 56;
const SYS_OPENAT2: i32 = 293;
const SYS_READLINKAT: i32 = 78;
const SYS_READLINK: i32 = 89;
const SYS_NEWFSTATAT: i32 = 79;
const SYS_STATX: i32 = 291;
const SYS_FACCESSAT: i32 = 48;
const SYS_FACCESSAT2: i32 = 439;
const SYS_GETDENTS64: i32 = 61;
const SYS_MMAP: i32 = 222;
const SYS_MPROTECT: i32 = 226;
const SYS_CONNECT: i32 = 203;
const SYS_SOCKET: i32 = 198;
const SYS_IOCTL: i32 = 29;
const SYS_PRCTL: i32 = 167;
const SYS_UNAME: i32 = 160;
const SYS_PTRACE: i32 = 117;
const SYS_SECCOMP: i32 = 277;

const SECCOMP_SET_MODE_FILTER: i32 = 1;
const AUDIT_ARCH_AARCH64_LOCAL: u32 = 0xC00000B7;

// ─── Architecture-independent constants ────────────────────────────
const VIRT_PATH_BUF_SIZE: usize = 4096;
const VIRT_TMP_BUF_SIZE: usize = 8192;
const VIRT_DECOY_FD_CACHE_SIZE: u32 = 32;
const VIRT_MAX_CACHED_PATHS: u32 = 8192;
const VIRT_MAX_RULES: u32 = 1024;
const VIRT_LATENCY_BUCKETS: usize = 8;
const VIRT_HANDLER_STACK_SIZE: usize = 256 * 1024;

const __NR_seccomp: i64 = 277;
const __NR_gettid: i64 = 178;
const __NR_process_vm_readv: i64 = 310;
const __NR_process_vm_writev: i64 = 311;
const __NR_getdents: i64 = 61;

const SECCOMP_GET_ACTION_AVAIL: c_int = 2;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: c_uint = 0x20;
const SECCOMP_FILTER_FLAG_TSYNC: c_uint = 0x4000;
const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: c_uint = 0x8000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 0x01;
const SECCOMP_ADDFD_FLAG_SEND: u32 = 0x01;

const PR_SET_NAME: c_int = 15;
const PR_GET_SECCOMP: c_int = 21;
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const CLOCK_MONOTONIC: i32 = 1;
const AT_FDCWD: i32 = -100;
const SIGTERM: i32 = 15;
const SIGINT: i32 = 2;
const SIGHUP: i32 = 1;
const SIGUSR1: i32 = 10;
const SIGUSR2: i32 = 12;
const SIGPIPE: i32 = 13;
const POLLIN: i16 = 1;

const O_RDONLY: c_int = 0;
const O_CLOEXEC: c_int = 0x80000;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0x40;
const O_TRUNC: c_int = 0x200;

const F_DUPFD_CLOEXEC: c_int = 1030;
const VIRT_NS_PER_SEC: u64 = 1_000_000_000;

// ─── IOCTL numbers for seccomp (ARM64) ──────────────────────────────
// Generated from _IOR/_IOW/_IOWR magic with SECCOMP_IOC_MAGIC '!' (0x21)
const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0x80502100;
const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xC0182101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = 0x80082102;
const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0x40182103;

// ─── seccomp_notif and friends ─────────────────────────────────────
#[repr(C)]
struct seccomp_data {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
struct seccomp_notif {
    id: u64,
    pid: u32,
    flags: u32,
    data: seccomp_data,
}

#[repr(C)]
struct seccomp_notif_resp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
struct seccomp_notif_addfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

#[repr(C)]
struct iovec {
    iov_base: *mut c_void,
    iov_len: usize,
}

#[repr(C)]
struct timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

// ─── Decoy file paths ───────────────────────────────────────────────
const DECOY_MAPS_PATH: &[u8] = b"/data/local/tmp/clean_maps\0";
const DECOY_STATUS_PATH: &[u8] = b"/data/local/tmp/clean_status\0";
const DECOY_MOUNTINFO_PATH: &[u8] = b"/data/local/tmp/clean_mountinfo\0";
const DECOY_CMDLINE_PATH: &[u8] = b"/data/local/tmp/clean_cmdline\0";
const DECOY_ENVIRON_PATH: &[u8] = b"/data/local/tmp/clean_environ\0";
const DECOY_UPTIME_PATH: &[u8] = b"/data/local/tmp/clean_uptime\0";
const DECOY_STAT_PATH: &[u8] = b"/data/local/tmp/clean_stat\0";
const DECOY_SELINUX_PATH: &[u8] = b"/data/local/tmp/clean_selinux\0";
const DECOY_VERSION_PATH: &[u8] = b"/data/local/tmp/clean_version\0";
const DECOY_BOOTID_PATH: &[u8] = b"/data/local/tmp/clean_boot_id\0";
const DECOY_HOSTNAME_PATH: &[u8] = b"/data/local/tmp/clean_hostname\0";
const DECOY_OSRELEASE_PATH: &[u8] = b"/data/local/tmp/clean_osrelease\0";
const DECOY_OSTYPE_PATH: &[u8] = b"/data/local/tmp/clean_ostype\0";
const DECOY_CPUINFO_PATH: &[u8] = b"/data/local/tmp/clean_cpuinfo\0";
const DECOY_FAKE_EXE_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_exe\0";
const DECOY_IO_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_io\0";
const DECOY_OOM_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_oom\0";
const DECOY_OOM_SCORE_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_oom_score\0";
const DECOY_OOM_SCORE_ADJ_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_oom_score_adj\0";
const DECOY_WCHAN_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_wchan\0";
const DECOY_STACK_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_stack\0";
const DECOY_SYSCALL_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_syscall\0";
const DECOY_PERSONALITY_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_personality\0";
const DECOY_COREDUMP_FILTER_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_coredump_filter\0";
const DECOY_TIMERS_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_timers\0";
const DECOY_LOGINUID_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_loginuid\0";
const DECOY_SESSIONID_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_sessionid\0";
const DECOY_COMM_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_comm\0";
const DECOY_MODULES_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_modules\0";
const DECOY_KALLSYMS_PATH: &[u8] = b"/data/local/tmp/virtualizer/fake_kallsyms\0";

fn path_as_cstr(p: &[u8]) -> *const c_char { p.as_ptr() as *const c_char }

// ─── Decoy content from virtualizer.h / seccomp_engine.cpp ──────────
fn decoy_file_write_impl(path: *const c_char, lines: &[&[u8]], binary: bool) -> bool {
    // Source: seccomp_engine.cpp:437-447
    let fd = unsafe { libc::open(path as *const c_char, O_WRONLY | O_CREAT | O_TRUNC, 0o644) };
    if fd < 0 { return false; }
    let ok = lines.iter().all(|&line| {
        unsafe {
            let n = libc::write(fd, line.as_ptr() as *const c_void, line.len());
            if n as isize != line.len() as isize { return false; }
            let sep = if binary { b"\0" } else { b"\n" };
            libc::write(fd, sep.as_ptr() as *const c_void, sep.len()) == sep.len() as isize
        }
    });
    unsafe { libc::close(fd); }
    ok
}

fn virt_decoy_file_create(path: *const c_char, lines: &[&[u8]]) -> bool {
    // Source: seccomp_engine.cpp:437-447 — wraps decoy_file_write_impl for text files
    decoy_file_write_impl(path, lines, false)
}

fn virt_decoy_file_create_binary(path: *const c_char, lines: &[&[u8]]) -> bool {
    // Source: seccomp_engine.cpp:425-435 — null-separated entries
    decoy_file_write_impl(path, lines, true)
}

// ─── Timing helpers ─────────────────────────────────────────────────
fn virt_gettime_ns() -> u64 {
    // Source: virtualizer.h:1925-1929
    let mut ts: timespec = unsafe { MaybeUninit::zeroed().assume_init() };
    unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec as *mut libc::timespec); }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

struct TimingJitter {
    enabled: bool,
    base_us: u32,
    range_us: u32,
}

static mut TIMING_JITTER: TimingJitter = TimingJitter { enabled: false, base_us: 0, range_us: 0 };

fn virt_timing_add_jitter(enabled: bool) {
    // Source: seccomp_engine.cpp:62-72
    if !enabled { return; }
    static mut JITTER_SEED: u32 = 0xDEADBEEF;
    unsafe {
        if JITTER_SEED == 0 { JITTER_SEED = virt_gettime_ns() as u32; }
        JITTER_SEED = JITTER_SEED.wrapping_mul(1103515245).wrapping_add(12345);
        let delay_us = (JITTER_SEED >> 16) & 0x3F;
        if delay_us > 0 {
            let ts = libc::timespec { tv_sec: 0, tv_nsec: (delay_us as i64) * 1000 };
            libc::nanosleep(&ts, ptr::null_mut());
        }
    }
}

// ─── Error recovery tracking ────────────────────────────────────────
struct ErrorRecovery {
    consecutive_notif_errors: u32,
    consecutive_respond_errors: u32,
    consecutive_addfd_errors: u32,
    max_consecutive_errors: u32,
    self_healing_mode: bool,
}

static mut ERROR_RECOVERY: ErrorRecovery = ErrorRecovery {
    consecutive_notif_errors: 0,
    consecutive_respond_errors: 0,
    consecutive_addfd_errors: 0,
    max_consecutive_errors: 5,
    self_healing_mode: false,
};

fn virt_error_record_success() {
    // Source: seccomp_engine.cpp:105-131
    unsafe {
        ERROR_RECOVERY.consecutive_notif_errors = 0;
        ERROR_RECOVERY.consecutive_respond_errors = 0;
        ERROR_RECOVERY.consecutive_addfd_errors = 0;
        if ERROR_RECOVERY.self_healing_mode {
            log_debug(b"Self-healing: operation recovered\0" as *const u8 as *const c_char);
            ERROR_RECOVERY.self_healing_mode = false;
        }
    }
}

fn virt_error_record_failure(op: &str) {
    unsafe {
        match op {
            "respond" => ERROR_RECOVERY.consecutive_respond_errors += 1,
            "addfd" => ERROR_RECOVERY.consecutive_addfd_errors += 1,
            _ => ERROR_RECOVERY.consecutive_notif_errors += 1,
        }
        if ERROR_RECOVERY.consecutive_notif_errors >= ERROR_RECOVERY.max_consecutive_errors {
            log_warn(b"Self-healing mode activated: too many errors\0" as *const u8 as *const c_char);
            ERROR_RECOVERY.self_healing_mode = true;
        }
    }
}

// ─── Decoy fd cache ─────────────────────────────────────────────────
// Source: seccomp_engine.cpp:156-213
static DECOY_FDS: [AtomicI32; 32] = [
    AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1),
    AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1),
    AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1),
    AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1),
    AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1),
    AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1),
    AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1),
    AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1), AtomicI32::new(-1),
];
static DECOY_FD_COUNT: AtomicU32 = AtomicU32::new(0);

fn virt_decoy_fd_open(path: *const c_char) -> i32 {
    // Source: seccomp_engine.cpp:156-175
    let count = DECOY_FD_COUNT.load(Ordering::Acquire) as usize;
    if path.is_null() { return -1; }
    for i in 0..count.min(32) {
        let fd = DECOY_FDS[i].load(Ordering::Relaxed);
        if fd >= 0 {
            let new_fd = unsafe { libc::fcntl(fd, F_DUPFD_CLOEXEC, 0) };
            if new_fd >= 0 { return new_fd; }
        }
    }
    if count < 32 {
        let fd = unsafe { libc::open(path, O_RDONLY | O_CLOEXEC) };
        if fd < 0 { return -1; }
        DECOY_FDS[count].store(fd, Ordering::Relaxed);
        DECOY_FD_COUNT.store(count as u32 + 1, Ordering::Release);
        let new_fd = unsafe { libc::fcntl(fd, F_DUPFD_CLOEXEC, 0) };
        if new_fd < 0 { unsafe { libc::close(fd); } DECOY_FDS[count].store(-1, Ordering::Relaxed); return -1; }
        return new_fd;
    }
    unsafe { libc::open(path, O_RDONLY | O_CLOEXEC) }
}

pub fn virt_decoy_fd_preopen_all() {
    // Source: seccomp_engine.cpp:177-213
    let paths: [*const c_char; 29] = [
        path_as_cstr(DECOY_MAPS_PATH), path_as_cstr(DECOY_STATUS_PATH),
        path_as_cstr(DECOY_MOUNTINFO_PATH), path_as_cstr(DECOY_CMDLINE_PATH),
        path_as_cstr(DECOY_ENVIRON_PATH), path_as_cstr(DECOY_UPTIME_PATH),
        path_as_cstr(DECOY_STAT_PATH), path_as_cstr(DECOY_SELINUX_PATH),
        path_as_cstr(DECOY_VERSION_PATH), path_as_cstr(DECOY_BOOTID_PATH),
        path_as_cstr(DECOY_HOSTNAME_PATH), path_as_cstr(DECOY_OSRELEASE_PATH),
        path_as_cstr(DECOY_OSTYPE_PATH), path_as_cstr(DECOY_CPUINFO_PATH),
        path_as_cstr(DECOY_FAKE_EXE_PATH), path_as_cstr(DECOY_IO_PATH),
        path_as_cstr(DECOY_OOM_PATH), path_as_cstr(DECOY_OOM_SCORE_PATH),
        path_as_cstr(DECOY_OOM_SCORE_ADJ_PATH), path_as_cstr(DECOY_WCHAN_PATH),
        path_as_cstr(DECOY_STACK_PATH), path_as_cstr(DECOY_SYSCALL_PATH),
        path_as_cstr(DECOY_PERSONALITY_PATH), path_as_cstr(DECOY_COREDUMP_FILTER_PATH),
        path_as_cstr(DECOY_TIMERS_PATH), path_as_cstr(DECOY_LOGINUID_PATH),
        path_as_cstr(DECOY_SESSIONID_PATH), path_as_cstr(DECOY_COMM_PATH),
        ptr::null(),
    ];
    let mut count = 0u32;
    for &p in &paths {
        if p.is_null() { break; }
        if virt_decoy_fd_open(p) >= 0 { count += 1; }
    }
    log_2u(b"Decoy fd cache: %d files pre-opened, slots=%d\0" as *const u8 as *const c_char,
           count, DECOY_FD_COUNT.load(Ordering::Relaxed));
}

// ─── ADDFD injection ────────────────────────────────────────────────
fn virt_seccomp_try_addfd(notify_fd: i32, req_id: u64, redirect_path: *const c_char) -> i32 {
    // Source: seccomp_engine.cpp:449-463
    let local_fd = virt_decoy_fd_open(redirect_path);
    if local_fd < 0 { return -1; }
    let addfd = seccomp_notif_addfd {
        id: req_id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: local_fd as u32,
        newfd: 0,
        newfd_flags: libc::O_CLOEXEC as u32,
    };
    let new_fd = unsafe {
        libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD as i32, &addfd as *const _ as *mut c_void)
    };
    unsafe { libc::close(local_fd); }
    new_fd
}

// ─── resolve_path_from_target via process_vm_readv ──────────────────
fn resolve_path_from_target(pid: u32, remote_addr: u64, buf: &mut [u8]) -> i32 {
    // Source: seccomp_engine.cpp:1384-1408
    if remote_addr == 0 || buf.is_empty() { return -1; }
    let local_iov = iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: buf.len(),
    };
    let remote_iov = iovec {
        iov_base: remote_addr as *mut c_void,
        iov_len: buf.len(),
    };
    let n = unsafe {
        syscall(
            __NR_process_vm_readv as i64,
            pid as i32, &local_iov, 1, &remote_iov, 1, 0
        ) as isize
    };
    if n <= 0 { return -1; }
    let n_usize = if (n as usize) < buf.len() { n as usize } else { buf.len() - 1 };
    buf[n_usize] = 0;
    for i in 0..n_usize {
        if buf[i] == 0 { return i as i32; }
    }
    n_usize as i32
}

// ─── BPF Compiler ───────────────────────────────────────────────────
// Source: seccomp_engine.cpp:517-655
struct BPFCompiler {
    instructions: Vec<sock_filter>,
    matched_nrs: Vec<i32>,
    arch: u32,
}

fn bpf_compiler_new() -> BPFCompiler {
    BPFCompiler {
        instructions: Vec::with_capacity(128),
        matched_nrs: Vec::with_capacity(64),
        arch: AUDIT_ARCH_AARCH64_LOCAL,
    }
}

fn bpf_compiler_emit(c: &mut BPFCompiler, code: u16, jt: u8, jf: u8, k: u32) -> i32 {
    let idx = c.instructions.len();
    c.instructions.push(sock_filter { code, jt, jf, k });
    idx as i32
}

fn bpf_compiler_ld_abs(c: &mut BPFCompiler, offset: u32) -> i32 {
    bpf_compiler_emit(c, BPF_LD | BPF_W | BPF_ABS, 0, 0, offset)
}

fn bpf_compiler_jeq(c: &mut BPFCompiler, k: u32, jt: u8, jf: u8) -> i32 {
    bpf_compiler_emit(c, BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k)
}

fn bpf_compiler_ret(c: &mut BPFCompiler, k: u32) -> i32 {
    bpf_compiler_emit(c, BPF_RET | BPF_K, 0, 0, k)
}

fn bpf_compiler_compile(c: &mut BPFCompiler, profiles: &[SeccompFilterProfile]) -> i32 {
    // Source: seccomp_engine.cpp:570-655
    let arch_insn = bpf_compiler_ld_abs(c, 4);
    if arch_insn < 0 { return -1; }

    let arch_jump = bpf_compiler_jeq(c, c.arch, 1, 0);
    if arch_jump < 0 { return -1; }

    let arch_allow = bpf_compiler_ret(c, SECCOMP_RET_ALLOW);
    if arch_allow < 0 { return -1; }

    let load_nr = bpf_compiler_ld_abs(c, 0);
    if load_nr < 0 { return -1; }

    let mut match_count = 0;
    for p in profiles {
        if p.syscall_nr < 0 { break; }
        if p.intercept {
            c.matched_nrs.push(p.syscall_nr);
            match_count += 1;
        }
    }

    if match_count == 0 {
        let ret_all = bpf_compiler_ret(c, SECCOMP_RET_ALLOW);
        return if ret_all >= 0 { c.instructions.len() as i32 } else { -1 };
    }

    let mut remaining = match_count;
    for p in profiles {
        if p.syscall_nr < 0 { break; }
        if !p.intercept { continue; }
        remaining -= 1;
        let skip = remaining + 1;
        if bpf_compiler_jeq(c, p.syscall_nr as u32, skip as u8, 0) < 0 { return -1; }
    }

    if bpf_compiler_ret(c, SECCOMP_RET_ALLOW) < 0 { return -1; }
    if bpf_compiler_ret(c, SECCOMP_RET_USER_NOTIF) < 0 { return -1; }

    c.instructions.len() as i32
}

// ─── SeccompFilterProfile + DEFAULT_FILTER_PROFILES ─────────────────
// Source: virtualizer.h:1471-1493
#[repr(C)]
pub struct SeccompFilterProfile {
    pub syscall_nr: i32,
    pub category: i32,
    pub intercept: bool,
    pub name: [u8; 32],
}

const CAT_FILE_READ: i32 = 0;
const CAT_FILE_WRITE: i32 = 1;
const CAT_FILE_META: i32 = 2;
const CAT_PROC: i32 = 3;
const CAT_NETWORK: i32 = 4;
const CAT_MEMORY: i32 = 5;
const CAT_EXEC: i32 = 6;
const CAT_DEBUG: i32 = 7;
const CAT_OTHER: i32 = 8;

const fn make_profile(nr: i32, cat: i32, intercept: bool, name: &[u8]) -> SeccompFilterProfile {
    let mut n = [0u8; 32];
    let len = if name.len() > 31 { 31 } else { name.len() };
    let mut i = 0;
    while i < len {
        n[i] = name[i];
        i += 1;
    }
    SeccompFilterProfile { syscall_nr: nr, category: cat, intercept, name: n }
}

pub static DEFAULT_FILTER_PROFILES: [SeccompFilterProfile; 21] = [
    // Source: virtualizer.h:1471-1493 — ARM64 syscall numbers
    make_profile(56,  CAT_FILE_READ,  true,  b"openat"),
    make_profile(293, CAT_FILE_READ,  true,  b"openat2"),
    make_profile(78,  CAT_FILE_READ,  true,  b"readlinkat"),
    make_profile(89,  CAT_FILE_READ,  true,  b"readlink"),
    make_profile(79,  CAT_FILE_META,  true,  b"newfstatat"),
    make_profile(291, CAT_FILE_META,  true,  b"statx"),
    make_profile(48,  CAT_FILE_READ,  true,  b"faccessat"),
    make_profile(439, CAT_FILE_READ,  true,  b"faccessat2"),
    make_profile(61,  CAT_FILE_READ,  true,  b"getdents64"),
    make_profile(222, CAT_MEMORY,     true,  b"mmap"),
    make_profile(226, CAT_MEMORY,     true,  b"mprotect"),
    make_profile(203, CAT_NETWORK,    true,  b"connect"),
    make_profile(198, CAT_NETWORK,    false, b"socket"),
    make_profile(29,  CAT_DEBUG,      false, b"ioctl"),
    make_profile(167, CAT_DEBUG,      true,  b"prctl"),
    make_profile(160, CAT_OTHER,      true,  b"uname"),
    make_profile(117, CAT_DEBUG,      true,  b"ptrace"),
    make_profile(35,  CAT_FILE_WRITE, true,  b"unlinkat"),
    make_profile(276, CAT_FILE_WRITE, true,  b"renameat2"),
    make_profile(241, CAT_DEBUG,      true,  b"perf_event_open"),
    make_profile(-1,  CAT_OTHER,      false, b"terminator"),
];

// ─── Feature probing via SECCOMP_GET_ACTION_AVAIL ───────────────────
// Source: seccomp_engine.cpp:734-806
static mut FEATURES_CACHED: i32 = -1;
static mut HAS_USER_NOTIF: bool = false;
static mut HAS_NEW_LISTENER: bool = false;
static mut HAS_TSYNC: bool = false;
static mut HAS_CONTINUE: bool = true;
static mut FEATURES_MASK: u32 = 0;

fn virt_seccomp_probe_kernel_features() -> i32 {
    // Source: seccomp_engine.cpp:734-806
    let mut features = 0i32;

    let dummy = [sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW }];
    let prog = sock_fprog { len: 1, filter: dummy.as_ptr() };

    unsafe {
        if syscall(__NR_seccomp as i64, SECCOMP_GET_ACTION_AVAIL as i64, 0, SECCOMP_RET_USER_NOTIF as u32 as i64) == 0 {
            features |= 1;
            HAS_USER_NOTIF = true;
        }
        if syscall(__NR_seccomp as i64, SECCOMP_GET_ACTION_AVAIL as i64, 0, 0x7ff00000i64 /* SECCOMP_RET_TRACE */) == 0 {
            features |= 16;
        }
        let fd = syscall(__NR_seccomp as i64, SECCOMP_SET_MODE_FILTER as i64,
                                SECCOMP_FILTER_FLAG_NEW_LISTENER as i64, &prog as *const _ as i64);
        if fd >= 0 {
            features |= 2;
            HAS_NEW_LISTENER = true;
            libc::close(fd as i32);

            let fd2 = syscall(__NR_seccomp as i64, SECCOMP_SET_MODE_FILTER as i64,
                                     (SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_TSYNC) as i64,
                                     &prog as *const _ as i64);
            if fd2 >= 0 {
                features |= 4;
                HAS_TSYNC = true;
                libc::close(fd2 as i32);

                let fd3 = syscall(__NR_seccomp as i64, SECCOMP_SET_MODE_FILTER as i64,
                                         (SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_TSYNC_ESRCH) as i64,
                                         &prog as *const _ as i64);
                if fd3 >= 0 {
                    features |= 32;
                    libc::close(fd3 as i32);
                }
            }
        }
        FEATURES_MASK = features as u32;
    }
    features
}

fn virt_seccomp_get_features(out: &mut i32) -> i32 {
    unsafe {
        if FEATURES_CACHED < 0 {
            FEATURES_CACHED = virt_seccomp_probe_kernel_features();
        }
        *out = FEATURES_CACHED;
    }
    0
}

// ─── Filter installation ────────────────────────────────────────────
// Source: seccomp_engine.cpp:814-885
fn virt_seccomp_install_static(profiles: &[SeccompFilterProfile]) -> i32 {
    let mut compiler = bpf_compiler_new();
    let total_insns = bpf_compiler_compile(&mut compiler, profiles);
    if total_insns < 0 { return -2; }

    let prog = sock_fprog {
        len: total_insns as u16,
        filter: compiler.instructions.as_ptr(),
    };

    unsafe {
        // Source: seccomp_engine.cpp:842 — PR_SET_NO_NEW_PRIVS before seccomp
        prctl(PR_SET_NO_NEW_PRIVS, 1 as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong);

        let mut filter_flags = SECCOMP_FILTER_FLAG_NEW_LISTENER;
        if HAS_TSYNC {
            filter_flags |= SECCOMP_FILTER_FLAG_TSYNC;
            if FEATURES_MASK & 32 != 0 {
                filter_flags |= SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
            }
        }

        let mut notify_fd = syscall(
            __NR_seccomp as i64, SECCOMP_SET_MODE_FILTER as i64,
            filter_flags as i64, &prog as *const _ as i64
        ) as i32;

        if notify_fd < 0 {
            if filter_flags & SECCOMP_FILTER_FLAG_TSYNC != 0 {
                filter_flags &= !SECCOMP_FILTER_FLAG_TSYNC;
                filter_flags &= !SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
                notify_fd = syscall(
                    __NR_seccomp as i64, SECCOMP_SET_MODE_FILTER as i64,
                    filter_flags as i64, &prog as *const _ as i64
                ) as i32;
            }
        }

        if notify_fd < 0 {
            // Try static fallback filter
            let static_filter = [
                sock_filter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 4 },
                sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: AUDIT_ARCH_AARCH64_LOCAL },
                sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
                sock_filter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 0 },
                sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 3, jf: 0, k: 48 },  // faccessat
                sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 2, jf: 0, k: 56 },  // openat
                sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: 78 },  // readlinkat
                sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
                sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_USER_NOTIF },
            ];
            let fallback_prog = sock_fprog { len: 9, filter: static_filter.as_ptr() };
            notify_fd = syscall(
                __NR_seccomp as i64, SECCOMP_SET_MODE_FILTER as i64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER as i64, &fallback_prog as *const _ as i64
            ) as i32;
        }

        if notify_fd < 0 {
            log_error(b"All seccomp installation methods failed\0" as *const u8 as *const c_char);
            return -3;
        }

        log_2u(b"Seccomp filter installed fd=%d flags=0x%x\0" as *const u8 as *const c_char,
               notify_fd as u32, filter_flags);
        notify_fd
    }
}

// ─── virt_seccomp_install_static_default ────────────────────────────
pub fn virt_seccomp_install_static_default() -> i32 {
    // Source: seccomp_engine.cpp:1041-1049
    virt_seccomp_install_static(&DEFAULT_FILTER_PROFILES)
}

// ─── Syscall execution functions ────────────────────────────────────
// Source: seccomp_engine.cpp:1153-1297
fn get_errno_val() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn get_errno() -> i64 {
    -(get_errno_val() as i64)
}

fn execute_faccessat(a0: u64, a1: u64, a2: u64) -> i64 {
    let ret = unsafe { syscall(SYS_FACCESSAT as i64, a0 as i32, a1 as *mut c_void, a2 as i32) };
    if ret < 0 { get_errno() } else { 0 }
}

fn execute_openat(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret = unsafe { syscall(SYS_OPENAT as i64, a0 as i32, a1 as *mut c_void, a2 as i32, a3 as u32) };
    if ret < 0 { get_errno() } else { ret }
}

fn execute_faccessat2(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret = unsafe { syscall(SYS_FACCESSAT2 as i64, a0 as i32, a1 as *mut c_void, a2 as i32, a3 as i32) };
    if ret < 0 { get_errno() } else { 0 }
}

fn execute_connect(a0: u64, a1: u64, a2: u64) -> i64 {
    let ret = unsafe { syscall(SYS_CONNECT as i64, a0 as i32, a1 as *mut c_void, a2 as u32) };
    if ret < 0 { get_errno() } else { 0 }
}

fn execute_mmap(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret = unsafe { syscall(SYS_MMAP as i64, a0 as *mut c_void, a1 as usize, a2 as i32, a3 as i32, a4 as i32, a5 as i64) };
    if ret < 0 { get_errno() } else { ret }
}

fn execute_mprotect(a0: u64, a1: u64, a2: u64) -> i64 {
    let ret = unsafe { syscall(SYS_MPROTECT as i64, a0 as *mut c_void, a1 as usize, a2 as i32) };
    if ret < 0 { get_errno() } else { 0 }
}

fn execute_readlinkat(a0: u64, a1: u64, a2: u64, a3: u64, target_pid: u32) -> i64 {
    // Source: seccomp_engine.cpp:1165-1180
    let mut tmp = [0u8; VIRT_PATH_BUF_SIZE];
    let n = unsafe { syscall(SYS_READLINKAT as i64, a0 as i32, a1 as *mut c_void, tmp.as_mut_ptr() as *mut c_void, tmp.len() as i64) };
    if n < 0 { return get_errno(); }
    let n_usize = n as usize;
    let copy_sz = n_usize.min(a3 as usize);
    if copy_sz > 0 {
        let lw = iovec { iov_base: tmp.as_mut_ptr() as *mut c_void, iov_len: copy_sz };
        let rw = iovec { iov_base: a2 as *mut c_void, iov_len: copy_sz };
        unsafe { syscall(__NR_process_vm_writev as i64, target_pid as i32, &lw, 1, &rw, 1, 0); }
    }
    copy_sz as i64
}

fn execute_readlink(a0: u64, a1: u64, a2: u64, target_pid: u32) -> i64 {
    // Source: seccomp_engine.cpp:1182-1195
    let mut tmp = [0u8; VIRT_PATH_BUF_SIZE];
    let n = unsafe { syscall(SYS_READLINK as i64, a0 as *mut c_void, tmp.as_mut_ptr() as *mut c_void, tmp.len() as i64) };
    if n < 0 { return get_errno(); }
    let n_usize = n as usize;
    let copy_sz = n_usize.min(a2 as usize);
    if copy_sz > 0 {
        let lw = iovec { iov_base: tmp.as_mut_ptr() as *mut c_void, iov_len: copy_sz };
        let rw = iovec { iov_base: a1 as *mut c_void, iov_len: copy_sz };
        unsafe { syscall(__NR_process_vm_writev as i64, target_pid as i32, &lw, 1, &rw, 1, 0); }
    }
    copy_sz as i64
}

fn execute_newfstatat(a0: u64, a1: u64, a2: u64, a3: u64, target_pid: u32) -> i64 {
    // Source: seccomp_engine.cpp:1197-1208
    let mut st: [u8; 144] = [0; 144]; // sizeof(struct stat) typically 144 on ARM64
    let ret = unsafe { syscall(SYS_NEWFSTATAT as i64, a0 as i32, a1 as *mut c_void, st.as_mut_ptr() as *mut c_void, a3 as i32) };
    if ret < 0 { return get_errno(); }
    let lw = iovec { iov_base: st.as_mut_ptr() as *mut c_void, iov_len: st.len() };
    let rw = iovec { iov_base: a2 as *mut c_void, iov_len: st.len() };
    unsafe { syscall(__NR_process_vm_writev as i64, target_pid as i32, &lw, 1, &rw, 1, 0); }
    0
}

fn execute_statx(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, target_pid: u32) -> i64 {
    // Source: seccomp_engine.cpp:1210-1221
    let mut stx: [u8; 256] = [0; 256]; // sizeof(struct statx) = 256
    let ret = unsafe { syscall(SYS_STATX as i64, a0 as i32, a1 as *mut c_void, a2 as i32, a3 as u32, stx.as_mut_ptr() as *mut c_void) };
    if ret < 0 { return get_errno(); }
    let lw = iovec { iov_base: stx.as_mut_ptr() as *mut c_void, iov_len: stx.len() };
    let rw = iovec { iov_base: a4 as *mut c_void, iov_len: stx.len() };
    unsafe { syscall(__NR_process_vm_writev as i64, target_pid as i32, &lw, 1, &rw, 1, 0); }
    0
}

fn execute_getdents64(a0: u64, a1: u64, a2: u64, target_pid: u32) -> i64 {
    // Source: seccomp_engine.cpp:1223-1247
    let mut tmp = [0u8; VIRT_TMP_BUF_SIZE];
    let read_size = (a2 as usize).min(VIRT_TMP_BUF_SIZE);
    let n = unsafe { syscall(__NR_getdents as i64, a0 as i32, tmp.as_mut_ptr() as *mut c_void, read_size as u32) };
    if n < 0 { return get_errno(); }
    if n == 0 { return 0; }
    let n_usize = n as usize;
    let lw = iovec { iov_base: tmp.as_mut_ptr() as *mut c_void, iov_len: n_usize };
    let rw = iovec { iov_base: a1 as *mut c_void, iov_len: n_usize };
    unsafe { syscall(__NR_process_vm_writev as i64, target_pid as i32, &lw, 1, &rw, 1, 0); }
    n_usize as i64
}

fn execute_uname(a0: u64, target_pid: u32) -> i64 {
    // Source: seccomp_engine.cpp:1288-1297
    let mut uts: [u8; 390] = [0; 390];
    let ret = unsafe { syscall(SYS_UNAME as i64, uts.as_mut_ptr() as *mut c_void) };
    if ret < 0 { return get_errno(); }
    // Spoof: write clean values
    let sysname = b"Linux\0";
    let release = b"5.10.149-android13-4-00001-gdeadbeef\0";
    let version = b"#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 2024\0";
    let machine = b"aarch64\0";
    uts[..sysname.len()].copy_from_slice(sysname);
    uts[65..65+release.len()].copy_from_slice(release);
    uts[130..130+version.len()].copy_from_slice(version);
    uts[195..195+machine.len()].copy_from_slice(machine);
    let lw = iovec { iov_base: uts.as_mut_ptr() as *mut c_void, iov_len: uts.len() };
    let rw = iovec { iov_base: a0 as *mut c_void, iov_len: uts.len() };
    unsafe { syscall(__NR_process_vm_writev as i64, target_pid as i32, &lw, 1, &rw, 1, 0); }
    0
}

// ─── handle_prctl ───────────────────────────────────────────────────
// Source: seccomp_engine.cpp:1299-1321
fn handle_prctl(nr: i64, a0: u64, _a1: u64, _a2: u64, resp: &mut seccomp_notif_resp) {
    if nr == SYS_PRCTL as i64 {
        let option = a0 as i64;
        if option as c_int == PR_GET_SECCOMP {
            resp.error = 0;
            resp.val = 0;
            resp.flags = 0;
            log_debug(b"[prctl] PR_GET_SECCOMP spoofed -> 0\0" as *const u8 as *const c_char);
        } else {
            resp.error = 0;
            resp.val = 0;
            resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        }
    }
}

// ─── Decoy file creation ───────────────────────────────────────────
// Source: seccomp_engine.cpp:889-1036
pub fn virt_seccomp_create_decoy_files() -> i32 {
    let mut ok = 0i32;

    if virt_decoy_file_create(path_as_cstr(DECOY_MAPS_PATH), &[
        b"557e8000-558e9000 r-xp 00000000 fe:00 12345     /system/bin/app_process64",
        b"558e9000-558ea000 r--p 00101000 fe:00 12345     /system/bin/app_process64",
        b"558ea000-558ec000 rw-p 00102000 fe:00 12345     /system/bin/app_process64",
        b"558ec000-558f0000 rw-p 00000000 00:00 0         [anon:.bss]",
        b"7c000000-7c032000 r-xp 00000000 fe:00 67890     /system/lib64/linker64",
        b"7c032000-7c034000 r--p 00031000 fe:00 67890     /system/lib64/linker64",
        b"7c034000-7c038000 rw-p 00033000 fe:00 67890     /system/lib64/linker64",
        b"7c038000-7c03d000 rw-p 00000000 00:00 0         [anon:linker_alloc]",
        b"7c03d000-7c0a7000 r-xp 00000000 fe:00 67891     /system/lib64/libc.so",
        b"7c0a7000-7c0ab000 r--p 00069000 fe:00 67891     /system/lib64/libc.so",
        b"7c0ab000-7c0ac000 rw-p 0006d000 fe:00 67891     /system/lib64/libc.so",
        b"7c0ac000-7c0b1000 rw-p 00000000 00:00 0         [anon:libc_malloc]",
        b"7c0b1000-7c0d3000 r-xp 00000000 fe:00 67892     /system/lib64/libm.so",
        b"7c0d3000-7c0d4000 r--p 00021000 fe:00 67892     /system/lib64/libm.so",
        b"7c0d4000-7c0d5000 rw-p 00022000 fe:00 67892     /system/lib64/libm.so",
        b"7c0d5000-7c0d7000 r-xp 00000000 fe:00 67893     /system/lib64/libdl.so",
        b"7c0d7000-7c0d8000 r--p 00001000 fe:00 67893     /system/lib64/libdl.so",
        b"7c0d8000-7c0d9000 rw-p 00002000 fe:00 67893     /system/lib64/libdl.so",
        b"7c0d9000-7c153000 r-xp 00000000 fe:00 67894     /system/lib64/libandroid_runtime.so",
        b"7c153000-7c159000 r--p 00079000 fe:00 67894     /system/lib64/libandroid_runtime.so",
        b"7c159000-7c15e000 rw-p 0007f000 fe:00 67894     /system/lib64/libandroid_runtime.so",
        b"7c15e000-7c192000 r-xp 00000000 fe:00 67895     /system/lib64/libc++.so",
        b"7c192000-7c196000 r--p 00033000 fe:00 67895     /system/lib64/libc++.so",
        b"7c196000-7c197000 rw-p 00037000 fe:00 67895     /system/lib64/libc++.so",
        b"7c197000-7c202000 r-xp 00000000 fe:00 67896     /system/lib64/liblog.so",
        b"7c202000-7c204000 r--p 0006a000 fe:00 67896     /system/lib64/liblog.so",
        b"7c204000-7c205000 rw-p 0006c000 fe:00 67896     /system/lib64/liblog.so",
        b"7c205000-7c23d000 r-xp 00000000 fe:00 67897     /system/lib64/libnativehelper.so",
        b"7c23d000-7c240000 r--p 00037000 fe:00 67897     /system/lib64/libnativehelper.so",
        b"7c240000-7c241000 rw-p 0003a000 fe:00 67897     /system/lib64/libnativehelper.so",
        b"7c241000-7c251000 r-xp 00000000 fe:00 67898     /system/lib64/libz.so",
        b"7c251000-7c252000 r--p 0000f000 fe:00 67898     /system/lib64/libz.so",
        b"7c252000-7c253000 rw-p 00010000 fe:00 67898     /system/lib64/libz.so",
        b"7c253000-7c28b000 r-xp 00000000 fe:00 67899     /system/lib64/libexpat.so",
        b"7c28b000-7c28d000 r--p 00037000 fe:00 67899     /system/lib64/libexpat.so",
        b"7c28d000-7c28e000 rw-p 00039000 fe:00 67899     /system/lib64/libexpat.so",
        b"7c28e000-7c2b7000 r-xp 00000000 fe:00 67900     /system/lib64/libwilhelm.so",
        b"7c2b7000-7c2b9000 r--p 00028000 fe:00 67900     /system/lib64/libwilhelm.so",
        b"7c2b9000-7c2ba000 rw-p 0002a000 fe:00 67900     /system/lib64/libwilhelm.so",
        b"7c2ba000-7c415000 r-xp 00000000 fe:00 67901     /system/lib64/libicuuc.so",
        b"7c415000-7c426000 r--p 0015a000 fe:00 67901     /system/lib64/libicuuc.so",
        b"7c426000-7c429000 rw-p 0016b000 fe:00 67901     /system/lib64/libicuuc.so",
        b"7c429000-7c438000 r-xp 00000000 fe:00 67902     /system/lib64/libnativebridge.so",
        b"7c438000-7c43a000 r--p 0000e000 fe:00 67902     /system/lib64/libnativebridge.so",
        b"7c43a000-7c43b000 rw-p 00010000 fe:00 67902     /system/lib64/libnativebridge.so",
        b"7c43b000-7d243000 r-xp 00000000 fe:00 67903     /system/framework/arm64/boot.oat",
        b"7d243000-7d2ed000 r--p 00e07000 fe:00 67903     /system/framework/arm64/boot.oat",
        b"7d2ed000-7d2f1000 rw-p 00eb1000 fe:00 67903     /system/framework/arm64/boot.oat",
        b"7d2f1000-7d3f1000 rw-p 00000000 00:00 0         [anon:dalvik-alloc-space]",
        b"7d3f1000-7d471000 rw-p 00000000 00:00 0         [anon:dalvik-main-space]",
        b"7d471000-7d4f1000 rw-p 00000000 00:00 0         [anon:dalvik-non-moving-space]",
        b"7d4f1000-7d4f2000 ---p 00000000 00:00 0         [anon:signal_page]",
        b"7d4f2000-7d531000 rw-p 00000000 00:00 0         [anon:thread_db]",
        b"7d531000-7d534000 r-xp 00000000 00:00 0         [vdso]",
        b"7d534000-7d53e000 rw-p 00000000 00:00 0         [stack:1002]",
        b"7d53e000-7d542000 rw-p 00000000 00:00 0         [stack:1003]",
        b"7d542000-7d546000 rw-p 00000000 00:00 0         [stack:1004]",
        b"7de00000-7de04000 rw-p 00000000 00:00 0         [anon:scudo:primary]",
        b"7de04000-7de31000 rw-p 00000000 00:00 0         [anon:scudo:secondary]",
        b"7de31000-7df00000 rw-p 00000000 00:00 0         [anon:scudo:metadata]",
        b"7e000000-7f000000 rw-p 00000000 00:00 0         [anon:dalvik-jit-code-cache]",
        b"7ffbe000-7ffe0000 rw-p 00000000 00:00 0         [stack]",
        b"7ffe0000-7ffe1000 r-xp 00000000 00:00 0         [vdso]",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_STATUS_PATH), &[
        b"Name:   app_process64",
        b"State:  S (sleeping)",
        b"Tgid:   12345",
        b"Ngid:   0",
        b"Pid:    12345",
        b"PPid:   1",
        b"TracerPid:      0",
        b"Uid:   10123   10123   10123   10123",
        b"Gid:   10123   10123   10123   10123",
        b"FDSize:        128",
        b"Groups:        3001 9997 20123",
        b"NStgid: 12345",
        b"NSpid:  12345",
        b"NSpgid: 12345",
        b"NSsid:  12345",
        b"VmPeak:        2345678 kB",
        b"VmSize:        2345678 kB",
        b"VmLck:         0 kB",
        b"VmPin:         0 kB",
        b"VmHWM:         345678 kB",
        b"VmRSS:         345678 kB",
        b"RssAnon:       310000 kB",
        b"RssFile:        35678 kB",
        b"RssShmem:       0 kB",
        b"VmData:        567890 kB",
        b"VmStk:         132 kB",
        b"VmExe:         12 kB",
        b"VmLib:         78901 kB",
        b"VmPTE:         789 kB",
        b"VmSwap:        0 kB",
        b"HugetlbPages:  0 kB",
        b"CoreDumping:   0",
        b"THP_enabled:   1",
        b"Threads:       18",
        b"SigQ:   0/24680",
        b"SigPnd: 0000000000000000",
        b"ShdPnd: 0000000000000000",
        b"SigBlk: 0000000000001204",
        b"SigIgn: 0000000000001006",
        b"SigCgt: 00000001800044e7",
        b"CapInh: 0000000000000000",
        b"CapPrm: 0000000000000000",
        b"CapEff: 0000000000000000",
        b"CapBnd: 0000000000000000",
        b"CapAmb: 0000000000000000",
        b"NoNewPrivs:     1",
        b"Seccomp:        0",
        b"Speculation_Store_Bypass:       thread vulnerable",
        b"SpeculationIndirectBranch:      always enabled",
        b"Cpus_allowed:   ff",
        b"Cpus_allowed_list:      0-7",
        b"Mems_allowed:   1",
        b"Mems_allowed_list:      0",
        b"voluntary_ctxt_switches:        18456",
        b"nonvoluntary_ctxt_switches:     3241",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_MOUNTINFO_PATH), &[
        b"1 0 0:0 / / rw,relatime shared:1 - rootfs rootfs rw",
        b"2 1 0:1 / /dev rw,nosuid,relatime shared:2 - devtmpfs devtmpfs rw",
        b"3 1 0:3 / /proc rw,nosuid,nodev,noexec,relatime shared:3 - proc proc rw",
        b"4 1 0:4 / /sys rw,nosuid,nodev,noexec,relatime shared:4 - sysfs sysfs rw",
        b"5 1 0:5 / /system rw,relatime shared:5 - ext4 mmcblk0p43 rw",
        b"6 1 0:6 / /data rw,nosuid,nodev,noatime shared:6 - ext4 mmcblk0p44 rw",
    ]) { ok += 1; }

    if virt_decoy_file_create_binary(path_as_cstr(DECOY_CMDLINE_PATH), &[
        b"/system/bin/app_process64",
    ]) { ok += 1; }

    if virt_decoy_file_create_binary(path_as_cstr(DECOY_ENVIRON_PATH), &[
        b"PATH=/sbin:/system/sbin:/system/bin:/system/xbin",
        b"ANDROID_BOOTLOGO=1",
        b"ANDROID_ROOT=/system",
        b"ANDROID_ASSETS=/system/app",
        b"ANDROID_DATA=/data",
        b"ANDROID_STORAGE=/storage",
        b"EXTERNAL_STORAGE=/sdcard",
        b"ASEC_MOUNTPOINT=/mnt/asec",
        b"BOOTCLASSPATH=/system/framework/core-libart.jar:/system/framework/conscrypt.jar:/system/framework/okhttp.jar:/system/framework/core-junit.jar:/system/framework/bouncycastle.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/ethernet-service.jar:/system/framework/wifi-service.jar",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_UPTIME_PATH), &[
        b"98765.43 197530.86",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_STAT_PATH), &[
        b"cpu  1234567 23456 789012 987654321 12345 6789 1234 5678 0 0",
        b"cpu0 123456 2345 78901 98765432 1234 678 123 567 0 0",
        b"cpu1 123456 2345 78901 98765432 1234 678 123 567 0 0",
        b"cpu2 123456 2345 78901 98765432 1234 678 123 567 0 0",
        b"cpu3 123456 2345 78901 98765432 1234 678 123 567 0 0",
        b"cpu4 123456 2345 78901 98765432 1234 678 123 567 0 0",
        b"cpu5 123456 2345 78901 98765432 1234 678 123 567 0 0",
        b"cpu6 123456 2345 78901 98765432 1234 678 123 567 0 0",
        b"cpu7 123456 2345 78901 98765432 1234 678 123 567 0 0",
        b"intr 12345678 ...",
        b"ctxt 987654321",
        b"btime 1234567890",
        b"processes 12345",
        b"procs_running 2",
        b"procs_blocked 0",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_SELINUX_PATH), &[
        b"u:r:untrusted_app:s0:c512,c768",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_VERSION_PATH), &[
        b"Linux version 5.10.149-android13-4-00001-gdeadbeef (build-user@build-host) (Android clang version 16.0.2) #1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 2024",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_BOOTID_PATH), &[
        b"deadbeef-cafe-babe-0123-456789abcdef",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_HOSTNAME_PATH), &[
        b"localhost",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_OSRELEASE_PATH), &[
        b"5.10.149-android13-4-00001-gdeadbeef",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_OSTYPE_PATH), &[
        b"Linux",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_CPUINFO_PATH), &[
        b"Processor\t: AArch64 Processor rev 14 (aarch64)",
        b"processor\t: 0",
        b"BogoMIPS\t: 38.40",
        b"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp simdhp cpuid asimdrdb lrcpc dcpop asimddp ssbs",
        b"CPU implementer\t: 0x51",
        b"CPU architecture\t: 8",
        b"CPU variant\t: 0x2",
        b"CPU part\t: 0x801",
        b"CPU revision\t: 14",
        b"",
        b"processor\t: 1",
        b"BogoMIPS\t: 38.40",
        b"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp simdhp cpuid asimdrdb lrcpc dcpop asimddp ssbs",
        b"CPU implementer\t: 0x51",
        b"CPU architecture\t: 8",
        b"CPU variant\t: 0x2",
        b"CPU part\t: 0x801",
        b"CPU revision\t: 14",
        b"",
        b"processor\t: 2",
        b"BogoMIPS\t: 38.40",
        b"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp simdhp cpuid asimdrdb lrcpc dcpop asimddp ssbs",
        b"CPU implementer\t: 0x51",
        b"CPU architecture\t: 8",
        b"CPU variant\t: 0x2",
        b"CPU part\t: 0x801",
        b"CPU revision\t: 14",
        b"",
        b"processor\t: 3",
        b"BogoMIPS\t: 38.40",
        b"Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp simdhp cpuid asimdrdb lrcpc dcpop asimddp ssbs",
        b"CPU implementer\t: 0x51",
        b"CPU architecture\t: 8",
        b"CPU variant\t: 0x2",
        b"CPU part\t: 0x801",
        b"CPU revision\t: 14",
        b"",
        b"Hardware\t: Qualcomm Technologies, Inc SM8550",
    ]) { ok += 1; }

    // Fake modules — empty
    if virt_decoy_file_create(path_as_cstr(DECOY_MODULES_PATH), &[b""]) { ok += 1; }
    // Fake kallsyms — empty
    if virt_decoy_file_create(path_as_cstr(DECOY_KALLSYMS_PATH), &[b""]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_FAKE_EXE_PATH), &[
        b"/system/bin/app_process64",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_IO_PATH), &[
        b"rchar: 12345678",
        b"wchar: 9876543",
        b"read_bytes: 2345678",
        b"write_bytes: 876543",
    ]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_OOM_PATH), &[b"0"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_OOM_SCORE_PATH), &[b"0"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_OOM_SCORE_ADJ_PATH), &[b"0"]) { ok += 1; }

    if virt_decoy_file_create(path_as_cstr(DECOY_WCHAN_PATH), &[b"do_epoll_wait"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_STACK_PATH), &[b"[<0>] __switch_to+0x70/0x80"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_SYSCALL_PATH), &[b"running"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_PERSONALITY_PATH), &[b"00000000"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_COREDUMP_FILTER_PATH), &[b"00000000"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_TIMERS_PATH), &[b"monotonic: 0\nreal: 0"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_LOGINUID_PATH), &[b"1000"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_SESSIONID_PATH), &[b"1000"]) { ok += 1; }
    if virt_decoy_file_create(path_as_cstr(DECOY_COMM_PATH), &[b"app_process64"]) { ok += 1; }

    log_2u(b"Decoy files created: %d total\0" as *const u8 as *const c_char, ok as u32, 0);
    ok
}

// ─── Handler loop ───────────────────────────────────────────────────
// Source: seccomp_engine.cpp:1430-2546
fn virt_seccomp_handler_loop(notify_fd: i32) -> i32 {
    unsafe {
        prctl(PR_SET_NAME, b"seccomp-virt\0" as *const u8 as usize as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong);
    }

    let mut stats_processed = 0u64;
    let mut stats_blocked = 0u64;
    let mut max_latency_ns = 0u64;
    let mut consecutive_errors = 0u32;

    loop {
        let loop_start = virt_gettime_ns();

        // poll with timeout (5000ms) for signal handling
        let mut pfd = libc::pollfd {
            fd: notify_fd,
            events: POLLIN,
            revents: 0,
        };
        let poll_rc = unsafe { libc::poll(&mut pfd, 1, 5000) };
        if poll_rc < 0 {
            let err = get_errno_val();
            if err == libc::EINTR { continue; }
            consecutive_errors += 1;
            if consecutive_errors > 10 { break; }
            continue;
        }
        if poll_rc == 0 { continue; } // timeout
        if pfd.revents & POLLIN == 0 { continue; }

        let mut req: seccomp_notif = unsafe { MaybeUninit::zeroed().assume_init() };
        let rc = unsafe {
            libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV as i32, &mut req as *mut _ as *mut c_void)
        };
        if rc < 0 {
            let err = get_errno_val();
            if err == libc::EINTR { continue; }
            if err == libc::ENOENT { break; }
            if err == libc::EBADF || err == libc::ENOTTY { break; }
            virt_error_record_failure("notif");
            consecutive_errors += 1;
            if consecutive_errors > 10 { break; }
            continue;
        }

        virt_error_record_success();
        consecutive_errors = 0;
        stats_processed += 1;

        // NOTIF_ID_VALID check
        let valid = unsafe {
            libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID as i32, &req.id as *const _ as *mut c_void)
        };
        if valid < 0 { continue; }

        let nr = req.data.nr;
        let pid = req.pid;

        // Resolve path for syscalls that carry a path arg
        let mut path_buf = [0u8; 512];
        let path_addr = match nr {
            56 | 293 | 78 | 89 | 79 | 291 | 48 | 439 | 35 | 276 => req.data.args[1],
            _ => 0u64,
        };
        let path_len = if path_addr != 0 {
            resolve_path_from_target(pid, path_addr, &mut path_buf)
        } else {
            -1
        };
        let path_readable = path_len > 0;

        let mut resp: seccomp_notif_resp = seccomp_notif_resp {
            id: req.id,
            val: 0,
            error: 0,
            flags: 0,
        };

        // Dispatch by syscall number
        let mut handled = false;
        let mut should_redirect = false;

        if nr == SYS_PRCTL {
            handle_prctl(SYS_PRCTL as i64, req.data.args[0], req.data.args[1], req.data.args[2], &mut resp);
            handled = true;
        } else if nr == SYS_UNAME {
            let result = execute_uname(req.data.args[0], pid);
            resp.error = 0;
            resp.val = result;
            resp.flags = 0;
            handled = true;
        } else if nr == SYS_GETDENTS64 {
            let result = execute_getdents64(req.data.args[0], req.data.args[1], req.data.args[2], pid);
            resp.error = 0;
            resp.val = result;
            resp.flags = 0;
            handled = true;
        } else if nr == SYS_PTRACE {
            // Block ptrace on self, allow TRACEME
            let request = req.data.args[0];
            let target_pid = req.data.args[1] as u32;
            if request == 0 {
                // PTRACE_TRACEME
                resp.error = 0;
                resp.val = 0;
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            } else if target_pid == 0 || target_pid == unsafe { libc::getpid() as u32 } {
                resp.error = -1; // -EPERM
                resp.val = 0;
                resp.flags = 0;
            } else {
                resp.error = 0;
                resp.val = 0;
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            }
            handled = true;
        }

        // For path-based syscalls, check patterns
        if !handled && path_readable && path_len > 0 {
            let sensitive = {
                let p = &path_buf[..path_len as usize];
                let patterns = super::core::virt_default_blocked_patterns();
                let mut found = false;
                for pat in patterns {
                    if super::core::path_match(p, pat, 3) { // VIRT_MATCH_SUBSTRING
                        found = true;
                        break;
                    }
                }
                found
            };
            if sensitive {
                stats_blocked += 1;
                // For openat/openat2, try ADDFD redirect
                if nr == SYS_OPENAT || nr == SYS_OPENAT2 {
                    // Determine which decoy file based on path content
                    let rp = decoy_lookup_redirect(&path_buf[..path_len as usize]);
                    if let Some(rp_ptr) = rp {
                        let new_fd = virt_seccomp_try_addfd(notify_fd, req.id, rp_ptr);
                        virt_error_record_success();
                        if new_fd >= 0 {
                            should_redirect = true;
                        }
                    }
                }
                if !should_redirect {
                    // For non-openat sensitive paths, block with -ENOENT
                    resp.error = -2; // -ENOENT
                    resp.val = 0;
                    resp.flags = 0;
                    handled = true;
                }
            }
        }

        // Handle readlinkat on /exe paths — spoof
        if !handled && path_readable && path_len > 0 &&
            (nr == SYS_READLINKAT || nr == SYS_READLINK)
        {
            let p = &path_buf[..path_len as usize];
            if p.len() >= 4 && &p[p.len()-4..] == b"/exe" {
                let buf_addr = if nr == SYS_READLINKAT { req.data.args[2] } else { req.data.args[1] };
                let buf_size = if nr == SYS_READLINKAT { req.data.args[3] } else { req.data.args[2] };
                let clean_path = b"/system/bin/app_process64\0";
                let write_sz = (clean_path.len() as u64).min(buf_size) as usize;
                if write_sz > 0 {
                    let lw = iovec { iov_base: clean_path.as_ptr() as *mut c_void, iov_len: write_sz };
                    let rw = iovec { iov_base: buf_addr as *mut c_void, iov_len: write_sz };
                    unsafe {
                        syscall(__NR_process_vm_writev as i64, pid as i32, &lw, 1, &rw, 1, 0);
                    }
                }
                resp.error = 0;
                resp.val = write_sz as i64;
                resp.flags = 0;
                handled = true;
            }
        }

        // Allow /proc/self/exe fstatat through
        if !handled && path_readable && path_len > 0 &&
            nr == SYS_NEWFSTATAT &&
            path_buf[..path_len as usize].windows(4).any(|w| w == b"/exe")
        {
            resp.error = 0;
            resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            handled = true;
        }

        // Handle connect - re-execute with CONTINUE
        if !handled && nr == SYS_CONNECT {
            let ret = execute_connect(req.data.args[0], req.data.args[1], req.data.args[2]);
            resp.error = 0;
            resp.val = ret;
            resp.flags = 0;
            handled = true;
        }

        // Send response
        if should_redirect {
            // ADDFD already sent the response via the ioctl
        } else if !handled {
            // Default: CONTINUE (pass through to kernel)
            resp.error = 0;
            resp.val = 0;
            resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            let send_rc = unsafe {
                libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND as i32, &resp as *const _ as *mut c_void)
            };
            virt_error_record_success();
            if send_rc < 0 {
                let err = get_errno_val();
                if err == libc::ENOENT { continue; }
                if err == libc::EOPNOTSUPP || err == libc::EINVAL {
                    // Try fallback: execute directly
                    resp.flags = 0;
                    let exec_ret = virt_seccomp_execute_syscall_inline(&req);
                    resp.error = exec_ret as i32;
                    resp.val = 0;
                    unsafe {
                        libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND as i32, &resp as *const _ as *mut c_void);
                    }
                }
                virt_error_record_failure("respond");
                consecutive_errors += 1;
                if consecutive_errors > 10 { break; }
            }
        } else {
            let send_rc = unsafe {
                libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND as i32, &resp as *const _ as *mut c_void)
            };
            virt_error_record_success();
            if send_rc < 0 {
                let err = get_errno_val();
                if err == libc::ENOENT { continue; }
                virt_error_record_failure("respond");
            }
        }

        // Timing + jitter
        let elapsed = virt_gettime_ns() - loop_start;
        if elapsed > max_latency_ns { max_latency_ns = elapsed; }
        virt_timing_add_jitter(unsafe { TIMING_JITTER.enabled });

        // Periodic stats
        if stats_processed % 100 == 0 {
            log_2u(b"Handler progress: %lu events, %lu blocked\0" as *const u8 as *const c_char,
                   stats_processed as u32, stats_blocked as u32);
        }
    }

    unsafe { libc::close(notify_fd); }
    log_info(b"Handler loop exited\0" as *const u8 as *const c_char);
    0
}

// ─── Helper: decoy_lookup_redirect ──────────────────────────────────
fn decoy_lookup_redirect(path: &[u8]) -> Option<*const c_char> {
    // Source: seccomp_engine.cpp:2063-2117
    if path.len() < 4 { return None; }
    let s = core::str::from_utf8(path).unwrap_or("");
    if s.contains("maps") { return Some(path_as_cstr(DECOY_MAPS_PATH)); }
    if s.contains("status") { return Some(path_as_cstr(DECOY_STATUS_PATH)); }
    if s.contains("mountinfo") || s.contains("mounts") { return Some(path_as_cstr(DECOY_MOUNTINFO_PATH)); }
    if s.contains("uptime") { return Some(path_as_cstr(DECOY_UPTIME_PATH)); }
    if s.contains("/proc/stat") { return Some(path_as_cstr(DECOY_STAT_PATH)); }
    if s.contains("attr/current") || s.contains("attr/") { return Some(path_as_cstr(DECOY_SELINUX_PATH)); }
    if s.contains("/proc/version") { return Some(path_as_cstr(DECOY_VERSION_PATH)); }
    if s.contains("boot_id") { return Some(path_as_cstr(DECOY_BOOTID_PATH)); }
    if s.contains("/hostname") { return Some(path_as_cstr(DECOY_HOSTNAME_PATH)); }
    if s.contains("/osrelease") { return Some(path_as_cstr(DECOY_OSRELEASE_PATH)); }
    if s.contains("/ostype") { return Some(path_as_cstr(DECOY_OSTYPE_PATH)); }
    if s.contains("cpuinfo") { return Some(path_as_cstr(DECOY_CPUINFO_PATH)); }
    if s.contains("/cmdline") { return Some(path_as_cstr(DECOY_CMDLINE_PATH)); }
    if s.contains("/environ") { return Some(path_as_cstr(DECOY_ENVIRON_PATH)); }
    if s.contains("/proc/self/io") { return Some(path_as_cstr(DECOY_IO_PATH)); }
    if s.contains("/proc/self/oom_score_adj") { return Some(path_as_cstr(DECOY_OOM_SCORE_ADJ_PATH)); }
    if s.contains("/proc/self/oom_score") { return Some(path_as_cstr(DECOY_OOM_SCORE_PATH)); }
    if s.contains("/proc/self/oom") { return Some(path_as_cstr(DECOY_OOM_PATH)); }
    if s.contains("/proc/self/wchan") { return Some(path_as_cstr(DECOY_WCHAN_PATH)); }
    if s.contains("/proc/self/stack") { return Some(path_as_cstr(DECOY_STACK_PATH)); }
    if s.contains("/proc/self/syscall") { return Some(path_as_cstr(DECOY_SYSCALL_PATH)); }
    if s.contains("/proc/self/personality") { return Some(path_as_cstr(DECOY_PERSONALITY_PATH)); }
    if s.contains("/proc/self/coredump_filter") { return Some(path_as_cstr(DECOY_COREDUMP_FILTER_PATH)); }
    if s.contains("/proc/self/timers") { return Some(path_as_cstr(DECOY_TIMERS_PATH)); }
    if s.contains("/proc/self/loginuid") { return Some(path_as_cstr(DECOY_LOGINUID_PATH)); }
    if s.contains("/proc/self/sessionid") { return Some(path_as_cstr(DECOY_SESSIONID_PATH)); }
    if s.contains("/proc/self/comm") { return Some(path_as_cstr(DECOY_COMM_PATH)); }
    None
}

// ─── Fallback syscall executor ──────────────────────────────────────
fn virt_seccomp_execute_syscall_inline(req: &seccomp_notif) -> i64 {
    // Source: seccomp_engine.cpp:1326-1376
    let nr = req.data.nr as i64;
    let a0 = req.data.args[0];
    let a1 = req.data.args[1];
    let a2 = req.data.args[2];
    let a3 = req.data.args[3];
    let a4 = req.data.args[4];
    let a5 = req.data.args[5];
    let pid = req.pid;

    match nr {
        48 => execute_faccessat(a0, a1, a2),
        439 => execute_faccessat2(a0, a1, a2, a3),
        56 => execute_openat(a0, a1, a2, a3),
        293 => {
            // openat2 - not directly supported, return -ENOSYS
            get_errno()
        }
        78 => execute_readlinkat(a0, a1, a2, a3, pid),
        89 => execute_readlink(a0, a1, a2, pid),
        79 => execute_newfstatat(a0, a1, a2, a3, pid),
        291 => execute_statx(a0, a1, a2, a3, a4, pid),
        61 => execute_getdents64(a0, a1, a2, pid),
        203 => execute_connect(a0, a1, a2),
        222 => execute_mmap(a0, a1, a2, a3, a4, a5),
        226 => execute_mprotect(a0, a1, a2),
        117 => -1, // -EPERM
        160 => execute_uname(a0, pid),
        35 | 276 => -2, // -ENOENT
        _ => -38, // -ENOSYS
    }
}

// ─── Handler thread creation ────────────────────────────────────────
// Source: seccomp_engine.cpp:2829-2847
extern "C" fn handler_thread_entry(arg: *mut c_void) -> *mut c_void {
    let notify_fd = arg as i32;
    virt_seccomp_handler_loop(notify_fd);
    ptr::null_mut()
}

pub fn virt_seccomp_start_handler_monitor(notify_fd: i32) -> i32 {
    // Source: seccomp_engine.cpp:2829-2847
    let mut attr: MaybeUninit<libc::pthread_attr_t> = MaybeUninit::uninit();
    let ret_init = unsafe { libc::pthread_attr_init(attr.as_mut_ptr()) };
    if ret_init != 0 { return -10; }

    unsafe {
        libc::pthread_attr_setdetachstate(attr.as_mut_ptr(), libc::PTHREAD_CREATE_DETACHED);
        libc::pthread_attr_setstacksize(attr.as_mut_ptr(), VIRT_HANDLER_STACK_SIZE);
    }

    let mut thread: MaybeUninit<libc::pthread_t> = MaybeUninit::uninit();
    let ret = unsafe {
        pthread_create(
            thread.as_mut_ptr(),
            attr.as_ptr(),
            handler_thread_entry as extern "C" fn(*mut c_void) -> *mut c_void,
            notify_fd as *mut c_void,
        )
    };
    unsafe { libc::pthread_attr_destroy(attr.as_mut_ptr()); }

    if ret != 0 {
        log_error(b"Failed to create handler thread\0" as *const u8 as *const c_char);
        return -10;
    }

    log_2u(b"Handler thread started for fd=%d pid=%d\0" as *const u8 as *const c_char,
           notify_fd as u32, unsafe { libc::getpid() as u32 });
    0
}
