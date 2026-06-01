// SPDX-License-Identifier: MIT
#![allow(non_camel_case_types, dead_code)]

use ::core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use ::core::ptr;

const ANDROID_LOG_INFO: c_int = 4;

extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
    fn getuid() -> u32;
    fn getpid() -> u32;
    fn prctl(option: c_int, a2: c_ulong, a3: c_ulong, a4: c_ulong, a5: c_ulong) -> c_int;
    fn access(path: *const c_char, mode: c_int) -> c_int;
    fn stat(path: *const c_char, buf: *mut c_void) -> c_int;
    fn open(path: *const c_char, flags: c_int, mode: c_uint) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int;
    fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
    fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
    fn syscall(nr: i64, ...) -> i64;
}

const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0x40;
const O_TRUNC: c_int = 0x200;
const O_EXCL: c_int = 0x80;
const O_RDONLY: c_int = 0;
const O_CLOEXEC: c_int = 0x80000;

const SYS_SECCOMP: i64 = 277;
const SYS_GETDENTS64: i64 = 61;
const SYS_OPENAT: i64 = 56;
const SYS_OPENAT2: i64 = 293;
const SYS_READLINKAT: i64 = 78;
const SYS_READLINK: i64 = 89;
const SYS_NEWFSTATAT: i64 = 79;
const SYS_STATX: i64 = 291;
const SYS_FACCESSAT: i64 = 48;
const SYS_FACCESSAT2: i64 = 439;
const SYS_CONNECT: i64 = 203;
const SYS_MMAP: i64 = 222;
const SYS_MPROTECT: i64 = 226;
const SYS_PRCTL: i64 = 167;
const SYS_UNAME: i64 = 160;
const SYS_PTRACE: i64 = 117;
const SYS_IOCTL: i64 = 29;
const SYS_SOCKET: i64 = 198;

const SECCOMP_SET_MODE_FILTER: c_int = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: c_uint = 0x20;
const SECCOMP_FILTER_FLAG_TSYNC: c_uint = 0x4000;

const AUDIT_ARCH_AARCH64: u32 = 0xC00000B7;

const VIRT_ENV_UNKNOWN: i32 = 0;
const VIRT_ENV_MAGISK: i32 = 1;
const VIRT_ENV_KERNELSU: i32 = 2;
const VIRT_ENV_APATCH: i32 = 3;

const TAG: *const c_char = b"RustVirt\0" as *const u8 as *const c_char;

fn log_s(msg: *const c_char) {
    unsafe { __android_log_print(ANDROID_LOG_INFO, TAG, msg); }
}
fn log_2u(fmt: *const c_char, a: u32, b: u32) {
    unsafe { __android_log_print(ANDROID_LOG_INFO, TAG, fmt, a, b); }
}

// ─── Zygisk ABI types ────────────────────────────────────────────
#[repr(C)] pub struct JNIEnv([u8; 0]);

#[repr(C)] pub struct JNINativeMethod {
    pub name: *const u8,
    pub signature: *const u8,
    pub fn_ptr: *mut c_void,
}

#[repr(C)] pub struct AppSpecializeArgs {
    pub size: usize,
    pub uid: u32,
    pub pid: u32,
    pub app_data_dir: *const u8,
    pub nice_name: *const u8,
    pub process_name: *const u8,
    pub app_data_dir_java: *mut c_void,
    pub package_name: *const u8,
}

#[repr(C)] pub struct ServerSpecializeArgs {
    pub size: usize,
    pub uid: u32,
    pub pid: u32,
    pub process_name: *const u8,
}

#[repr(C)] pub struct ModuleBaseVtable {
    pub on_load: Option<unsafe extern "C" fn(*mut ModuleBase, *mut ApiTable, *mut JNIEnv)>,
    pub pre_app_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *mut AppSpecializeArgs)>,
    pub post_app_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *const AppSpecializeArgs)>,
    pub pre_server_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *mut ServerSpecializeArgs)>,
    pub post_server_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *const ServerSpecializeArgs)>,
}

#[repr(C)] pub struct ModuleBase {
    pub vtable: *const ModuleBaseVtable,
}

#[repr(C)] pub struct ModuleAbi {
    pub api_version: i64,
    pub impl_: *mut ModuleBase,
    pub pre_app_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *mut AppSpecializeArgs)>,
    pub post_app_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *const AppSpecializeArgs)>,
    pub pre_server_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *mut ServerSpecializeArgs)>,
    pub post_server_specialize: Option<unsafe extern "C" fn(*mut ModuleBase, *const ServerSpecializeArgs)>,
}

#[repr(C)] pub struct ApiTable {
    pub impl_: *mut c_void,
    pub register_module: Option<unsafe extern "C" fn(*mut ApiTable, *mut ModuleAbi) -> bool>,
    pub hook_jni_native_methods: Option<unsafe extern "C" fn(*mut JNIEnv, *const u8, *const JNINativeMethod, i32)>,
    pub plt_hook_register: Option<unsafe extern "C" fn(u64, u64, *const u8, *mut c_void, *mut *mut c_void)>,
    pub exempt_fd: Option<unsafe extern "C" fn(i32) -> bool>,
    pub plt_hook_commit: Option<unsafe extern "C" fn() -> bool>,
    pub connect_companion: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    pub set_option: Option<unsafe extern "C" fn(*mut c_void, u32)>,
    pub get_module_dir: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    pub get_flags: Option<unsafe extern "C" fn(*mut c_void) -> u32>,
}

const ZYGISK_API_VERSION: i64 = 16;

// ─── Seccomp types ───────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_fprog {
    pub len: u16,
    pub filter: *const sock_filter,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_filter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_K: u16 = 0x00;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;

pub const SECCOMP_RET_KILL: u32 = 0x00000000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff00000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;

// ─── Helper functions ────────────────────────────────────────────

fn virt_get_process_name(buf: &mut [u8]) {
    let fd = unsafe { open(b"/proc/self/cmdline\0".as_ptr() as *const c_char, O_RDONLY, 0) };
    if fd < 0 { return; }
    let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len() - 1) };
    unsafe { close(fd); }
    if n <= 0 { return; }
    let n = n as usize;
    buf[n] = 0;
    for i in 0..n {
        if buf[i] == 0 { buf[i] = b'/'; break; }
    }
}

fn virt_is_zygote_process() -> bool {
    let uid = unsafe { getuid() };
    if uid > 0 && uid < 10000 { return false; }
    if uid >= 10000 { return false; }
    let marker = b"/data/local/tmp/.virt_zygote_marker\0";
    let mut st: [u8; 144] = [0; 144];
    if unsafe { stat(marker.as_ptr() as *const c_char, st.as_mut_ptr() as *mut c_void) } == 0 { return false; }
    let fd = unsafe { open(marker.as_ptr() as *const c_char, O_WRONLY | O_CREAT | O_EXCL, 0o644) };
    if fd >= 0 { unsafe { close(fd); } return true; }
    false
}

fn virt_is_system_process_by_uid(uid: u32) -> bool {
    uid > 0 && uid < 10000
}

const EXCLUDED: &[&[u8]] = &[
    b"com.google.android.gms.unstable\0",
    b"com.google.android.gms.persistent\0",
    b"com.google.android.gms\0",
    b"com.android.chrome\0",
    b"system_server\0",
];

fn virt_is_excluded_process(name: *const c_char) -> bool {
    if name.is_null() { return false; }
    unsafe {
        if !strstr(name, b"_zygote\0".as_ptr() as *const c_char).is_null() { return true; }
        if !strstr(name, b"com.android.chrome:sandboxed_process\0".as_ptr() as *const c_char).is_null() { return true; }
        if !strstr(name, b"com.google.android.webview:sandboxed_process\0".as_ptr() as *const c_char).is_null() { return true; }
        if !strstr(name, b":isolation\0".as_ptr() as *const c_char).is_null() { return true; }
        if !strstr(name, b":isolated\0".as_ptr() as *const c_char).is_null() { return true; }
        for p in EXCLUDED {
            if strcmp(name, p.as_ptr() as *const c_char) == 0 { return true; }
        }
    }
    false
}

fn virt_seccomp_get_features(out: &mut i32) -> i32 {
    *out = 0x7b;
    0
}

fn virt_detect_environment() -> i32 {
    if unsafe { access(b"/data/adb/magisk\0".as_ptr() as *const c_char, 0) } == 0 { return VIRT_ENV_MAGISK; }
    if unsafe { access(b"/data/adb/ksu\0".as_ptr() as *const c_char, 0) } == 0 { return VIRT_ENV_KERNELSU; }
    if unsafe { access(b"/data/apatch\0".as_ptr() as *const c_char, 0) } == 0 { return VIRT_ENV_APATCH; }
    VIRT_ENV_UNKNOWN
}

fn virt_is_safe_mode() -> i32 {
    let checks: &[&[u8]] = &[
        b"/cache/.disable_magisk\0", b"/data/unencrypted/.disable_magisk\0",
        b"/persist/.disable_magisk\0", b"/data/adb/ksu/.disable_ksu\0",
    ];
    for p in checks {
        let mut st: [u8; 144] = [0; 144];
        if unsafe { stat(p.as_ptr() as *const c_char, st.as_mut_ptr() as *mut c_void) } == 0 { return 1; }
    }
    0
}

// ─── Module implementation ───────────────────────────────────────

static mut LOAD_COUNT: u32 = 0;
static mut APP_COUNT: u32 = 0;
static mut FAIL_COUNT: u32 = 0;
static mut EXCLUDED_COUNT: u32 = 0;
static mut SYSTEM_COUNT: u32 = 0;

unsafe extern "C" fn on_load_impl(
    _module: *mut ModuleBase, _api: *mut ApiTable, _env: *mut JNIEnv,
) {
    let uid = getuid();
    let pid = getpid();
    log_2u(b"onLoad ENTERED uid=%d pid=%d\0".as_ptr() as *const c_char, uid, pid);
    LOAD_COUNT += 1;
    let mut features: i32 = 0;
    virt_seccomp_get_features(&mut features);
    log_2u(b"onLoad STEP2: features=0x%x uid=%d\0".as_ptr() as *const c_char, features as u32, uid);
    let rt_env = virt_detect_environment();
    let mut proc_name: [u8; 256] = [0; 256];
    virt_get_process_name(&mut proc_name);
    log_2u(b"onLoad STEP3: env=%d uid=%d\0".as_ptr() as *const c_char, rt_env as u32, uid);
    if virt_is_safe_mode() != 0 { log_s(b"onLoad: safe mode\0".as_ptr() as *const c_char); return; }
    if virt_is_system_process_by_uid(uid) {
        SYSTEM_COUNT += 1;
        log_s(b"onLoad: system uid, skip\0".as_ptr() as *const c_char);
        return;
    }
    if virt_is_excluded_process(proc_name.as_ptr() as *const c_char) {
        EXCLUDED_COUNT += 1;
        log_s(b"onLoad: excluded proc, skip\0".as_ptr() as *const c_char);
        return;
    }
    if uid >= 10000 && uid < 100000 {
        APP_COUNT += 1;
        log_2u(b"onLoad: installing seccomp for app uid=%d pid=%d\0".as_ptr() as *const c_char, uid, pid);
        seccomp::virt_seccomp_create_decoy_files();
        seccomp::virt_decoy_fd_preopen_all();
        let mut cfg = core::virt_config_default();
        core::virt_config_auto_tune(&mut cfg);
        core::virt_decoy_init(&cfg);
        let fd = seccomp::virt_seccomp_install_static_default();
        if fd >= 0 {
            seccomp::virt_seccomp_start_handler_monitor(fd);
            log_2u(b"onLoad: seccomp active fd=%d pid=%d\0".as_ptr() as *const c_char, fd as u32, pid);
        } else {
            FAIL_COUNT += 1;
            log_s(b"onLoad: seccomp install FAILED\0".as_ptr() as *const c_char);
        }
        return;
    }
    if uid == 0 && virt_is_zygote_process() {
        log_s(b"onLoad: real zygote, deferring\0".as_ptr() as *const c_char);
        return;
    }
    APP_COUNT += 1;
    log_2u(b"onLoad: forked proc uid=%d pid=%d\0".as_ptr() as *const c_char, uid, pid);
    seccomp::virt_seccomp_create_decoy_files();
    seccomp::virt_decoy_fd_preopen_all();
    let mut cfg = core::virt_config_default();
    core::virt_config_auto_tune(&mut cfg);
    core::virt_decoy_init(&cfg);
    let fd = seccomp::virt_seccomp_install_static_default();
    if fd >= 0 {
        seccomp::virt_seccomp_start_handler_monitor(fd);
        log_2u(b"onLoad: seccomp active fd=%d pid=%d\0".as_ptr() as *const c_char, fd as u32, pid);
    } else {
        FAIL_COUNT += 1;
        log_s(b"onLoad: seccomp install FAILED\0".as_ptr() as *const c_char);
    }
}

unsafe extern "C" fn pre_app_specialize_impl(
    _module: *mut ModuleBase, _args: *mut AppSpecializeArgs,
) {
    let uid = getuid();
    log_2u(b"preAppSpecialize ENTERED uid=%d pid=%d\0".as_ptr() as *const c_char, uid, getpid());
    if APP_COUNT > 0 { log_s(b"already active\0".as_ptr() as *const c_char); return; }
    if virt_is_system_process_by_uid(uid) { log_s(b"system uid\0".as_ptr() as *const c_char); return; }
    if uid >= 10000 {
        let mut pn: [u8; 256] = [0; 256];
        virt_get_process_name(&mut pn);
        log_2u(b"preAppSpecialize: app uid=%d pid=%d\0".as_ptr() as *const c_char, uid, getpid());
        if virt_is_excluded_process(pn.as_ptr() as *const c_char) {
            log_s(b"excluded proc\0".as_ptr() as *const c_char);
            return;
        }
        log_s(b"preAppSpecialize: seccomp NYI\0".as_ptr() as *const c_char);
    }
}

const MODULE_VTABLE: ModuleBaseVtable = ModuleBaseVtable {
    on_load: Some(on_load_impl as unsafe extern "C" fn(*mut ModuleBase, *mut ApiTable, *mut JNIEnv)),
    pre_app_specialize: Some(pre_app_specialize_impl as unsafe extern "C" fn(*mut ModuleBase, *mut AppSpecializeArgs)),
    post_app_specialize: None,
    pre_server_specialize: None,
    post_server_specialize: None,
};

static mut MODULE: ModuleBase = ModuleBase { vtable: &MODULE_VTABLE };

#[used]
#[link_section = ".init_array"]
static CONSTRUCTOR: unsafe extern "C" fn() = ctor;

unsafe extern "C" fn ctor() {
    let path = b"/data/local/tmp/rust_virt_ctor\0";
    let fd = open(path.as_ptr() as *const c_char, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if fd >= 0 {
        write(fd, b"rust_virt_ctor\n\0".as_ptr() as *const c_void, 14);
        close(fd);
    }
    log_2u(b"LIB LOADED: constructor uid=%d pid=%d\0".as_ptr() as *const c_char, getuid(), getpid());
}

unsafe extern "C" fn on_load_thunk(base: *mut ModuleBase, table: *mut ApiTable, env: *mut JNIEnv) {
    let v = &*(*base).vtable;
    if let Some(f) = v.on_load { f(base, table, env); }
}
unsafe extern "C" fn pre_app_specialize_thunk(base: *mut ModuleBase, args: *mut AppSpecializeArgs) {
    let v = &*(*base).vtable;
    if let Some(f) = v.pre_app_specialize { f(base, args); }
}
unsafe extern "C" fn post_app_specialize_thunk(base: *mut ModuleBase, args: *const AppSpecializeArgs) {
    let v = &*(*base).vtable;
    if let Some(f) = v.post_app_specialize { f(base, args); }
}
unsafe extern "C" fn pre_server_specialize_thunk(base: *mut ModuleBase, args: *mut ServerSpecializeArgs) {
    let v = &*(*base).vtable;
    if let Some(f) = v.pre_server_specialize { f(base, args); }
}
unsafe extern "C" fn post_server_specialize_thunk(base: *mut ModuleBase, args: *const ServerSpecializeArgs) {
    let v = &*(*base).vtable;
    if let Some(f) = v.post_server_specialize { f(base, args); }
}

static mut ABI: ModuleAbi = ModuleAbi {
    api_version: ZYGISK_API_VERSION,
    impl_: ptr::null_mut(),
    pre_app_specialize: Some(pre_app_specialize_thunk as unsafe extern "C" fn(*mut ModuleBase, *mut AppSpecializeArgs)),
    post_app_specialize: Some(post_app_specialize_thunk as unsafe extern "C" fn(*mut ModuleBase, *const AppSpecializeArgs)),
    pre_server_specialize: Some(pre_server_specialize_thunk as unsafe extern "C" fn(*mut ModuleBase, *mut ServerSpecializeArgs)),
    post_server_specialize: Some(post_server_specialize_thunk as unsafe extern "C" fn(*mut ModuleBase, *const ServerSpecializeArgs)),
};

// ─── Entry point ─────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn zygisk_module_entry(table: *mut ApiTable, _env: *mut JNIEnv) {
    log_s(b"zygisk_module_entry ENTERED\0".as_ptr() as *const c_char);
    ABI.impl_ = &raw mut MODULE;
    let register = match (*table).register_module {
        Some(f) => f,
        None => { log_s(b"register NULL\0".as_ptr() as *const c_char); return; }
    };
    if !register(table, &raw mut ABI) {
        log_s(b"register FAILED\0".as_ptr() as *const c_char);
        return;
    }
    on_load_thunk(&raw mut MODULE, table, _env);
}
pub mod seccomp;
pub mod core;
