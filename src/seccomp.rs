use ::core::ffi::{c_char, c_int, c_uint, c_void};

const ANDROID_LOG_INFO: c_int = 4;
const TAG: *const c_char = b"RustVirt\0" as *const u8 as *const c_char;

extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
    fn open(path: *const c_char, flags: c_int, mode: c_uint) -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn ioctl(fd: c_int, request: u64, ...) -> c_int;
    fn syscall(nr: i64, ...) -> i64;
    fn pthread_create(thread: *mut u64, attr: *const c_void, start: unsafe extern "C" fn(*mut c_void) -> *mut c_void, arg: *mut c_void) -> c_int;
    fn pthread_attr_init(attr: *mut c_void) -> c_int;
    fn pthread_attr_setdetachstate(attr: *mut c_void, detachstate: c_int) -> c_int;
    fn pthread_attr_destroy(attr: *mut c_void) -> c_int;
}

// ─── BPF constants ──────────────────────────────────────────────

#[repr(C)] #[derive(Copy, Clone)]
pub struct sock_filter { pub code: u16, pub jt: u8, pub jf: u8, pub k: u32 }

#[repr(C)] #[derive(Copy, Clone)]
pub struct sock_fprog { pub len: u16, pub filter: *const sock_filter }

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;

const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_KILL: u32 = 0x00000000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;
const AUDIT_ARCH_AARCH64: u32 = 0xC00000B7;

const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0x40;
const O_TRUNC: c_int = 0x200;
const O_CLOEXEC: c_int = 0x80000;

fn log_2u(fmt: *const c_char, a: u32, b: u32) {
    unsafe { __android_log_print(ANDROID_LOG_INFO, TAG, fmt, a, b); }
}
fn log_s(msg: *const c_char) {
    unsafe { __android_log_print(ANDROID_LOG_INFO, TAG, msg); }
}

// ─── BPF helpers ─────────────────────────────────────────────────

fn bpf_stmt(code: u16, k: u32) -> sock_filter {
    sock_filter { code, jt: 0, jf: 0, k }
}
fn bpf_jump(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

// ─── Seccomp notification types ──────────────────────────────────

#[repr(C)]
pub struct seccomp_data { pub nr: c_int, pub arch: u32, pub instruction_pointer: u64, pub args: [u64; 6] }

#[repr(C)]
pub struct seccomp_notif { pub id: u64, pub pid: u32, pub flags: u32, pub data: seccomp_data }

#[repr(C)]
pub struct seccomp_notif_resp { pub id: u64, pub val: i64, pub error: i32, pub flags: u32 }

const SYS_SECCOMP: i64 = 277;
const SECCOMP_SET_MODE_FILTER: c_int = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 0x20;
const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xc0502100;
const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xc0182101;

// ─── BPF filter ──────────────────────────────────────────────────

fn build_seccomp_filter() -> ([sock_filter; 48], u16) {
    let mut f = [sock_filter { code: 0, jt: 0, jf: 0, k: 0 }; 48];
    let mut i: u16 = 0;

    f[i as usize] = bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4);
    i += 1;
    f[i as usize] = bpf_jump(BPF_JMP | BPF_JEQ, 1, 0, AUDIT_ARCH_AARCH64);
    i += 1;
    f[i as usize] = bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL);
    i += 1;
    f[i as usize] = bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0);
    i += 1;

    let notified: &[i64] = &[56, 293, 78, 89, 79, 291, 48, 439, 61, 222, 226, 203, 198, 29, 167, 160, 117];
    for &nr in notified {
        if i as usize >= f.len() - 3 { break; }
        f[i as usize] = bpf_jump(BPF_JMP | BPF_JEQ, 3, 0, nr as u32);
        i += 1;
    }

    f[i as usize] = bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    i += 1;
    f[i as usize] = bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    i += 1;

    (f, i)
}

// ─── Decoy files ─────────────────────────────────────────────────

pub fn virt_seccomp_create_decoy_files() -> i32 {
    let files: &[(&[u8], &[u8])] = &[
        (b"/data/local/tmp/virtualizer/maps\0",
         b"12ab0000-12ac0000 r-xp 00000000 08:01 123456 /system/bin/app_process64\n12ac0000-12ad0000 rw-p 00010000 08:01 123456 /system/bin/app_process64\n"),
        (b"/data/local/tmp/virtualizer/status\0",
         b"Name: app_process64\nState: S (sleeping)\nTgid: 1234\nPid: 1234\nTracerPid: 0\nUid: 0 0 0 0\n"),
    ];
    for (path, content) in files {
        let fd = unsafe { open(path.as_ptr() as *const c_char, O_WRONLY | O_CREAT | O_TRUNC, 0o644) };
        if fd >= 0 {
            unsafe { write(fd, content.as_ptr() as *const c_void, content.len() - 1); close(fd); }
        }
    }
    0
}

static mut DECOY_FDS: [i32; 8] = [-1; 8];
static mut DECOY_FD_COUNT: i32 = 0;

pub fn virt_decoy_fd_preopen_all() -> i32 {
    let paths: &[&[u8]] = &[
        b"/data/local/tmp/virtualizer\0",
        b"/data/local/tmp/virtualizer/maps\0",
        b"/data/local/tmp/virtualizer/status\0",
    ];
    let mut count = 0i32;
    for p in paths {
        if count >= 8 { break; }
        let fd = unsafe { open(p.as_ptr() as *const c_char, O_RDONLY | O_CLOEXEC, 0) };
        if fd >= 0 { unsafe { DECOY_FDS[count as usize] = fd; } count += 1; }
    }
    unsafe { DECOY_FD_COUNT = count; }
    count
}

// ─── Install filter ──────────────────────────────────────────────

pub fn virt_seccomp_install_static_default() -> i32 {
    let (filter, len) = build_seccomp_filter();
    let prog = sock_fprog { len, filter: &filter as *const sock_filter };
    let fd = unsafe { syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER as i64, SECCOMP_FILTER_FLAG_NEW_LISTENER as i64, &prog as *const sock_fprog as i64) };
    if fd < 0 {
        let fd2 = unsafe { syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER as i64, 0i64, &prog as *const sock_fprog as i64) };
        return if fd2 < 0 { -1 } else { fd2 as i32 };
    }
    fd as i32
}

// ─── Handler loop ────────────────────────────────────────────────

fn is_sensitive_path(path: &[u8]) -> bool {
    let p: &[&[u8]] = &[b"/su", b"/magisk", b"/sbin/.magisk", b"/data/adb",
        b"/system/bin/su", b"/system/xbin/su",
        b"frida", b"xposed", b"XposedBridge",
        b"/proc/self/pagemap", b"/proc/self/smaps",
        b"/proc/self/mem", b"/proc/self/stack", b"/proc/self/syscall",
        b"/proc/self/mountinfo", b"/proc/self/exe"];
    for pat in p {
        if path.windows(pat.len()).any(|w| w == *pat) { return true; }
    }
    false
}

fn find_decoy(path: &[u8]) -> i32 {
    if path.windows(5).any(|w| w == b"/maps") {
        return unsafe { open(b"/data/local/tmp/virtualizer/maps\0".as_ptr() as *const c_char, O_RDONLY | O_CLOEXEC, 0) };
    }
    if path.windows(7).any(|w| w == b"/status") {
        return unsafe { open(b"/data/local/tmp/virtualizer/status\0".as_ptr() as *const c_char, O_RDONLY | O_CLOEXEC, 0) };
    }
    -1
}

fn resolve_path(args: &[u64; 6], nr: i64) -> [u8; 4096] {
    let mut buf = [0u8; 4096];
    let addr = if nr == 56 || nr == 293 { args[1] } else if nr == 78 || nr == 79 || nr == 291 || nr == 48 || nr == 439 { args[1] } else if nr == 89 { args[0] } else { return buf; };
    unsafe {
        let p = addr as *const u8;
        for i in 0..4095 {
            let b = *p.add(i);
            buf[i] = b;
            if b == 0 { break; }
        }
    }
    buf
}

pub fn virt_seccomp_handler_loop(fd: i32) {
    log_2u(b"handler_loop started fd=%d\0".as_ptr() as *const c_char, fd as u32, 0);
    loop {
        let mut notif = seccomp_notif { id: 0, pid: 0, flags: 0, data: seccomp_data { nr: 0, arch: 0, instruction_pointer: 0, args: [0; 6] } };
        let ret = unsafe { ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif as *mut seccomp_notif) };
        if ret < 0 { break; }
        if notif.data.nr == 0 { continue; }
        let path = resolve_path(&notif.data.args, notif.data.nr as i64);
        let mut resp = seccomp_notif_resp { id: notif.id, val: 0, error: 0, flags: 0 };
        if is_sensitive_path(&path) {
            let decoy_fd = find_decoy(&path);
            if decoy_fd >= 0 {
                resp.error = -2;
            } else {
                resp.error = -2;
            }
        } else {
            resp.flags = 1; // CONTINUE
        }
        if unsafe { ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp as *const seccomp_notif_resp) } < 0 { break; }
    }
    log_s(b"handler_loop exiting\0".as_ptr() as *const c_char);
}

pub fn virt_seccomp_start_handler_monitor(notify_fd: i32) -> i32 {
    let fd = notify_fd;
    let mut thread: u64 = 0;
    let mut attr: [u64; 8] = [0; 8];
    unsafe {
        pthread_attr_init(attr.as_mut_ptr() as *mut c_void);
        pthread_attr_setdetachstate(attr.as_mut_ptr() as *mut c_void, 1);
        extern "C" fn handler_wrapper(arg: *mut c_void) -> *mut c_void {
            virt_seccomp_handler_loop(arg as i32);
            ::core::ptr::null_mut()
        }
        let tret = pthread_create(&mut thread, attr.as_ptr() as *const c_void, handler_wrapper, fd as *mut c_void);
        pthread_attr_destroy(attr.as_mut_ptr() as *mut c_void);
        tret
    }
}
