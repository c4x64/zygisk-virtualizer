// SPDX-License-Identifier: MIT
//! Core data structures and logic for the Zygisk Virtualizer on ARM64 Android.
//! Ported from virtualizer.h / virtualizer_core.cpp.
#![allow(non_upper_case_globals, non_snake_case)]

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Error codes ───────────────────────────────────────────────────────────
// ported from virtualizer.h lines 940-965
pub const VIRT_OK: i32 = 0;
pub const VIRT_ERR_NOMEM: i32 = -1;
pub const VIRT_ERR_INVAL: i32 = -2;
pub const VIRT_ERR_NODEV: i32 = -3;
pub const VIRT_ERR_TIMEOUT: i32 = -5;
pub const VIRT_ERR_BPF: i32 = -8;
pub const VIRT_ERR_SECCOMP: i32 = -9;
pub const VIRT_ERR_HANDLER: i32 = -10;
pub const VIRT_ERR_CONFIG: i32 = -11;
pub const VIRT_ERR_IO: i32 = -12;
pub const VIRT_ERR_CORRUPT: i32 = -13;
pub const VIRT_ERR_BUSY: i32 = -14;
pub const VIRT_ERR_NOENT: i32 = -96;
pub const VIRT_ERR_PERM: i32 = -97;
pub const VIRT_ERR_GENERIC: i32 = -99;

// ─── Action constants ─────────────────────────────────────────────────────
// ported from virtualizer.h lines 885-901
pub const VIRT_ACTION_ALLOW: i32 = 0;
pub const VIRT_ACTION_BLOCK_ENOENT: i32 = 1;
pub const VIRT_ACTION_BLOCK_EACCES: i32 = 2;
pub const VIRT_ACTION_BLOCK_EPERM: i32 = 3;
pub const VIRT_ACTION_BLOCK_ENXIO: i32 = 4;
pub const VIRT_ACTION_BLOCK_EIO: i32 = 5;
pub const VIRT_ACTION_BLOCK_EROFS: i32 = 6;
pub const VIRT_ACTION_REDIRECT_PATH: i32 = 7;
pub const VIRT_ACTION_FAKE_CONTENT: i32 = 8;
pub const VIRT_ACTION_FAKE_EMPTY: i32 = 9;
pub const VIRT_ACTION_FAKE_MAPS: i32 = 10;
pub const VIRT_ACTION_FAKE_STATUS: i32 = 11;
pub const VIRT_ACTION_PASS_THROUGH: i32 = 12;
pub const VIRT_ACTION_MONITOR: i32 = 13;
pub const VIRT_ACTION_COUNT: usize = 14;

// ported from virtualizer.h line 1495
pub const ACTION_ERRNO_TABLE: [(i32, i32); 8] = [
    (VIRT_ACTION_ALLOW, 0),
    (VIRT_ACTION_BLOCK_ENOENT, 2),  // ENOENT
    (VIRT_ACTION_BLOCK_EACCES, 13), // EACCES
    (VIRT_ACTION_BLOCK_EPERM, 1),   // EPERM
    (VIRT_ACTION_BLOCK_ENXIO, 6),   // ENXIO
    (VIRT_ACTION_BLOCK_EIO, 5),     // EIO
    (VIRT_ACTION_PASS_THROUGH, 0),
    (VIRT_ACTION_MONITOR, 0),
];

// ported from virtualizer.h line 1520
pub const VIRT_ACTION_NAMES: [&str; VIRT_ACTION_COUNT] = [
    "allow",
    "block-enoent",
    "block-eacces",
    "block-eperm",
    "block-enxio",
    "block-eio",
    "block-erofs",
    "redirect",
    "fake-content",
    "fake-empty",
    "fake-maps",
    "fake-status",
    "pass-through",
    "monitor",
];

// ─── Category constants ───────────────────────────────────────────────────
// ported from virtualizer.h lines 910-921
pub const VIRT_CAT_FILE_READ: i32 = 0;
pub const VIRT_CAT_FILE_WRITE: i32 = 1;
pub const VIRT_CAT_FILE_META: i32 = 2;
pub const VIRT_CAT_PROC: i32 = 3;
pub const VIRT_CAT_NETWORK: i32 = 4;
pub const VIRT_CAT_MEMORY: i32 = 5;
pub const VIRT_CAT_DEBUG: i32 = 7;
pub const VIRT_CAT_OTHER: i32 = 8;
pub const VIRT_CAT_COUNT: usize = 9;
pub const VIRT_CATEGORY_NAMES: [&str; VIRT_CAT_COUNT] = [
    "file_read",
    "file_write",
    "file_meta",
    "proc",
    "network",
    "memory",
    "exec",
    "debug",
    "other",
];

// ─── Match type constants ─────────────────────────────────────────────────
// ported from virtualizer.h lines 873-883
pub const VIRT_MATCH_EXACT: i32 = 0;
pub const VIRT_MATCH_PREFIX: i32 = 1;
pub const VIRT_MATCH_SUFFIX: i32 = 2;
pub const VIRT_MATCH_SUBSTRING: i32 = 3;
pub const VIRT_MATCH_GLOB: i32 = 4;
pub const VIRT_MATCH_ALWAYS: i32 = 6;
pub const VIRT_MATCH_NEVER: i32 = 7;

// ─── Config ───────────────────────────────────────────────────────────────
// ported from virtualizer.h lines 1071-1117
pub const VIRT_PATH_BUF_SIZE: usize = 4096;
pub const VIRT_PROC_NAME_MAX: usize = 256;
pub const VIRT_MAX_CACHED_PATHS: u32 = 8192;
pub const VIRT_MAX_RULES: u32 = 1024;
pub const VIRT_HANDLER_STACK_SIZE: u32 = 256 * 1024;
pub const VIRT_NOTIF_FD_TIMEOUT_MS: u32 = 5000;

#[derive(Clone, Debug)]
pub struct VIRT_Config {
    pub config_path: [u8; VIRT_PATH_BUF_SIZE],
    pub enable_file_decoy: bool,
    pub enable_cache: bool,
    pub cache_size: u32,
    pub max_rules: u32,
    pub handler_stack_size: u32,
    pub notif_timeout_ms: u32,
    pub max_consecutive_errors: u32,
    pub enable_watchdog: bool,
    pub enable_anti_tamper: bool,
    pub enable_proc_hiding: bool,
    pub enable_timing_jitter: bool,
    pub enable_thread_sync: bool,
    pub enable_kernel_compat: bool,
    pub enable_openat_intercept: bool,
    pub enable_readlinkat_intercept: bool,
    pub enable_connect_intercept: bool,
    pub enable_mmap_intercept: bool,
    pub default_action: i32,
    pub filter_mode: u32,
    pub log_tag: [u8; 64],
}

impl VIRT_Config {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for VIRT_Config {
    // ported from virtualizer.h VIRT_DEFAULT_CONFIG lines 1539-1584
    fn default() -> Self {
        let mut cfg = VIRT_Config {
            config_path: [0u8; VIRT_PATH_BUF_SIZE],
            enable_file_decoy: false,
            enable_cache: true,
            cache_size: VIRT_MAX_CACHED_PATHS,
            max_rules: VIRT_MAX_RULES,
            handler_stack_size: VIRT_HANDLER_STACK_SIZE,
            notif_timeout_ms: VIRT_NOTIF_FD_TIMEOUT_MS,
            max_consecutive_errors: 10,
            enable_watchdog: true,
            enable_anti_tamper: true,
            enable_proc_hiding: true,
            enable_timing_jitter: false,
            enable_thread_sync: false,
            enable_kernel_compat: true,
            enable_openat_intercept: true,
            enable_readlinkat_intercept: true,
            enable_connect_intercept: true,
            enable_mmap_intercept: true,
            default_action: VIRT_ACTION_PASS_THROUGH,
            filter_mode: 0,
            log_tag: [0u8; 64],
        };
        let p = b"/data/local/tmp/virtualizer/config.txt\0";
        let n = p.len().min(VIRT_PATH_BUF_SIZE);
        cfg.config_path[..n].copy_from_slice(&p[..n]);
        let tag = b"Virtualizer\0";
        let tlen = tag.len().min(64);
        cfg.log_tag[..tlen].copy_from_slice(&tag[..tlen]);
        cfg
    }
}

// ported from virtualizer.cpp line 1342
pub fn virt_config_default() -> VIRT_Config {
    VIRT_Config::default()
}

// ported from virtualizer.cpp line 1342 (simplified)
pub fn virt_config_load() -> VIRT_Config {
    VIRT_Config::default()
}

// ported from seccomp_engine.cpp decoy init
pub fn virt_decoy_init(cfg: &VIRT_Config) {
    if cfg.enable_file_decoy {
        // Decoy files are created by seccomp::virt_seccomp_create_decoy_files() before this call
    }
}

// ported from virtualizer.cpp line 2106
pub fn virt_config_auto_tune(cfg: &mut VIRT_Config) {
    if cfg.cache_size > 65536 {
        cfg.cache_size = 65536;
    }
    if cfg.cache_size < 64 {
        cfg.cache_size = 64;
    }
    if cfg.max_rules > 8192 {
        cfg.max_rules = 8192;
    }
    if cfg.max_rules < 16 {
        cfg.max_rules = 16;
    }
    if cfg.handler_stack_size < 65536 {
        cfg.handler_stack_size = 65536;
    }
    if cfg.handler_stack_size > 8 * 1024 * 1024 {
        cfg.handler_stack_size = 8 * 1024 * 1024;
    }
    if cfg.notif_timeout_ms < 100 {
        cfg.notif_timeout_ms = 100;
    }
    if cfg.notif_timeout_ms > 60000 {
        cfg.notif_timeout_ms = 60000;
    }
    if cfg.max_consecutive_errors < 1 {
        cfg.max_consecutive_errors = 1;
    }
    if cfg.max_consecutive_errors > 1000 {
        cfg.max_consecutive_errors = 1000;
    }
}

// ─── Sensitive path patterns ──────────────────────────────────────────────
// ported from virtualizer.h lines 1586-1774
pub fn virt_default_blocked_patterns() -> &'static [&'static [u8]] {
    const PATTERNS: &[&[u8]] = &[
        b"/su",
        b"/su/su",
        b"/magisk",
        b"/sbin/.magisk",
        b"/sbin/.magisk.img",
        b"/sbin/magisk",
        b"/sbin/magic_mask",
        b"/sbin/su",
        b"/data/adb",
        b"/data/adb/magisk",
        b"/data/adb/modules",
        b"/data/adb/su",
        b"/data/adb/service.d",
        b"/data/adb/post-fs-data.d",
        b"/data/adb/modules_update",
        b"/data/adb/ksu",
        b"/data/adb/ap",
        b"/data/adb/modules/zygisk-virtualizer",
        b"/data/adb/magisk.img",
        b"/data/adb/magisk.db",
        b"/system/bin/su",
        b"/system/xbin/su",
        b"/system/bin/debuggerd",
        b"/system/app/Superuser.apk",
        b"/system/app/SuperSU.apk",
        b"/system/app/Kingroot.apk",
        b"/system/app/KingUser.apk",
        b"/system/etc/init.d",
        b"/system/etc/super.d",
        b"/system/framework/core-libart.jar",
        b"/system/lib64/libsupol.so",
        b"/system/lib/libsupol.so",
        b"/init.rc",
        b"/init.super.rc",
        b"/init.magisk.rc",
        b"/persist/property",
        b"/data/property",
        b"/dbdata/property",
        b"/cache/recovery",
        b"/cache/magisk.log",
        b"/dev/com.koushikdutta.superuser",
        b"/dev/socket/zygote",
        b"/dev/socket/zygote_secondary",
        b"/dev/socket/ksu",
        b"DexposedBridge",
        b"xposed",
        b"XposedBridge",
        b"de.robv.android.xposed",
        b"frida",
        b"gum-js-loop",
        b"frida-helper",
        b"frida-server",
        b"frida-agent",
        b"libfrida",
        b"libgadget",
        b"frida-gadget",
        b"frida-gadget.so",
        b"com.saurik.substrate",
        b"cydia",
        b"substrate",
        b"libsubstrate.so",
        b"libsubstrated.so",
        b"com.noshufou.android.su",
        b"com.thirdparty.superuser",
        b"eu.chainfire.supersu",
        b"com.koushikdutta.superuser",
        b"com.topjohnwu.magisk",
        b"com.kingroot.master",
        b"com.kingo.root",
        b"com.qihoo.permmgr",
        b"com.dianxinos.superuser",
        b"com.ramdroid.rootqueries",
        b"com.topjohnwu.snet",
        b"com.scottyab.rootbeer",
        b"/proc/self/pagemap",
        b"/proc/self/smaps",
        b"/proc/self/smaps_rollup",
        b"/proc/self/wchan",
        b"/proc/self/io",
        b"/proc/self/oom_score",
        b"/proc/self/oom_score_adj",
        b"/proc/self/mem",
        b"/proc/self/personality",
        b"/proc/self/stack",
        b"/proc/self/syscall",
        b"/proc/self/coredump_filter",
        b"/proc/self/task/",
        b"/sys/kernel/security/",
        b"/sys/fs/selinux/",
        b"/proc/self/mountinfo",
        b"/proc/self/mounts",
        b"/proc/self/exe",
        b"/data/local/tmp/frida",
        b"/data/local/tmp/re.frida",
        b"/data/local/tmp/frida-server",
        b"/data/local/frida",
        b"/data/local/tmp/lief",
        b"/data/local/tmp/libtrace",
        b"/data/local/tmp/linjector",
        b"/data/local/tmp/hijack",
        b"/data/local/tmp/inject",
        b"/data/local/tmp/injector",
        b"/data/local/tmp/dobby",
        b"/data/local/tmp/bhook",
        b"/data/local/tmp/ree",
        b"/data/local/tmp/libree",
        b"/data/local/tmp/xposed",
        b"/data/local/tmp/edxposed",
        b"/data/local/tmp/lsposed",
        b"/data/local/tmp/zygisk",
        b"/data/local/tmp/riru",
        b"/data/local/tmp/substrate",
        b"/data/local/tmp/cyanogenmod",
        b"/data/local/tmp/strace",
        b"/data/local/tmp/gdb",
        b"/data/local/tmp/gdbserver",
        b"/data/local/tmp/.frida",
        b"/data/local/tmp/__frida",
        b"/system/lib/libfrida",
        b"/system/lib64/libfrida",
        b"/system/lib/libxposed",
        b"/system/lib64/libxposed",
        b"/proc/uptime",
        b"/proc/stat",
        b"/proc/self/attr/current",
        b"/proc/self/task/self",
        b"/proc/self/numa_maps",
        b"/proc/self/clear_refs",
        b"/proc/self/timers",
        b"/proc/self/timerslack_ns",
        b"/proc/self/oom",
        b"/proc/self/comm",
        b"/proc/self/sessionid",
        b"/proc/self/loginuid",
        b"/proc/self/latency",
        b"/proc/self/auxv",
        b"/proc/version",
        b"/proc/cpuinfo",
        b"/proc/sys/kernel/random/boot_id",
        b"/proc/sys/kernel/hostname",
        b"/proc/sys/kernel/osrelease",
        b"/proc/sys/kernel/ostype",
        b"/proc/net/tcp",
        b"/proc/net/tcp6",
        b"/proc/net/udp",
        b"/proc/net/unix",
        b"/proc/net/route",
        b"/data/local/tmp/chelper",
        b"/data/local/tmp/cexo",
        b"/data/local/tmp/drkg",
        b"/data/local/tmp/ez4u",
        b"/data/local/tmp/gfree",
        b"/data/local/tmp/gkworld",
        b"/data/local/tmp/hluda",
        b"/data/local/tmp/kysdk",
        b"/data/local/tmp/lansp",
        b"/data/local/tmp/mfpub",
        b"/data/local/tmp/niwot",
        b"/data/local/tmp/reflutter",
        b"/data/local/tmp/sgiwp",
        b"/data/local/tmp/taoyy",
        b"/data/local/tmp/utroot",
        b"/data/local/tmp/vproxy",
        b"/data/local/tmp/wsroot",
        b"/data/local/tmp/run.sh",
        b"/data/local/tmp/shizuku",
        b"/data/local/tmp/KingUser",
        b"/data/local/tmp/kinguser",
        b"/data/local/tmp/rootbeer",
        b"/data/local/tmp/binaryeye",
        b"/proc/modules",
        b"/proc/kallsyms",
        b"/system/default.prop",
        b"/data/adb/service.d",
        b"/data/adb/post-fs-data.d",
        b"/system/xbin/su",
        b"/system/sd/xbin/su",
        b"/data/data/eu.chainfire.supersu",
        b"/system/xbin/busybox",
        b"/system/bin/busybox",
        b"/data/data/burrows.apps.busybox",
    ];
    PATTERNS
}

// ─── Memory tracking ──────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 90-131
use std::sync::atomic::{AtomicU64, Ordering};

static MEM_TOTAL_ALLOCATED: AtomicU64 = AtomicU64::new(0);
static MEM_PEAK_ALLOCATED: AtomicU64 = AtomicU64::new(0);
static MEM_OOM_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn virt_mem_track_alloc(size: u64) {
    let prev = MEM_TOTAL_ALLOCATED.fetch_add(size, Ordering::SeqCst);
    let new = prev + size;
    let mut peak = MEM_PEAK_ALLOCATED.load(Ordering::SeqCst);
    while new > peak {
        match MEM_PEAK_ALLOCATED.compare_exchange(peak, new, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(cur) => peak = cur,
        }
    }
}

pub fn virt_mem_track_free(size: u64) {
    let prev = MEM_TOTAL_ALLOCATED.load(Ordering::SeqCst);
    if size <= prev {
        MEM_TOTAL_ALLOCATED.fetch_sub(size, Ordering::SeqCst);
    }
}

pub fn virt_mem_get_usage() -> u64 {
    MEM_TOTAL_ALLOCATED.load(Ordering::SeqCst)
}

pub fn virt_mem_get_peak() -> u64 {
    MEM_PEAK_ALLOCATED.load(Ordering::SeqCst)
}

pub fn virt_mem_record_oom() {
    MEM_OOM_COUNT.fetch_add(1, Ordering::SeqCst);
}

pub const VIRT_MEM_PRESSURE_THRESHOLD: u64 = 10 * 1024 * 1024;
pub const VIRT_MEM_CRITICAL_THRESHOLD: u64 = 20 * 1024 * 1024;

pub fn virt_mem_check_pressure() -> i32 {
    let usage = virt_mem_get_usage();
    if usage >= VIRT_MEM_CRITICAL_THRESHOLD {
        return 2;
    }
    if usage >= VIRT_MEM_PRESSURE_THRESHOLD {
        return 1;
    }
    0
}

// ─── Timer helper ─────────────────────────────────────────────────────────
// ported from virtualizer.h line 1925
pub fn virt_gettime_ns() -> u64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    dur.as_secs() * 1_000_000_000 + dur.subsec_nanos() as u64
}

// ─── CRC-16/CCITT ─────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp line 31
pub fn virt_crc16(data: &[u8], init: u16) -> u16 {
    let mut crc = init;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ─── Trie ─────────────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 285-461
#[derive(Clone)]
pub struct TrieNode {
    pub is_end: bool,
    pub action: i32,
    pub priority: u32,
    pub children: Vec<(u8, Box<TrieNode>)>,
    pub fallback: Option<Box<TrieNode>>,
}

impl TrieNode {
    fn new() -> Self {
        TrieNode {
            is_end: false,
            action: VIRT_ACTION_PASS_THROUGH,
            priority: 0,
            children: Vec::new(),
            fallback: None,
        }
    }

    fn child_mut(&mut self, c: u8) -> Option<&mut Box<TrieNode>> {
        self.children
            .iter_mut()
            .find(|(k, _)| *k == c)
            .map(|(_, v)| v)
    }

    fn child_ref(&self, c: u8) -> Option<&Box<TrieNode>> {
        self.children.iter().find(|(k, _)| *k == c).map(|(_, v)| v)
    }

    fn insert_child(&mut self, c: u8, child: Box<TrieNode>) {
        self.children.push((c, child));
    }
}

pub fn trie_child_find<'a>(node: &'a TrieNode, c: u8) -> Option<&'a TrieNode> {
    node.children
        .iter()
        .find(|(k, _)| *k == c)
        .map(|(_, v)| &**v)
}

pub fn trie_child_find_mut<'a>(node: &'a mut TrieNode, c: u8) -> Option<&'a mut TrieNode> {
    node.children
        .iter_mut()
        .find(|(k, _)| *k == c)
        .map(|(_, v)| &mut **v)
}

pub struct Trie {
    pub root: Mutex<Option<Box<TrieNode>>>,
    pub node_count: Mutex<u32>,
    pub total_lookups: AtomicU64,
    pub cache_hits: AtomicU64,
}

unsafe impl Send for Trie {}
unsafe impl Sync for Trie {}

impl Trie {
    pub fn new() -> Self {
        Trie {
            root: Mutex::new(None),
            node_count: Mutex::new(0),
            total_lookups: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
        }
    }

    // ported from virtualizer_core.cpp line 335
    pub fn insert(&self, key: &[u8], action: i32, priority: u32) -> i32 {
        if key.is_empty() || key.len() >= VIRT_PATH_BUF_SIZE {
            return VIRT_ERR_INVAL;
        }
        let root_lock = self.root.lock().unwrap();
        if root_lock.is_none() {
            drop(root_lock);
            let mut rl = self.root.lock().unwrap();
            *rl = Some(Box::new(TrieNode::new()));
            *self.node_count.lock().unwrap() += 1;
        } else {
            drop(root_lock);
        }
        // Clone the fallback root for use when building new nodes
        let fallback_root = self.root.lock().unwrap().as_ref().map(|r| r.clone());

        let mut root_lock2 = self.root.lock().unwrap();
        let root_node = root_lock2.as_mut().unwrap();
        let mut node: &mut TrieNode = &mut **root_node;
        let mut is_root = true;

        for &c in key.iter() {
            if node.child_mut(c).is_none() {
                let mut child = Box::new(TrieNode::new());
                // Aho-Corasick fallback
                if !is_root {
                    if let Some(ref fb) = node.fallback {
                        let mut fb_node: &TrieNode = &**fb;
                        loop {
                            if let Some(fb_child) = fb_node.child_ref(c) {
                                child.fallback = Some(fb_child.clone());
                                break;
                            }
                            match fb_node.fallback {
                                Some(ref f) => fb_node = &**f,
                                None => break,
                            }
                        }
                    }
                }
                if child.fallback.is_none() {
                    child.fallback = fallback_root.clone();
                }
                node.insert_child(c, child);
                *self.node_count.lock().unwrap() += 1;
            }
            is_root = false;
            node = node.child_mut(c).unwrap();
        }

        if !node.is_end || priority > node.priority {
            node.is_end = true;
            node.action = action;
            node.priority = priority;
        }
        VIRT_OK
    }

    // ported from virtualizer_core.cpp line 385
    pub fn lookup(&self, key: &[u8]) -> Option<i32> {
        self.total_lookups.fetch_add(1, Ordering::SeqCst);
        let root_lock = self.root.lock().unwrap();
        let root_node = root_lock.as_ref()?;

        let mut node: &TrieNode = &**root_node;
        let mut best_action: Option<i32> = None;
        let mut best_priority: u32 = 0;

        for &c in key.iter() {
            loop {
                if let Some(child) = node.child_ref(c) {
                    node = &**child;
                    break;
                }
                match node.fallback {
                    Some(ref fb) => node = &**fb,
                    None => {
                        node = &**root_node;
                        break;
                    }
                }
            }
            if node.is_end && node.priority > best_priority {
                best_action = Some(node.action);
                best_priority = node.priority;
                self.cache_hits.fetch_add(1, Ordering::SeqCst);
            }
        }

        if best_priority > 0 {
            best_action
        } else {
            None
        }
    }

    // ported from virtualizer_core.cpp line 420
    pub fn build_default(&self) -> i32 {
        for &pat in virt_default_blocked_patterns() {
            let mut action = VIRT_ACTION_BLOCK_ENOENT;
            let mut prio: u32 = 100;
            if let Ok(s) = std::str::from_utf8(pat) {
                if s.contains("/proc/net/") {
                    action = VIRT_ACTION_MONITOR;
                    prio = 50;
                } else if s.contains("/proc/self/") {
                    prio = 100;
                } else if s.contains("/su")
                    || s.contains("/magisk")
                    || s.contains("/data/adb")
                    || s.contains("/sbin/")
                {
                    prio = 200;
                } else if s.contains("frida") || s.contains("xposed") || s.contains("substrate") {
                    prio = 300;
                }
            }
            let rc = self.insert(pat, action, prio);
            if rc < 0 {
                return rc;
            }
        }
        VIRT_OK
    }

    // ported from virtualizer_core.cpp line 450
    pub fn destroy(&self) {
        let mut root = self.root.lock().unwrap();
        *root = None;
        *self.node_count.lock().unwrap() = 0;
        self.total_lookups.store(0, Ordering::SeqCst);
        self.cache_hits.store(0, Ordering::SeqCst);
    }

    pub fn get_node_count(&self) -> u32 {
        *self.node_count.lock().unwrap()
    }

    pub fn get_lookup_count(&self) -> u64 {
        self.total_lookups.load(Ordering::SeqCst)
    }

    pub fn get_cache_hit_count(&self) -> u64 {
        self.cache_hits.load(Ordering::SeqCst)
    }
}

// ─── Cache ────────────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 979-1033
pub const VIRT_CACHE_TTL_NS: u64 = 5 * 1_000_000_000;

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub path: [u8; VIRT_PATH_BUF_SIZE],
    pub path_len: u32,
    pub is_sensitive: bool,
    pub action: i32,
    pub cached_at_ns: u64,
    pub hit_count: u64,
    pub ttl_ns: u64,
    pub valid: bool,
}

impl Default for CacheEntry {
    fn default() -> Self {
        CacheEntry {
            path: [0u8; VIRT_PATH_BUF_SIZE],
            path_len: 0,
            is_sensitive: false,
            action: VIRT_ACTION_PASS_THROUGH,
            cached_at_ns: 0,
            hit_count: 0,
            ttl_ns: VIRT_CACHE_TTL_NS,
            valid: false,
        }
    }
}

pub struct Cache {
    pub entries: Mutex<Vec<CacheEntry>>,
    pub max_size: u32,
}

impl Cache {
    // ported from virtualizer_core.cpp
    pub fn new(max_size: u32) -> Self {
        Cache {
            entries: Mutex::new(Vec::with_capacity(max_size as usize)),
            max_size,
        }
    }

    // ported from virtualizer_core.cpp line 980
    pub fn lookup(&self, path: &[u8]) -> Option<i32> {
        let entries = self.entries.lock().unwrap();
        let now = virt_gettime_ns();
        let path_len = path.len() as u32;
        if path_len as usize > VIRT_PATH_BUF_SIZE {
            return None;
        }
        for entry in entries.iter() {
            if !entry.valid {
                continue;
            }
            if entry.path_len == path_len && &entry.path[..path_len as usize] == path {
                if now - entry.cached_at_ns > entry.ttl_ns {
                    continue;
                }
                return if entry.is_sensitive {
                    Some(entry.action)
                } else {
                    Some(VIRT_ACTION_PASS_THROUGH)
                };
            }
        }
        None
    }

    // ported from virtualizer_core.cpp line 1004
    pub fn insert(&self, path: &[u8], sensitive: bool, action: i32) {
        let mut entries = self.entries.lock().unwrap();
        let path_len = path.len() as u32;
        if path_len as usize > VIRT_PATH_BUF_SIZE - 1 {
            return;
        }
        let max = self.max_size as usize;
        // LRU eviction: find oldest or first invalid slot
        let idx = if entries.len() < max {
            entries.push(CacheEntry::default());
            entries.len() - 1
        } else {
            let mut oldest = u64::MAX;
            let mut oldest_idx = 0;
            for (i, e) in entries.iter().enumerate() {
                if !e.valid {
                    oldest_idx = i;
                    break;
                }
                if e.cached_at_ns < oldest {
                    oldest = e.cached_at_ns;
                    oldest_idx = i;
                }
            }
            oldest_idx
        };
        let entry = &mut entries[idx];
        entry.path[..path_len as usize].copy_from_slice(path);
        entry.path_len = path_len;
        entry.is_sensitive = sensitive;
        entry.action = action;
        entry.cached_at_ns = virt_gettime_ns();
        entry.ttl_ns = VIRT_CACHE_TTL_NS;
        entry.valid = true;
        entry.hit_count = 0;
    }

    // ported from virtualizer_core.cpp line 1024
    pub fn invalidate(&self, path: &[u8]) -> i32 {
        let mut entries = self.entries.lock().unwrap();
        let plen = path.len() as u32;
        let mut removed = 0;
        for entry in entries.iter_mut() {
            if entry.valid && entry.path_len == plen && &entry.path[..plen as usize] == path {
                entry.valid = false;
                removed += 1;
            }
        }
        if removed > 0 {
            VIRT_OK
        } else {
            VIRT_ERR_NOENT
        }
    }

    // ported from virtualizer_core.cpp line 590
    pub fn flush(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }
}

// ─── ProcHider ────────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 1117-1220
pub struct ProcHider {
    pub hidden_fds: Vec<u32>,
    pub hidden_pids: Vec<u32>,
    pub hidden_tids: Vec<u32>,
    pub initialized: bool,
    pub hide_maps: bool,
    pub hide_fd: bool,
    pub hide_status: bool,
    pub proc_name_fake: [u8; VIRT_PROC_NAME_MAX],
    pub cmdline_fake: [u8; VIRT_PATH_BUF_SIZE],
}

impl ProcHider {
    // ported from virtualizer_core.cpp line 1117
    pub fn new() -> Self {
        let mut pn = [0u8; VIRT_PROC_NAME_MAX];
        let cpn = b"app_process64\0";
        let n = cpn.len().min(VIRT_PROC_NAME_MAX);
        pn[..n].copy_from_slice(&cpn[..n]);

        let mut cl = [0u8; VIRT_PATH_BUF_SIZE];
        let ccl = b"/system/bin/app_process64\0";
        let m = ccl.len().min(VIRT_PATH_BUF_SIZE);
        cl[..m].copy_from_slice(&ccl[..m]);

        ProcHider {
            hidden_fds: Vec::with_capacity(64),
            hidden_pids: Vec::with_capacity(64),
            hidden_tids: Vec::with_capacity(64),
            initialized: true,
            hide_maps: true,
            hide_fd: true,
            hide_status: true,
            proc_name_fake: pn,
            cmdline_fake: cl,
        }
    }

    // ported from virtualizer_core.cpp line 1142
    pub fn add_fd(&mut self, fd: u32) {
        if !self.hidden_fds.contains(&fd) && self.hidden_fds.len() < 64 {
            self.hidden_fds.push(fd);
        }
    }

    // ported from virtualizer_core.cpp line 1149
    pub fn remove_fd(&mut self, fd: u32) {
        self.hidden_fds.retain(|&x| x != fd);
    }

    // ported from virtualizer_core.cpp line 1160
    pub fn add_pid(&mut self, pid: u32) {
        if !self.hidden_pids.contains(&pid) && self.hidden_pids.len() < 64 {
            self.hidden_pids.push(pid);
        }
    }

    // ported from virtualizer_core.cpp line 613
    pub fn remove_pid(&mut self, pid: u32) {
        self.hidden_pids.retain(|&x| x != pid);
    }

    // ported from virtualizer_core.cpp line 626
    pub fn add_tid(&mut self, tid: u32) {
        if !self.hidden_tids.contains(&tid) && self.hidden_tids.len() < 64 {
            self.hidden_tids.push(tid);
        }
    }

    // ported from virtualizer_core.cpp line 1172
    pub fn check_fd_path(&self, path: &[u8]) -> bool {
        let path_str = match std::str::from_utf8(path) {
            Ok(s) => s,
            Err(_) => return false,
        };
        if let Some(fdpos) = path_str.find("/fd/") {
            let fdnum_start = fdpos + 4;
            let rest = &path_str[fdnum_start..];
            for &fd in &self.hidden_fds {
                let fd_str = fd.to_string();
                if rest.starts_with(&fd_str) {
                    let after = rest.as_bytes().get(fd_str.len()).copied().unwrap_or(b'\0');
                    if after == b'\0' || after == b'/' || after == b'\n' {
                        return true;
                    }
                }
            }
        }
        false
    }

    // ported from virtualizer_core.cpp line 1193
    pub fn filter_dirents(&self, dirents: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(dirents.len());
        let mut pos = 0;
        while pos + 18 < dirents.len() {
            let d_ino = u64::from_ne_bytes(dirents[pos..pos + 8].try_into().unwrap_or([0u8; 8]));
            if d_ino == 0 {
                break;
            }
            let d_reclen =
                u16::from_ne_bytes(dirents[pos + 16..pos + 18].try_into().unwrap_or([0u8; 2]))
                    as usize;
            if d_reclen == 0 {
                break;
            }
            if pos + d_reclen > dirents.len() {
                break;
            }
            let _d_type = dirents[pos + 18];
            let name_start = pos + 19;
            let name_end = dirents[name_start..pos + d_reclen]
                .iter()
                .position(|&b| b == 0)
                .map(|z| name_start + z)
                .unwrap_or(pos + d_reclen);
            let name = &dirents[name_start..name_end];
            let mut skip = false;
            for &fd in &self.hidden_fds {
                let fd_str = fd.to_string();
                if name == fd_str.as_bytes() {
                    skip = true;
                    break;
                }
            }
            if !skip {
                out.extend_from_slice(&dirents[pos..pos + d_reclen]);
            }
            pos += d_reclen;
        }
        out
    }
}

// ─── Rules engine ─────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 1035-1115
#[derive(Clone, Debug)]
pub struct Rule {
    pub pattern: [u8; VIRT_PATH_BUF_SIZE],
    pub pattern_len: u32,
    pub match_type: i32,
    pub action: i32,
    pub category: i32,
    pub priority: u32,
    pub enabled: bool,
    pub is_default: bool,
    pub is_system: bool,
    pub hit_count: u64,
    pub created_ns: u64,
}

impl Default for Rule {
    fn default() -> Self {
        Rule {
            pattern: [0u8; VIRT_PATH_BUF_SIZE],
            pattern_len: 0,
            match_type: VIRT_MATCH_SUBSTRING,
            action: VIRT_ACTION_PASS_THROUGH,
            category: VIRT_CAT_OTHER,
            priority: 0,
            enabled: true,
            is_default: false,
            is_system: false,
            hit_count: 0,
            created_ns: 0,
        }
    }
}

// ported from virtualizer_core.cpp line 1035
pub fn rules_add(rules: &mut Vec<Rule>, rule: &Rule, max_rules: u32) -> i32 {
    if rules.len() >= max_rules as usize {
        // Replace lowest-priority default rule
        let mut lowest = u32::MAX;
        let mut repl = None;
        for (i, r) in rules.iter().enumerate() {
            if r.is_default && r.priority < lowest {
                lowest = r.priority;
                repl = Some(i);
            }
        }
        match repl {
            Some(idx) => {
                rules[idx] = rule.clone();
                VIRT_OK
            }
            None => VIRT_ERR_NOMEM,
        }
    } else {
        rules.push(rule.clone());
        VIRT_OK
    }
}

// ported from virtualizer_core.cpp line 1048
pub fn rules_remove(rules: &mut Vec<Rule>, index: usize) -> i32 {
    if index >= rules.len() {
        return VIRT_ERR_INVAL;
    }
    if rules[index].is_system {
        return VIRT_ERR_PERM;
    }
    rules.remove(index);
    VIRT_OK
}

// ported from virtualizer_core.cpp line 1062
pub fn rules_lookup(rules: &[Rule], path: &[u8]) -> Option<i32> {
    let mut best: Option<i32> = None;
    let mut best_prio: i32 = -1;
    for rule in rules.iter() {
        if !rule.enabled {
            continue;
        }
        if path_match(
            path,
            &rule.pattern[..rule.pattern_len as usize],
            rule.match_type,
        ) {
            let prio = rule.priority as i32;
            if prio > best_prio {
                best_prio = prio;
                best = Some(rule.action);
            }
        }
    }
    best
}

// ported from virtualizer_core.cpp line 1081
pub fn rules_sort(rules: &mut Vec<Rule>) {
    rules.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| match (a.is_system, b.is_system) {
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                _ => std::cmp::Ordering::Equal,
            })
    });
}

// ported from virtualizer_core.cpp line 1087
pub fn rules_load_defaults(rules: &mut Vec<Rule>, max_rules: u32) -> i32 {
    rules.clear();
    for &pat in virt_default_blocked_patterns() {
        if rules.len() >= max_rules as usize {
            break;
        }
        let mut rule = Rule::default();
        let plen = pat.len().min(VIRT_PATH_BUF_SIZE - 1);
        rule.pattern[..plen].copy_from_slice(&pat[..plen]);
        rule.pattern_len = plen as u32;
        rule.match_type = VIRT_MATCH_SUBSTRING;
        rule.category = VIRT_CAT_PROC;
        rule.priority = 100;
        rule.enabled = true;
        rule.is_default = true;
        rule.is_system = true;
        rule.created_ns = virt_gettime_ns();

        if let Ok(s) = std::str::from_utf8(pat) {
            if s.contains("/proc/net/") {
                rule.action = VIRT_ACTION_MONITOR;
                rule.category = VIRT_CAT_NETWORK;
                rule.priority = 50;
            } else {
                rule.action = VIRT_ACTION_BLOCK_ENOENT;
                if s.contains("/proc/") {
                    rule.category = VIRT_CAT_PROC;
                } else if s.contains("/su")
                    || s.contains("/magisk")
                    || s.contains("/data/adb")
                    || s.contains("/sbin/")
                {
                    rule.category = VIRT_CAT_DEBUG;
                    rule.priority = 200;
                } else if s.contains("xposed") || s.contains("frida") || s.contains("substrate") {
                    rule.category = VIRT_CAT_DEBUG;
                    rule.priority = 300;
                }
            }
        }
        rules.push(rule);
    }
    VIRT_OK
}

// ported from virtualizer_core.cpp line 597
pub fn rules_count_by_action(rules: &[Rule], action: i32) -> usize {
    rules
        .iter()
        .filter(|r| r.enabled && r.action == action)
        .count()
}

// ported from virtualizer_core.cpp line 605
pub fn rules_count_by_category(rules: &[Rule], category: i32) -> usize {
    rules
        .iter()
        .filter(|r| r.enabled && r.category == category)
        .count()
}

// ─── Stats ────────────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 824-977
const VIRT_MAX_STATS_HISTORY: usize = 3600;

#[derive(Clone, Debug)]
pub struct SyscallStats {
    pub total_calls: u64,
    pub blocked_calls: u64,
    pub allowed_calls: u64,
    pub continued_calls: u64,
    pub error_calls: u64,
    pub per_syscall: [u64; 512],
    pub per_action: [u64; VIRT_ACTION_COUNT],
    pub total_latency_ns: u64,
    pub max_latency_ns: u64,
    pub min_latency_ns: u64,
    pub calls_per_sec: f64,
    pub blocked_percent: f64,
    pub avg_latency_ns: f64,
    pub last_reset_tp: u64,
    pub history_index: u32,
    pub history_count: u32,
    pub history: [(u64, u64, u64, u64); VIRT_MAX_STATS_HISTORY],
}

impl SyscallStats {
    // ported from virtualizer_core.cpp line 824
    pub fn new() -> Self {
        SyscallStats {
            total_calls: 0,
            blocked_calls: 0,
            allowed_calls: 0,
            continued_calls: 0,
            error_calls: 0,
            per_syscall: [0u64; 512],
            per_action: [0u64; VIRT_ACTION_COUNT],
            total_latency_ns: 0,
            max_latency_ns: 0,
            min_latency_ns: u64::MAX,
            calls_per_sec: 0.0,
            blocked_percent: 0.0,
            avg_latency_ns: 0.0,
            last_reset_tp: virt_gettime_ns(),
            history_index: 0,
            history_count: 0,
            history: [(0u64, 0u64, 0u64, 0u64); VIRT_MAX_STATS_HISTORY],
        }
    }

    // ported from virtualizer_core.cpp line 839
    pub fn record(&mut self, syscall: i32, action: i32, latency: u64) {
        self.total_calls += 1;
        self.total_latency_ns += latency;
        if latency > self.max_latency_ns {
            self.max_latency_ns = latency;
        }
        if latency < self.min_latency_ns {
            self.min_latency_ns = latency;
        }
        if syscall >= 0 && (syscall as usize) < 512 {
            self.per_syscall[syscall as usize] += 1;
        }
        if action >= 0 && (action as usize) < VIRT_ACTION_COUNT {
            self.per_action[action as usize] += 1;
        }
        const BLOCKED_ACTIONS: [i32; 9] = [
            VIRT_ACTION_BLOCK_ENOENT,
            VIRT_ACTION_BLOCK_EACCES,
            VIRT_ACTION_BLOCK_EPERM,
            VIRT_ACTION_BLOCK_ENXIO,
            VIRT_ACTION_BLOCK_EIO,
            VIRT_ACTION_FAKE_CONTENT,
            VIRT_ACTION_FAKE_EMPTY,
            VIRT_ACTION_FAKE_MAPS,
            VIRT_ACTION_FAKE_STATUS,
        ];
        if BLOCKED_ACTIONS.contains(&action) {
            self.blocked_calls += 1;
        } else if action == VIRT_ACTION_ALLOW {
            self.allowed_calls += 1;
        } else if action == VIRT_ACTION_PASS_THROUGH {
            self.continued_calls += 1;
        }
        self.avg_latency_ns = self.total_latency_ns as f64 / self.total_calls.max(1) as f64;
        let now = virt_gettime_ns();
        let elapsed = (now - self.last_reset_tp) as f64 / 1e9;
        self.calls_per_sec = self.total_calls as f64 / elapsed.max(0.001);
        self.blocked_percent = if self.total_calls > 0 {
            100.0 * self.blocked_calls as f64 / self.total_calls as f64
        } else {
            0.0
        };
        let idx = self.history_index as usize % VIRT_MAX_STATS_HISTORY;
        self.history[idx] = (
            now,
            self.total_calls,
            self.blocked_calls,
            self.avg_latency_ns as u64,
        );
        self.history_index += 1;
        if self.history_count < VIRT_MAX_STATS_HISTORY as u32 {
            self.history_count += 1;
        }
    }

    // ported from virtualizer_core.cpp line 882
    pub fn snapshot_to_string(&self) -> String {
        let now = virt_gettime_ns();
        let uptime = (now - self.last_reset_tp) as f64 / 1e9;
        let mut s = String::new();
        s.push_str(&format!("=== Virtualizer Stats ===\n"));
        s.push_str(&format!("Uptime:       {:>10.1} sec\n", uptime));
        s.push_str(&format!("Total:        {:>10}\n", self.total_calls));
        s.push_str(&format!(
            "Rate:         {:>10.1} events/sec\n",
            self.calls_per_sec
        ));
        s.push_str(&format!(
            "Blocked:      {:>10} ({:>5.1}%)\n",
            self.blocked_calls, self.blocked_percent
        ));
        s.push_str(&format!("Passthrough:  {:>10}\n", self.continued_calls));
        s.push_str(&format!("Allowed:      {:>10}\n", self.allowed_calls));
        s.push_str(&format!("Errors:       {:>10}\n", self.error_calls));
        s.push_str(&format!("Avg Lat:      {:>10.0} ns\n", self.avg_latency_ns));
        s.push_str(&format!("Max Lat:      {:>10}\n", self.max_latency_ns));
        s.push_str(&format!("Min Lat:      {:>10}\n", self.min_latency_ns));
        s.push_str("\nPer-Action:\n");
        for (i, &cnt) in self.per_action.iter().enumerate() {
            if cnt > 0 && i < VIRT_ACTION_NAMES.len() {
                s.push_str(&format!("  {:>16} {}\n", VIRT_ACTION_NAMES[i], cnt));
            }
        }
        s
    }
}

// ─── Anti-tamper ──────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 635-706, 1222-1280
#[derive(Clone, Debug)]
pub struct AntiTamperState {
    pub initialized: bool,
    pub integrity_ok: bool,
    pub debugger_detected: bool,
    pub hook_detected: bool,
    pub ptrace_detected: bool,
    pub memory_modified: bool,
    pub code_page_writable: bool,
    pub tamper_detected: bool,
    pub last_check_ns: u64,
    pub check_interval_ns: u64,
    pub integrity_failures: u32,
    pub consecutive_failures: u32,
    pub module_base: usize,
    pub module_size: usize,
    pub expected_text_hash: u32,
    pub total_checks: u32,
    pub total_alerts: u32,
}

impl AntiTamperState {
    // ported from virtualizer_core.cpp line 1222
    pub fn new() -> Self {
        AntiTamperState {
            initialized: true,
            integrity_ok: true,
            debugger_detected: false,
            hook_detected: false,
            ptrace_detected: false,
            memory_modified: false,
            code_page_writable: false,
            tamper_detected: false,
            last_check_ns: virt_gettime_ns(),
            check_interval_ns: 5 * 1_000_000_000,
            integrity_failures: 0,
            consecutive_failures: 0,
            module_base: 0,
            module_size: 0,
            expected_text_hash: 0,
            total_checks: 0,
            total_alerts: 0,
        }
    }

    // ported from virtualizer_core.cpp line 1257
    pub fn check(&mut self) -> i32 {
        if !self.initialized {
            return VIRT_ERR_INVAL;
        }
        let now = virt_gettime_ns();
        if now - self.last_check_ns < self.check_interval_ns {
            return VIRT_OK;
        }
        self.last_check_ns = now;
        self.total_checks += 1;
        self.tamper_detected = false;

        if self.debugger_detected || self.ptrace_detected || self.hook_detected {
            self.integrity_failures += 1;
            self.tamper_detected = true;
        }
        if self.code_page_writable || self.memory_modified {
            self.integrity_failures += 1;
            self.tamper_detected = true;
        }
        if self.tamper_detected {
            self.integrity_ok = false;
            self.total_alerts += 1;
            self.consecutive_failures += 1;
            return VIRT_ERR_PERM;
        }
        self.consecutive_failures = 0;
        self.last_check_ns = now;
        VIRT_OK
    }
}

// ─── Event ring ───────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 466-514
pub const VIRT_EVENT_RING_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug)]
pub struct SyscallEvent {
    pub id: u64,
    pub syscall_nr: i32,
    pub action: i32,
    pub latency_ns: u64,
    pub timestamp_ns: u64,
    pub path: [u8; VIRT_PATH_BUF_SIZE],
    pub path_len: i32,
}

impl Default for SyscallEvent {
    fn default() -> Self {
        SyscallEvent {
            id: 0,
            syscall_nr: 0,
            action: VIRT_ACTION_PASS_THROUGH,
            latency_ns: 0,
            timestamp_ns: 0,
            path: [0u8; VIRT_PATH_BUF_SIZE],
            path_len: 0,
        }
    }
}

pub struct EventRing {
    pub events: [SyscallEvent; VIRT_EVENT_RING_SIZE],
    pub write_pos: u32,
    pub read_pos: u32,
    pub count: u32,
    pub overflow: bool,
}

impl EventRing {
    // ported from virtualizer_core.cpp line 466
    pub fn new() -> Self {
        EventRing {
            events: [SyscallEvent::default(); VIRT_EVENT_RING_SIZE],
            write_pos: 0,
            read_pos: 0,
            count: 0,
            overflow: false,
        }
    }

    // ported from virtualizer_core.cpp line 480
    pub fn push(&mut self, evt: &SyscallEvent) -> i32 {
        let idx = self.write_pos as usize % VIRT_EVENT_RING_SIZE;
        self.events[idx] = evt.clone();
        self.write_pos = (self.write_pos + 1) % VIRT_EVENT_RING_SIZE as u32;
        if self.count < VIRT_EVENT_RING_SIZE as u32 {
            self.count += 1;
        } else {
            self.read_pos = (self.read_pos + 1) % VIRT_EVENT_RING_SIZE as u32;
            self.overflow = true;
        }
        VIRT_OK
    }

    // ported from virtualizer_core.cpp line 497
    pub fn pop(&mut self) -> Option<SyscallEvent> {
        if self.count == 0 {
            return None;
        }
        let idx = self.read_pos as usize % VIRT_EVENT_RING_SIZE;
        let evt = self.events[idx].clone();
        self.read_pos = (self.read_pos + 1) % VIRT_EVENT_RING_SIZE as u32;
        self.count -= 1;
        Some(evt)
    }

    // ported from virtualizer_core.cpp line 505
    pub fn peek(&self, offset: u32) -> Option<&SyscallEvent> {
        if offset >= self.count {
            return None;
        }
        let idx = (self.read_pos + offset) as usize % VIRT_EVENT_RING_SIZE;
        Some(&self.events[idx])
    }

    // ported from virtualizer_core.cpp line 512
    pub fn len(&self) -> u32 {
        self.count
    }
}

// ─── Process profile detection ────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 549-588
#[derive(Clone, Debug)]
pub struct ProfileInfo {
    pub name: [u8; VIRT_PROC_NAME_MAX],
    pub profile: i32,
    pub is_game: bool,
    pub is_browser: bool,
    pub is_banking: bool,
    pub has_anticheat: bool,
}

impl Default for ProfileInfo {
    fn default() -> Self {
        ProfileInfo {
            name: [0u8; VIRT_PROC_NAME_MAX],
            profile: 0,
            is_game: false,
            is_browser: false,
            is_banking: false,
            has_anticheat: false,
        }
    }
}

// ported from virtualizer_core.cpp line 549
pub fn process_profile_detect(name: &str) -> ProfileInfo {
    let mut info = ProfileInfo::default();
    let n = name.as_bytes().len().min(VIRT_PROC_NAME_MAX - 1);
    info.name[..n].copy_from_slice(&name.as_bytes()[..n]);
    info.name[n] = 0;
    if name.contains("com.tencent")
        || name.contains("com.miHoYo")
        || name.contains("com.netease")
        || name.contains("com.garena")
        || name.contains("com.activision")
        || name.contains("com.ea.game")
        || name.contains("com.epicgames")
        || name.contains("com.roblox")
        || name.contains("com.riotgames")
        || name.contains("com.valve")
        || name.contains("com.kiloo")
        || name.contains("com.supercell")
        || name.contains("com.king")
        || name.contains("com.zynga")
    {
        info.profile = 1; // VIRT_PROFILE_GAME
        info.is_game = true;
    } else if name.contains("com.android.chrome")
        || name.contains("org.mozilla.firefox")
        || name.contains("com.opera")
        || name.contains("com.brave")
        || name.contains("com.microsoft.emmx")
        || name.contains("com.duckduckgo.mobile.android")
        || name.contains("com.vivaldi")
    {
        info.profile = 2; // VIRT_PROFILE_BROWSER
        info.is_browser = true;
    } else if name.contains("bank")
        || name.contains("pay")
        || name.contains("fintech")
        || name.contains("wallet")
        || name.contains("com.sbi")
        || name.contains("com.hdfc")
        || name.contains("com.icici")
    {
        info.profile = 5; // VIRT_PROFILE_BANKING
        info.is_banking = true;
    }
    if name.contains("anticheat")
        || name.contains("guard")
        || name.contains("protect")
        || name.contains("security")
        || name.contains("safe")
        || name.contains("xigncode")
        || name.contains("battleye")
        || name.contains("easyanticheat")
        || name.contains("nprotect")
        || name.contains("gameguard")
    {
        info.has_anticheat = true;
    }
    info
}

// ─── Glob pattern ─────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 708-793
#[derive(Clone, Debug)]
pub struct GlobPattern {
    pub pattern: [u8; VIRT_PATH_BUF_SIZE],
    pub pattern_len: u32,
    pub has_wildcard: bool,
    pub has_doublestar: bool,
    pub prefix_len: u32,
    pub suffix_len: u32,
    pub literal_prefix: [u8; VIRT_PATH_BUF_SIZE],
    pub literal_suffix: [u8; VIRT_PATH_BUF_SIZE],
}

impl Default for GlobPattern {
    fn default() -> Self {
        GlobPattern {
            pattern: [0u8; VIRT_PATH_BUF_SIZE],
            pattern_len: 0,
            has_wildcard: false,
            has_doublestar: false,
            prefix_len: 0,
            suffix_len: 0,
            literal_prefix: [0u8; VIRT_PATH_BUF_SIZE],
            literal_suffix: [0u8; VIRT_PATH_BUF_SIZE],
        }
    }
}

// ported from virtualizer_core.cpp line 708
pub fn virt_glob_compile(pattern: &[u8]) -> GlobPattern {
    let mut gp = GlobPattern::default();
    let plen = pattern.len().min(VIRT_PATH_BUF_SIZE - 1);
    gp.pattern[..plen].copy_from_slice(&pattern[..plen]);
    gp.pattern_len = plen as u32;
    gp.has_wildcard = false;
    gp.has_doublestar = false;

    for i in 0..plen {
        if pattern[i] == b'*' || pattern[i] == b'?' {
            gp.has_wildcard = true;
            if pattern[i] == b'*' && i + 1 < plen && pattern[i + 1] == b'*' {
                gp.has_doublestar = true;
            }
            break;
        }
    }

    if !gp.has_wildcard {
        gp.literal_prefix[..plen].copy_from_slice(&pattern[..plen]);
        gp.prefix_len = plen as u32;
        return gp;
    }

    let mut first_wc = plen;
    let mut last_wc = 0;
    for i in 0..plen {
        if pattern[i] == b'*' || pattern[i] == b'?' {
            if first_wc == plen {
                first_wc = i;
            }
            last_wc = i;
        }
    }

    if first_wc > 0 {
        gp.literal_prefix[..first_wc].copy_from_slice(&pattern[..first_wc]);
        gp.prefix_len = first_wc as u32;
    }
    if last_wc < plen - 1 {
        let ss = last_wc + 1;
        gp.suffix_len = (plen - ss) as u32;
        gp.literal_suffix[..(plen - ss)].copy_from_slice(&pattern[ss..]);
    }
    gp
}

// ported from virtualizer_core.cpp line 781
pub fn virt_glob_match(gp: &GlobPattern, s: &[u8]) -> bool {
    if !gp.has_wildcard {
        return s.len() == gp.pattern_len as usize
            && &s[..] == &gp.pattern[..gp.pattern_len as usize];
    }
    if gp.prefix_len > 0 {
        if s.len() < gp.prefix_len as usize {
            return false;
        }
        if &s[..gp.prefix_len as usize] != &gp.literal_prefix[..gp.prefix_len as usize] {
            return false;
        }
    }
    if gp.suffix_len > 0 {
        if s.len() < gp.suffix_len as usize {
            return false;
        }
        let soff = s.len() - gp.suffix_len as usize;
        if &s[soff..] != &gp.literal_suffix[..gp.suffix_len as usize] {
            return false;
        }
    }
    true
}

// ─── Path matching ────────────────────────────────────────────────────────
// ported from virtualizer_core.cpp lines 795-822
pub fn path_match(path: &[u8], pattern: &[u8], match_type: i32) -> bool {
    match match_type {
        VIRT_MATCH_EXACT => path == pattern,
        VIRT_MATCH_PREFIX => path.len() >= pattern.len() && path[..pattern.len()] == pattern[..],
        VIRT_MATCH_SUFFIX => {
            path.len() >= pattern.len() && path[path.len() - pattern.len()..] == pattern[..]
        }
        VIRT_MATCH_SUBSTRING => {
            if pattern.len() > path.len() {
                return false;
            }
            path.windows(pattern.len()).any(|w| w == pattern)
        }
        VIRT_MATCH_GLOB => {
            let gp = virt_glob_compile(pattern);
            virt_glob_match(&gp, path)
        }
        VIRT_MATCH_ALWAYS => true,
        VIRT_MATCH_NEVER => false,
        _ => false,
    }
}
