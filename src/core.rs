use std::vec::Vec;

// ─── Config ──────────────────────────────────────────────────────

pub const VIRT_PATH_BUF_SIZE: usize = 4096;

pub struct VIRT_Config {
    pub config_path: [u8; VIRT_PATH_BUF_SIZE],
    pub enable_file_decoy: bool,
    pub enable_cache: bool,
    pub cache_size: u32,
    pub max_rules: u32,
    pub handler_stack_size: u32,
    pub notif_timeout_ms: u32,
    pub max_consecutive_errors: u32,
}

pub fn virt_config_default() -> VIRT_Config {
    let mut cfg = VIRT_Config {
        config_path: [0u8; VIRT_PATH_BUF_SIZE],
        enable_file_decoy: true,
        enable_cache: true,
        cache_size: 8192,
        max_rules: 1024,
        handler_stack_size: 262144,
        notif_timeout_ms: 5000,
        max_consecutive_errors: 10,
    };
    let s = b"/data/local/tmp/virtualizer/config.txt";
    cfg.config_path[..s.len()].copy_from_slice(s);
    cfg
}

pub fn virt_config_load() -> VIRT_Config {
    virt_config_default()
}

pub fn virt_config_auto_tune(cfg: &mut VIRT_Config) {
    if cfg.cache_size == 0 { cfg.cache_size = 8192; }
    if cfg.max_rules == 0 { cfg.max_rules = 1024; }
    if cfg.handler_stack_size < 65536 { cfg.handler_stack_size = 262144; }
}

pub fn virt_decoy_init(_cfg: &VIRT_Config) -> i32 { 0 }

// ─── Sensitive path patterns ─────────────────────────────────────

pub fn is_sensitive_pattern(path: &[u8]) -> bool {
    let p: &[&[u8]] = &[
        b"/su", b"/magisk", b"/sbin/.magisk", b"/data/adb",
        b"/system/bin/su", b"/system/xbin/su",
        b"/data/local/tmp/frida", b"/data/local/tmp/linjector",
        b"/data/local/tmp/xposed", b"/data/local/tmp/lsposed",
        b"/data/local/tmp/zygisk", b"/data/local/tmp/riru",
        b"frida", b"xposed", b"XposedBridge", b"dexposed",
        b"com.topjohnwu.magisk", b"com.saurik.substrate",
        b"frida-server", b"frida-helper", b"frida-agent",
        b"libfrida", b"libgadget",
        b"/proc/self/pagemap", b"/proc/self/smaps",
        b"/proc/self/mem", b"/proc/self/stack", b"/proc/self/syscall",
        b"/proc/self/mountinfo", b"/proc/self/exe",
    ];
    for pat in p {
        if path.windows(pat.len()).any(|w| w == *pat) { return true; }
    }
    false
}

// ─── Trie for path matching ──────────────────────────────────────

fn children_default() -> [Option<Box<TrieNode>>; 32] {
    [None, None, None, None, None, None, None, None,
     None, None, None, None, None, None, None, None,
     None, None, None, None, None, None, None, None,
     None, None, None, None, None, None, None, None]
}

struct TrieNode {
    children: [Option<Box<TrieNode>>; 32],
    is_end: bool,
    action: i32,
}

impl TrieNode {
    fn new() -> Self {
        TrieNode { children: children_default(), is_end: false, action: 0 }
    }
}

pub struct Trie {
    root: TrieNode,
}

impl Trie {
    pub fn new() -> Self {
        Trie { root: TrieNode::new() }
    }

    pub fn insert(&mut self, key: &[u8], action: i32) {
        let mut node = &mut self.root;
        for &b in key {
            if b == 0 || b >= 32 { break; }
            let idx = b as usize;
            if node.children[idx].is_none() {
                node.children[idx] = Some(Box::new(TrieNode::new()));
            }
            node = node.children[idx].as_mut().unwrap();
        }
        node.is_end = true;
        node.action = action;
    }

    pub fn lookup(&self, key: &[u8]) -> Option<i32> {
        let mut node = &self.root;
        for &b in key {
            if b == 0 || b >= 32 { break; }
            let idx = b as usize;
            match &node.children[idx] {
                Some(child) => node = child,
                None => return None,
            }
        }
        if node.is_end { Some(node.action) } else { None }
    }
}

// ─── LRU Cache ───────────────────────────────────────────────────

const CACHE_SIZE: usize = 256;

pub struct LRUCache {
    entries: Vec<CacheEntry>,
    count: u16,
}

struct CacheEntry {
    path: [u8; 128],
    path_len: u16,
    action: i32,
    valid: bool,
}

impl LRUCache {
    pub fn new() -> Self {
        LRUCache { entries: Vec::with_capacity(CACHE_SIZE), count: 0 }
    }

    pub fn get(&self, path: &[u8]) -> Option<i32> {
        let plen = path.len().min(127) as u16;
        for e in &self.entries {
            if e.valid && e.path_len == plen && &e.path[..plen as usize] == path {
                return Some(e.action);
            }
        }
        None
    }

    pub fn set(&mut self, path: &[u8], action: i32) {
        if path.is_empty() || path.len() > 127 { return; }
        if self.entries.len() < CACHE_SIZE {
            self.entries.push(CacheEntry {
                path: { let mut b = [0u8; 128]; let l = path.len().min(128); b[..l].copy_from_slice(&path[..l]); b },
                path_len: path.len() as u16,
                action,
                valid: true,
            });
        } else {
            let idx = (self.count as usize) % CACHE_SIZE;
            let e = &mut self.entries[idx];
            e.valid = true;
            e.path_len = path.len() as u16;
            e.path[..path.len()].copy_from_slice(path);
            e.action = action;
        }
        self.count = self.count.wrapping_add(1);
    }
}

// ─── Proc fd hiding ──────────────────────────────────────────────

pub struct ProcHider {
    pub hidden_fds: [i32; 64],
    pub hidden_fd_count: u32,
}

impl ProcHider {
    pub fn new() -> Self {
        ProcHider { hidden_fds: [-1; 64], hidden_fd_count: 0 }
    }

    pub fn add_hidden_fd(&mut self, fd: i32) {
        let n = self.hidden_fd_count as usize;
        if n < self.hidden_fds.len() {
            self.hidden_fds[n] = fd;
            self.hidden_fd_count += 1;
        }
    }

    pub fn is_fd_hidden(&self, fd: i32) -> bool {
        for i in 0..self.hidden_fd_count as usize {
            if self.hidden_fds[i] == fd { return true; }
        }
        false
    }
}
