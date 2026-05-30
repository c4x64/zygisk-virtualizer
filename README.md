# 🛡️ Zygisk Virtualizer — Universal Syscall Virtualization Framework

[![Build](https://github.com/droid-re-chain/zygisk-virtualizer/actions/workflows/build.yml/badge.svg)](https://github.com/droid-re-chain/zygisk-virtualizer/actions/workflows/build.yml)
[![Release](https://github.com/droid-re-chain/zygisk-virtualizer/actions/workflows/release.yml/badge.svg)](https://github.com/droid-re-chain/zygisk-virtualizer/actions/workflows/release.yml)
[![CodeQL](https://github.com/droid-re-chain/zygisk-virtualizer/actions/workflows/codeql.yml/badge.svg)](https://github.com/droid-re-chain/zygisk-virtualizer/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android%20ARM64-brightgreen)](https://developer.android.com/ndk)
[![API](https://img.shields.io/badge/API-30%2B-success)](https://developer.android.com/studio/releases/platforms)
[![Kernel](https://img.shields.io/badge/Kernel-5.0%2B-critical)](https://www.kernel.org)
[![Magisk](https://img.shields.io/badge/Magisk-27%2B-FF6F00)](https://github.com/topjohnwu/Magisk)
[![Stars](https://img.shields.io/github/stars/droid-re-chain/zygisk-virtualizer?style=social)](https://github.com/droid-re-chain/zygisk-virtualizer)

---

## 📋 Overview

**Zygisk Virtualizer** is a Magisk Zygisk module that intercepts and virtualizes filesystem-related system calls at the kernel level using Linux's `SECCOMP_RET_USER_NOTIF` mechanism. Instead of simply blocking sensitive paths (which anti-cheat engines can detect), it **redirects reads** to clean decoy files, making the environment appear completely unmodified to target applications.

### Core Concept

When an app reads `/proc/self/maps` and sees `libfrida.so` or `/su`, it knows it's in a rooted/hooked environment. Traditional root hiding simply blocks access (`-ENOENT`), but anti-cheat engines have evolved to detect this. Zygisk Virtualizer takes a different approach:

1. **Intercept** — A BPF seccomp filter intercepts filesystem syscalls (`openat`, `readlinkat`, `newfstatat`, `faccessat`, `getdents64`, `statx`, etc.)
2. **Virtualize** — A notification handler evaluates the path against a trie-based rule engine
3. **Redirect** — Sensitive paths are redirected to clean decoy files via `SECCOMP_IOCTL_NOTIF_ADDFD` (fd projection)
4. **Hide** — Non-sensitive paths are passed through seamlessly via `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
5. **Spoof** — `PR_GET_SECCOMP` is intercepted to return `SECCOMP_MODE_DISABLED`, hiding the seccomp filter itself

The result: **the app sees a completely clean filesystem** exactly as if it were running on a stock, non-rooted device — because the virtualized responses are indistinguishable from real kernel responses.

---

## ✨ Features

### 🔍 Per-Process Seccomp BPF Filtering
- Dynamic BPF compiler generates optimized seccomp filters per-process
- Architecture validation (`AUDIT_ARCH_AARCH64`) prevents cross-arch bypasses
- Optional `SECCOMP_FILTER_FLAG_TSYNC` for all-thread coverage
- Fallback to static precompiled filter on kernel compatibility issues

### 📬 SECCOMP_RET_USER_NOTIF Notification-Based Interception
- Kernel-level syscall interception with zero ptrace overhead
- Handler thread receives notifications via `ioctl(SECCOMP_IOCTL_NOTIF_RECV)`
- Response dispatched via `ioctl(SECCOMP_IOCTL_NOTIF_SEND)`
- Automatic fallback to direct syscall re-execution on pre-5.11 kernels

### 🗺️ Trie-Based Path Matching
- Fast O(n) path matching using a compressed trie with Aho-Corasick-style fallback links
- Supports multiple match types: exact, prefix, suffix, substring, glob, regex, always, never
- Pattern priorities for deterministic rule resolution
- ~80 built-in root/magisk/frida/xposed detection patterns

### ⚡ LRU Cache for O(1) Path Lookups
- Configurable cache with TTL-based invalidation
- 8,192 entry default cache (≈34MB)
- LRU eviction when cache is full
- First-miss penalty avoided on subsequent calls to the same path

### 🎭 Configurable Decoy Content
- **File-based decoys** — Load custom `/proc/self/maps` and `/proc/self/status` content from `/data/local/tmp/virtualizer/maps` and `/data/local/tmp/virtualizer/status`
- **Built-in templates** — Pre-built clean `/proc/self/maps` (no magisk/frida modules) and `/proc/self/status` (TracerPid: 0, Seccomp: 0)
- Application of decoy content via `SECCOMP_IOCTL_NOTIF_ADDFD` — actually opens the decoy file and projects the fd into the target

### 📜 JSON Rule Loading at Runtime
- Dynamic rule loading from `/data/local/tmp/virtualizer/rules.json`
- Rich JSON format with pattern, match_type, action, category, priority fields
- Rules merged with built-in defaults (user rules take higher priority)
- No reboot required — rules evaluated on handler start

### 🔐 PR_GET_SECCOMP Spoofing
- Intercepts `__NR_prctl` with `PR_GET_SECCOMP` option
- Returns `SECCOMP_MODE_DISABLED` (0) — hiding the USER_NOTIF filter
- All other prctl commands pass through to the kernel
- Critical anti-detection: anti-cheat seccomp probes see a clean state

### 📁 /proc/self/fd Hiding for Notify FD
- Notification fd registered in the `VIRT_ProcHiderState` hidden FD list
- `openat("/proc/self/fd/<notify_fd>")` blocked with `-ENOENT`
- `getdents64` output on `/proc/self/fd` filtered to remove the notify fd entry
- `newfstatat` on hidden fd paths also blocked

### 📂 getdents64 Output Filtering
- Full directory listing filtering for `/proc/self/fd`
- Removes hidden FD entries from `getdents64` responses
- Handles the `linux_dirent64` structure format
- Zero-copy filtering into pre-allocated buffer

### 📝 File-Based Decoy Loading
- `/data/local/tmp/virtualizer/config.txt` — Runtime configuration (log level, cache size, feature toggles)
- `/data/local/tmp/virtualizer/rules.json` — JSON rule definitions
- `/data/local/tmp/virtualizer/maps` — Custom `/proc/self/maps` replacement
- `/data/local/tmp/virtualizer/status` — Custom `/proc/self/status` replacement

### 🛡️ Anti-Tamper Memory Integrity Checks
- Periodic hash verification of the loaded library's code section
- Detection of writable code pages (potential hooking)
- Debugger detection via `/proc/self/status` TracerPid check
- Hook detection via `dlsym` function pointer comparison in libc
- Configurable check interval with alert counters

### 🐾 Watchdog with Auto-Recovery
- Periodic watchdog ping from the notification handler
- Configurable timeout (default 10s) with missed-ping tolerance (default 3)
- Automatic handler loop exit on watchdog trigger
- Prevents silent hangs from blocking the notification consumer

### ⏱️ Timing Jitter for Anti-Detection
- Configurable random delay added to notification processing
- Prevents latency-based fingerprinting (anti-cheat measuring response time)
- Adjustable base and range in microseconds
- Statistics tracking (min/max/avg jitter)

### 🔄 Supports Both Standard Magisk and Kitsune
- UID-based zygote detection for standard Magisk
- File-marker zygote detection (`/data/local/tmp/.virt_zygote_marker`) for Kitsune
- Graceful fallback between `onLoad` and `preAppSpecialize` paths
- Excluded process list prevents interference with Google Play Services, Chrome sandboxes

---

## 🏗️ Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Zygisk Virtualizer                         │
├───────────────┬───────────────────┬──────────────────────────┤
│ zygisk_entry  │  seccomp_engine   │    virtualizer_core       │
│  (Zygisk      │  (BPF Filter +    │    (Trie Match +          │
│   Lifecycle)  │   Handler Loop)   │     Rules + Cache)        │
├───────────────┼───────────────────┼──────────────────────────┤
│ onLoad        │ BPF Compiler      │ Trie (Aho-Corasick)      │
│ preAppSpecial │ Notification Loop │ LRU Cache                │
│ Zygote Detect │ ADDFD Projection  │ Rules Engine             │
│ Process Filter│ Decoy Files       │ Proc Hider               │
│ Thread Launch │ Syscall Re-exec   │ Anti-Tamper              │
└───────────────┴───────────────────┴──────────────────────────┘
```

### zygisk_entry.cpp — Zygisk Lifecycle & Process Filtering

| Component | Description |
|-----------|-------------|
| `onLoad()` | Called once per module load during zygote init. Probes kernel features, creates decoy files, installs seccomp filter, spawns handler thread |
| `preAppSpecialize()` | Called in forked child for standard Magisk. Handles the case where onLoad ran in the real zygote |
| `postAppSpecialize()` | Post-app-initialization hook (minimal usage) |
| Zygote Detection | UID-based (UID==0 = zygote) + file-marker fallback for Kitsune (`/data/local/tmp/.virt_zygote_marker`) |
| Process Filtering | Skips system processes (UID 1-9999), excluded list (Google Play Services, Chrome sandboxes, webview zygotes) |

**Key code flow in `onLoad`:**
```
onLoad()
  ├─ Probe kernel seccomp features
  ├─ Check UID + process name
  ├─ Skip system/excluded processes
  ├─ Create decoy files (maps, status)
  ├─ Install BPF seccomp filter → get notify_fd
  └─ Spawn handler thread (detached) → virt_seccomp_handler_launcher
```

### seccomp_engine.cpp — BPF Filter & Notification Handler

| Component | Description |
|-----------|-------------|
| BPF Compiler | Dynamic generation of optimized seccomp BPF filters with architecture validation |
| Notification Loop | `poll()` + `ioctl(NOTIF_RECV)` + path resolution + `ioctl(NOTIF_SEND)` |
| ADDFD Projection | `ioctl(SECCOMP_IOCTL_NOTIF_ADDFD)` to inject decoy file descriptors into target processes |
| Decoy File Creation | Writes built-in fake `/proc/self/maps` and `/proc/self/status` to `/data/local/tmp/` |
| Syscall Re-execution | Fallback for pre-5.11 kernels: re-executes syscalls and writes results via `process_vm_writev` |
| PR_GET_SECCOMP Spoof | Returns 0 (disabled) to hide the USER_NOTIF filter state |
| Watchdog System | Timer-based health monitoring with configurable timeout and missed-ping threshold |

**Handler loop pseudocode:**
```
virt_seccomp_handler_loop(notify_fd):
  ├─ Heap-allocate cache[8192], rules[1024], stats, proc_hider
  ├─ Load config from /data/local/tmp/virtualizer/config.txt
  ├─ Load rules from /data/local/tmp/virtualizer/rules.json
  ├─ Init proc hider → add notify_fd to hidden list
  ├─ Watchdog arm
  │
  └─ Loop:
       ├─ poll(notify_fd, timeout=5000ms)
       ├─ ioctl(NOTIF_RECV) → struct seccomp_notif
       ├─ Read path from target via process_vm_readv
       ├─ Cache lookup (LRU)
       ├─ Rules engine lookup (trie)
       ├─ Hidden FD path check
       ├─ Handle prctl (PR_GET_SECCOMP spoof)
       ├─ Handle mprotect shadow mirror guard
       ├─ Handle path redirection (ADDFD for openat)
       ├─ Send response (CONTINUE / error / direct)
       ├─ Update stats + watchdog
       └─ Health check every N iterations
```

### virtualizer_core.cpp — Trie, Rules, Cache & Anti-Tamper

| Component | Description |
|-----------|-------------|
| Trie Matching | Compressed trie with Aho-Corasick fallback links for O(n) path matching |
| Rules Engine | Array-based rules with priority sorting, supports all match types |
| LRU Cache | Path → action cache with TTL eviction and LRU replacement |
| Proc Hider | FD/PID/TID tracking, `getdents64` filtering, path-based blocking |
| Anti-Tamper | Code integrity hashing, debugger detection, hook detection, memory checks |
| Config Loader | Key=value config parser for `/data/local/tmp/virtualizer/config.txt` |
| JSON Rules Parser | Full JSON array parser for `/data/local/tmp/virtualizer/rules.json` |
| Thread Monitor | Tracks thread states, seccomp status, syscall counts |
| Shadow Library Mirror | Pristine copy of loaded library in anonymous memory for anti-tamper bypass |

### virtualizer.h — Master Header

The single master header (≈1700 LOC) contains:

- **Types & Enums** — `VIRT_SYSCALL_NR`, `VIRT_MATCH_TYPE`, `VIRT_ACTION`, `VIRT_SCOPE`, `VIRT_FILTER_MODE`, `VIRT_HANDLER_STATE`, `VIRT_PROCESS_PROFILE`
- **Structs** — `VIRT_Rule`, `VIRT_Config`, `VIRT_CacheEntry`, `VIRT_SyscallEvent`, `VIRT_EventRing`, `VIRT_HealthStatus`, `VIRT_AntiTamperState`, `VIRT_ProcHiderState`, `VIRT_KernelInfo`, etc.
- **Constants** — `VIRT_DEFAULT_CONFIG`, `VIRT_DEFAULT_BLOCKED_PATTERNS` (~80 paths), `VIRT_FAKE_MAPS_CONTENT` (~64 lines), `VIRT_FAKE_STATUS_CONTENT` (~56 lines)
- **Logging Macros** — Level-based logging through `android_log_print` (ERROR/WARN/INFO/DEBUG/TRACE)
- **Utility Inline Functions** — Time getters (`virt_gettime_ns/us/ms`), hash functions (djb2, fnv1a), syscall name resolver, errno mapper
- **API Declarations** — All functions exported from `seccomp_engine.cpp` and `virtualizer_core.cpp`

---

## ⚙️ How It Works

### Step 1: BPF Filter Design

The seccomp BPF filter is a directed acyclic graph:

```
[0]  LD arch (offset 4 in seccomp_data)
[1]  JEQ AUDIT_ARCH_AARCH64 → skip 1, fall through
[2]  RET ALLOW (non-AARCH64 architecture → bypass)
[3]  LD syscall_nr (offset 0)
[4]  JEQ __NR_faccessat → skip remaining checks
[5]  JEQ __NR_openat → skip remaining checks
[6]  JEQ __NR_readlinkat → skip remaining checks
[7]  JEQ __NR_newfstatat → skip remaining checks
[8]  JEQ __NR_statx → skip remaining checks
[9]  JEQ __NR_getdents64 → skip remaining checks
[N]  RET ALLOW (no match)
[N+1] RET USER_NOTIF (match)
```

The jump offsets are computed as `(remaining_checks + 1)` so that unmatched checks are skipped in a single jump. The dynamic BPF compiler handles this automatically.

**Intercepted syscalls:**
| Syscall | ARM64 NR | Purpose |
|---------|----------|---------|
| `openat` | 56 | Opening files (primary path-based access) |
| `readlinkat` | 78 | Reading symlink targets |
| `readlink` | 89 | Reading symlink targets (legacy) |
| `newfstatat` | 79 | Stat operations on paths |
| `statx` | 291 | Extended stat operations |
| `faccessat` | 48 | File access checks |
| `faccessat2` | 439 | Extended file access checks |
| `getdents64` | 61 | Directory listing |
| `mmap` | 222 | Memory mapping (for integrity checks) |
| `mprotect` | 226 | Memory protection changes (shadow mirror) |
| `connect` | 203 | Network connections |
| `prctl` | 167 | Process control (PR_GET_SECCOMP spoof) |

### Step 2: Notification Lifecycle

```
App Thread                   Kernel                     Handler Thread
    │                          │                              │
    │ openat("/proc/maps")     │                              │
    │─────────────────────────>│                              │
    │                          │ BPF → USER_NOTIF            │
    │                          │─────────────────────────────>│
    │    [BLOCKED]             │                              │
    │                          │                              │ poll(notify_fd) ← event
    │                          │                              │ ioctl(NOTIF_RECV) → req
    │                          │                              │ process_vm_readv(path)
    │                          │                              │ trie_lookup(path)
    │                          │                              │ resolve action
    │                          │                              │
    │                          │                              │ [REDIRECT]:
    │                          │                              │   open(decoy_file)
    │                          │                              │   ioctl(ADDFD) → fd
    │                          │                              │
    │                          │                              │ [CONTINUE]:
    │                          │                              │   resp.flags = CONTINUE
    │                          │                              │
    │                          │                              │ ioctl(NOTIF_SEND, resp)
    │                          │<─────────────────────────────│
    │    [UNBLOCKED]           │                              │
    │  openat returns fd       │                              │
    │<─────────────────────────│                              │
```

### Step 3: Path Action Types

| Action | Value | Behavior |
|--------|-------|----------|
| `ALLOW` | 0 | Let syscall proceed normally via CONTINUE |
| `BLOCK_ENOENT` | 1 | Return `-ENOENT` (file not found) |
| `BLOCK_EACCES` | 2 | Return `-EACCES` (permission denied) |
| `BLOCK_EPERM` | 3 | Return `-EPERM` (operation not permitted) |
| `BLOCK_ENXIO` | 4 | Return `-ENXIO` (no such device) |
| `BLOCK_EIO` | 5 | Return `-EIO` (I/O error) |
| `BLOCK_EROFS` | 6 | Return `-EROFS` (read-only filesystem) |
| `REDIRECT_PATH` | 7 | Redirect `openat` to a different file path |
| `FAKE_CONTENT` | 8 | Serve decoy content file |
| `FAKE_EMPTY` | 9 | Return empty content |
| `FAKE_MAPS` | 10 | Serve built-in fake `/proc/self/maps` content |
| `FAKE_STATUS` | 11 | Serve built-in fake `/proc/self/status` content |
| `PASS_THROUGH` | 12 | Let kernel handle via `SECCOMP_USER_NOTIF_FLAG_CONTINUE` |

### Step 4: ADDFD FD Projection (Linux 5.8+)

For `openat`/`openat2` on sensitive paths, instead of returning an error or continuing to the real path, the handler:

1. Opens the decoy file locally (e.g., `/data/local/tmp/clean_maps`)
2. Calls `ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd)` which:
   - Atomically injects the fd into the target process's fd table
   - Returns the new fd number to the handler
   - Sends the NOTIF_SEND response automatically (the callout is both ADDFD + SEND)
3. The target's `openat` syscall returns the new fd pointing to the decoy file

### Step 5: Direct Fallback for Pre-5.11 Kernels

On kernels without `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (< 5.11):

- The handler cannot return CONTINUE to let the kernel execute the syscall
- Instead, it re-executes the syscall locally via a raw `syscall()` invocation
- For syscalls that produce output (readlinkat, newfstatat, statx, getdents64), results are written to the target's memory via `process_vm_writev`
- This ensures full compatibility even on older Android kernels (Android 12 with 5.10 kernel, etc.)

---

## 📦 Build Instructions

### Prerequisites

- **Android NDK** 25.2.9519653 or later
- **Android SDK** platform 30+ (Android 11)
- **ARM64 cross-compilation toolchain** (included in NDK)

### Quick Build

```sh
# Setup JNI symlinks (required for ndk-build)
mkdir -p jni && ln -sf ../*.cpp ../*.h ../Android.mk ../Application.mk jni/

# Build
NDK=/path/to/android-ndk-r25c
NDK_PROJECT_PATH=/path/to/bypass $NDK/ndk-build NDK_DEBUG=0
```

### Using Homebrew NDK (macOS)

```sh
NDK=/opt/homebrew/share/android-commandlinetools/ndk/25.2.9519653
NDK_PROJECT_PATH=$PWD $NDK/ndk-build NDK_DEBUG=0
```

### Using CMake (Alternative)

```sh
mkdir -p build/cmake && cd build/cmake
cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a \
      -DANDROID_PLATFORM=android-30 \
      -DCMAKE_BUILD_TYPE=Release \
      ../..
cmake --build .
```

### Output

The compiled library is at `libs/arm64-v8a/libvirtualizer.so`.

### Build Configuration

| Flag | Description |
|------|-------------|
| `NDK_DEBUG=0` | Release build with optimization |
| `NDK_DEBUG=1` | Debug build with symbols |
| `APP_STL=c++_static` | Static C++ runtime (required for Kitsune compatibility) |

---

## 📱 Installation

### Module Structure

```
zygisk-virtualizer-v1.0.0.zip
├── zygisk/
│   └── arm64-v8a.so          # Compiled library
├── module.prop               # Magisk module metadata
├── post-fs-data.sh           # Boot-time cleanup script
└── service.sh                # Service watchdog script
```

### Install via Magisk Manager

1. Build or download the compiled `.zip` from releases
2. Open Magisk Manager → Modules → Install from storage
3. Select `zygisk-virtualizer-v1.0.0.zip`
4. Reboot the device

### Manual Installation via ADB

```sh
# Push and install
adb push zygisk-virtualizer-v1.0.0.zip /data/local/tmp/
adb shell su -c 'magisk --install-module /data/local/tmp/zygisk-virtualizer-v1.0.0.zip'

# Reboot
adb reboot
```

### Packaging from Source

```sh
rm -rf /tmp/module && mkdir -p /tmp/module/zygisk
cp libs/arm64-v8a/libvirtualizer.so /tmp/module/zygisk/arm64-v8a.so
cp module.prop post-fs-data.sh service.sh /tmp/module/
cd /tmp/module && zip -r /tmp/zygisk-virtualizer-v1.0.0.zip .
```

---

## 🛠️ Configuration

### Config File: `/data/local/tmp/virtualizer/config.txt`

```ini
# Log level: 0=none, 1=error, 2=warn, 3=info, 4=debug, 5=trace
log_level=3

# Filter mode: 0=static BPF, 1=dynamic BPF
filter_mode=0

# Default action for unmatched paths (0=allow, 1=block-enoent, 12=pass-through)
default_action=12

# Cache configuration
cache_size=8192
stats_window_sec=60

# Watchdog: interval in seconds, max missed pings before trigger
watchdog_interval_sec=10

# Handler thread stack size (min=65536, max=8388608)
handler_stack_size=262144

# Notification timeout in milliseconds
notif_timeout_ms=5000

# Maximum consecutive errors before handler exits
max_consecutive_errors=10

# Timing jitter in microseconds (0 = disabled)
timing_jitter_us=0
jitter_range_us=0

# Decoy file paths
fake_maps_path=/data/local/tmp/virtualizer/maps
fake_status_path=/data/local/tmp/virtualizer/status

# JSON rules path
rules_json_path=/data/local/tmp/virtualizer/rules.json

# Feature toggles (0=disabled, 1=enabled)
enable_stats=1
enable_cache=1
enable_watchdog=1
enable_anti_tamper=1
enable_proc_hiding=1
enable_fake_content=1
enable_thread_sync=1
enable_kernel_compat=1
enable_self_diagnostics=1
enable_trie_index=1
enable_event_ring=1
enable_file_decoy=0
enable_timing_jitter=0
```

### JSON Rules Format: `/data/local/tmp/virtualizer/rules.json`

```json
[
  {
    "pattern": "/data/adb/magisk",
    "match_type": "prefix",
    "action": "block_enoent",
    "category": "root",
    "priority": 200
  },
  {
    "pattern": "**/frida*",
    "match_type": "glob",
    "action": "block_enoent",
    "category": "hook",
    "priority": 300
  },
  {
    "pattern": "/proc/self/maps",
    "match_type": "exact",
    "action": "redirect",
    "redirect_target": "/data/local/tmp/clean_maps",
    "category": "proc",
    "priority": 100
  },
  {
    "pattern": "gum-js-loop",
    "match_type": "substr",
    "action": "block_enoent",
    "category": "hook",
    "priority": 300
  }
]
```

#### JSON Rule Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern` | string | Yes | Path pattern to match |
| `match_type` | string | No | `exact`, `prefix`, `suffix`, `substr`, `glob` (default: `exact`) |
| `action` | string | Yes | `allow`, `block_enoent`, `block_eacces`, `block_eperm`, `block_enxio`, `block_eio`, `block_erofs`, `redirect`, `fake_content`, `fake_empty`, `fake_maps`, `fake_status`, `pass_through` |
| `category` | string | No | `proc`, `debug`, `root`, `hook`, `system`, `tmp`, `sys`, `app`, `other` |
| `priority` | integer | No | Higher priority rules are evaluated first (default: 0) |
| `redirect_target` | string | No | Target path for `redirect` action |
| `fake_content_path` | string | No | Decoy file path for `fake_content` action |

### Decoy Content Files

**`/data/local/tmp/virtualizer/maps`** — Custom `/proc/self/maps` content:
```
557e8000-558e9000 r-xp 00000000 fe:00 12345     /system/bin/app_process64
558e9000-558ea000 r--p 00101000 fe:00 12345     /system/bin/app_process64
7c000000-7c032000 r-xp 00000000 fe:00 67890     /system/lib64/linker64
... (see built-in VIRT_FAKE_MAPS_CONTENT in virtualizer.h)
```

**`/data/local/tmp/virtualizer/status`** — Custom `/proc/self/status` content:
```
Name:   app_process64
State:  S (sleeping)
Tgid:   12345
Pid:    12345
PPid:   1
TracerPid:      0
Seccomp:        0
... (see built-in VIRT_FAKE_STATUS_CONTENT in virtualizer.h)
```

---

## 🧪 Supported Kernel Features

| Kernel Version | Feature | Status |
|----------------|---------|--------|
| 5.0+ | `SECCOMP_RET_USER_NOTIF` | ✅ Required |
| 5.0+ | `SECCOMP_FILTER_FLAG_NEW_LISTENER` | ✅ Required |
| 5.8+ | `SECCOMP_IOCTL_NOTIF_ADDFD` | ✅ Enhanced |
| 5.11+ | `SECCOMP_USER_NOTIF_FLAG_CONTINUE` | ✅ Enhanced |
| 5.0+ | `SECCOMP_FILTER_FLAG_TSYNC` | ✅ Optional |
| 4.x | No USER_NOTIF support | ❌ Not supported |

### Feature Detection

The module probes kernel features at startup via `SECCOMP_GET_ACTION_AVAIL` and `seccomp(SECCOMP_SET_MODE_FILTER, flags)`:

```
Kernel features: USER_NOTIF=Y NEW_LISTENER=Y TSYNC=Y TSYNC_ESRCH=Y LOG=N TRACE=N NOTIF_SIZES=Y (0x67)
```

- **USER_NOTIF** (bit 0): Core requirement — notification-based interception
- **NEW_LISTENER** (bit 1): Core requirement — creates a listener fd per filter
- **TSYNC** (bit 2): Thread synchronization — applies filter to all threads
- **TSYNC_ESRCH** (bit 5): Extended TSYNC — handles exited threads gracefully
- **CONTINUE** (bit 0 implicit): Linux 5.11+ — kernel executes the syscall on our behalf
- **ADDFD** (implicit): Linux 5.8+ — fd projection into target process

---

## 🛡️ Anti-Detection Measures

### 1. Seccomp State Hiding
**Technique**: Intercept `PR_GET_SECCOMP` via `__NR_prctl` notification handler
**How**: When an app calls `prctl(PR_GET_SECCOMP, ...)`, the handler returns `0` (`SECCOMP_MODE_DISABLED`), making it appear that no seccomp filter is installed
**Why**: Anti-cheat engines probe seccomp state to detect filtering; presenting a clean state defeats this check

### 2. No Ptrace Usage
**Technique**: Pure seccomp-based interception with zero ptrace
**How**: The notification handler uses `SECCOMP_RET_USER_NOTIF` + `SECCOMP_IOCTL_NOTIF_ADDFD` — no `PTRACE_SYSCALL` or `PTRACE_TRACEME` involved
**Why**: Ptrace is a primary anti-cheat detection vector. Anti-cheat checks for `TracerPid != 0` or ptrace attach failures. Our approach is invisible to ptrace-based scans

### 3. Handler Thread Naming
**Technique**: Non-suspicious thread name
**How**: Handler thread named `seccomp-virt` via `prctl(PR_SET_NAME)`
**Why**: Blends in with normal system thread naming patterns

### 4. Timing Jitter
**Technique**: Randomized processing delays
**How**: Optional random delay (configurable base + range in microseconds) added to notification processing
**Why**: Anti-cheat engines measure syscall latency to detect interception; adding jitter normalizes the timing profile

### 5. Fake /proc/self/maps Content
**Technique**: Complete replacement of /proc/self/maps
**How**: Built-in template (VIRT_FAKE_MAPS_CONTENT) with ~64 lines of clean library mappings — no magisk, frida, xposed, or suspicious entries
**Why**: Contents of /proc/self/maps are the most common detection vector; providing realistic-looking clean output is critical

### 6. Fake /proc/self/status Content
**Technique**: Cleaned process status
**How**: Built-in template with `TracerPid: 0`, `Seccomp: 0`, realistic memory values
**Why**: Anti-cheat reads `/proc/self/status` to detect ptrace (TracerPid) and seccomp state

### 7. Shadow Library Mirror
**Technique**: Pristine code copy for anti-tamper
**How**: Loads a clean copy of the library into anonymous memory; anti-cheat memory scans of the execution_base region see the untouched original
**Why**: Anti-cheat engines scan code pages for hooks/NOPs/patch patterns; the shadow mirror shows a clean library state

### 8. FD Table Hiding
**Technique**: Hide notification fd from /proc/self/fd
**How**: The notification fd is tracked in `VIRT_ProcHiderState`. `openat` on `/proc/self/fd/<fd>` returns `-ENOENT`, and `getdents64` output filters out the fd entry
**Why**: Anti-cheat enumerates the process fd table to find suspicious file descriptors (e.g., seccomp notify fds)

### 9. getdents64 Output Sanitization
**Technique**: Filtered directory listings
**How**: `getdents64` responses are post-processed to remove entries matching hidden FDs, PIDs, and TIDs
**Why**: Anti-cheat lists `/proc/self/fd/` to detect hidden file descriptors

### 10. Anti-Tamper Integrity Checks
**Technique**: Self-verification of code integrity
**How**: Periodic hashing of loaded library header, detection of writable code pages, function pointer comparison for common hooked libc functions
**Why**: If an anti-cheat engine hooks the handler's own code, the integrity check detects it and can trigger countermeasures

---

## 🔧 Kitsune Compatibility

[Magisk Kitsune](https://github.com/KitsuneMagisk) (formerly Magisk Delta) has a different Zygisk lifecycle:

| Aspect | Standard Magisk | Kitsune |
|--------|----------------|---------|
| `onLoad` | Called once in real zygote (UID=0) | Called in every forked child (UID=0) |
| `preAppSpecialize` | Called in forked children | **Never called** |
| Zygote Detection | `getuid() == 0` (once) | File marker needed (multiple UID=0) |

### How We Handle Kitsune

```cpp
static bool virt_is_zygote_process(void) {
    uid_t uid = getuid();
    if (uid > 0 && uid < 10000) return false;  // System process
    if (uid >= 10000) return false;             // App process

    // UID == 0: could be real zygote or Kitsune forked child
    static const char *marker = "/data/local/tmp/.virt_zygote_marker";
    if (stat(marker, &st) == 0) return false;   // File exists → not first
    int fd = open(marker, O_WRONLY|O_CREAT|O_EXCL, 0644);
    if (fd >= 0) { close(fd); return true; }    // Created marker → real zygote
    return false;                                // Race loser → not first
}
```

The first process with UID=0 creates the marker file and is identified as the real zygote. Subsequent processes see the existing marker and know they are forked children. The marker is cleaned by `post-fs-data.sh` on each boot.

---

## 🧪 Testing

### Test Device Setup

The project is tested on **BlueStacks Tiramisu64** (Android 13, ARM64) with Magisk v27+:

```sh
# Connect ADB
adb connect 127.0.0.1:5555

# Build and deploy
NDK_PROJECT_PATH=$PWD $NDK/ndk-build NDK_DEBUG=0
./package.sh && adb push /tmp/zygisk-virtualizer-v1.0.0.zip /data/local/tmp/
adb shell su -c 'magisk --install-module /data/local/tmp/zygisk-virtualizer-v1.0.0.zip'
adb reboot
```

### Monitoring Logs

```sh
# Watch virtualizer logs
adb logcat -s Virtualizer ZygiskVirtualizer

# Filter for specific events
adb logcat -s Virtualizer | grep -E "REDIRECT|BLOCK|CONTINUE"

# Watch for handler startup
adb logcat -s Virtualizer | grep -E "Handler v.*started"

# View stats output (every 5000 events)
adb logcat -s Virtualizer | grep "Periodic stats"
```

### Verification

```sh
# Check if module is loaded
adb shell ls -la /data/adb/modules/zygisk-virtualizer/

# Test path hiding (from a target app context)
adb shell run-as com.target.app ls -la /data/adb/magisk

# Verify TracerPid spoofing
adb shell cat /proc/self/status | grep TracerPid

# Verify Seccomp hiding
adb shell cat /proc/self/status | grep Seccomp
```

---

## 🔍 Troubleshooting

### Module Not Loading

| Symptom | Likely Cause | Solution |
|---------|-------------|----------|
| No logs in logcat | Kernel < 5.0 | Check kernel version, USER_NOTIF required |
| `SECCOMP_RET_USER_NOTIF not available` | Missing kernel feature | Verify kernel ≥ 5.0 with `uname -r` |
| `SECCOMP_FILTER_FLAG_NEW_LISTENER not available` | Missing kernel feature | Verify kernel ≥ 5.0 |
| Silent failure | Kitsune + shared STL | Ensure `APP_STL := c++_static` |

### Bootloop Recovery

If the module causes a bootloop:

**Method 1 — ADB (Recommended):**
```sh
# Connect during boot animation
adb connect 127.0.0.1:5555

# Remove module
adb shell su -c 'magisk --remove-modules'

# Or manually:
adb shell rm -rf /data/adb/modules/zygisk-virtualizer/
adb shell rm -f /data/local/tmp/.virt_zygote_marker

# Reboot
adb reboot
```

**Method 2 — Recovery Mode:**
1. Boot into custom recovery
2. Navigate to `/data/adb/modules/` via file manager
3. Delete `zygisk-virtualizer/`
4. Reboot

**Method 3 — Factory Reset (BlueStacks):**
If ADB is unavailable, uninstall and reinstall the BlueStacks instance from Multi-Instance Manager.

---

## 📄 License

MIT License

Copyright (c) 2024 droid-re-chain

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

*Built with ❤️ for the Android modding community*
