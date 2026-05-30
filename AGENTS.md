## Repo: Zygisk Virtualizer

Android Zygisk module using SECCOMP_RET_USER_NOTIF + SECCOMP_IOCTL_NOTIF_ADDFD to redirect sensitive path reads (maps, status, su, magisk, frida, xposed) to clean decoy files instead of blocking with -ENOENT. Includes __NR_prctl interception to spoof PR_GET_SECCOMP, hiding the seccomp filter from anti-cheat seccomp state probing.

### Architecture

- **`virtualizer.h`**: Single master header (1694 LOC) — all types, constants, API declarations, `VIRT_DEFAULT_BLOCKED_PATTERNS` (~80 root/anti-cheat/detection paths), `VIRT_FAKE_MAPS_CONTENT` and `VIRT_FAKE_STATUS_CONTENT` templates.
- **`zygisk_entry.cpp`**: Zygisk module entry — `onLoad`/`preAppSpecialize` with UID + file-marker zygote detection (works on both standard Magisk and Kitsune).
- **`seccomp_engine.cpp`**: BPF filter, notification handler loop, `virt_seccomp_try_addfd()` for fd projection into target processes, decoy file creation.
- **`virtualizer_core.cpp`**: Trie-based path matching, rules engine, LRU cache, /proc fd hider (getdents64 filtering + openat blocking).

### Build

```sh
NDK=/opt/homebrew/share/android-commandlinetools/ndk/25.2.9519653
NDK_PROJECT_PATH=/path/to/bypass $NDK/ndk-build NDK_DEBUG=0
```

ndk-build requires `jni/` directory with symlinks to source files at repo root — run `mkdir -p jni && ln -sf ../*.cpp ../*.h ../Android.mk ../Application.mk jni/` if `jni/` is missing.

### Packaging

```sh
rm -rf /tmp/module && mkdir -p /tmp/module/zygisk
cp libs/arm64-v8a/libvirtualizer.so /tmp/module/zygisk/arm64-v8a.so
cp module.prop post-fs-data.sh service.sh /tmp/module/
cd /tmp/module && zip -r /tmp/zygisk-virtualizer-v1.0.0.zip .
```

Zip structure: `zygisk/arm64-v8a.so`, `module.prop`, `post-fs-data.sh`, `service.sh`

### Device Testing

Test device: Samsung SM-S908E (Galaxy S22 Ultra, Android 13, ARM64), Magisk Kitsune v27.2.

ADB transport uses TCP — after reboot, reconnect to `emulator-5554`:
```sh
adb kill-server && sleep 2 && adb start-server
adb -s emulator-5554 shell ...
```

Module install: `adb push zip /data/local/tmp/ && adb shell su -c 'magisk --install-module /data/local/tmp/zygisk-virtualizer-v1.0.0.zip'`

### Key Quirks

- **Static C++ STL**: `APP_STL := c++_static` in Application.mk — the library MUST NOT depend on `libc++_shared.so` or Magisk Kitsune's Zygisk loader crashes silently without logs.
- **Kitsune**: `preAppSpecialize` never called; `onLoad` runs in every forked child with UID 0. Zygote detection uses a file-marker at `/data/local/tmp/.virt_zygote_marker`.
- **GNSS crash**: Samsung HAL bug (`gps.bst.so` null deref) triggers Kitsune's crash detector to create `zygisk/unloaded`. `post-fs-data.sh` and `service.sh` clear this flag continuously.
- **ADDFD**: Linux 5.8+ feature. On kernels without it (e.g., emulated or old devices), falls back to CONTINUE for all paths.
- **`__NR_getdents64`**: Not defined for ARM64 NDK headers. `virtualizer.h` defines it as 61 (ARM64) behind `#ifndef`.
- **`seccomp_notif`/`seccomp_notif_resp`**: NDK headers define these. `struct seccomp_notif_addfd` also available in NDK 25 headers.
- **Notify fd hiding**: `/proc/self/fd/<notify_fd>` blocked with BLOCK_ENOENT for `openat`/`newfstatat`; `getdents64` output filtered to remove the entry.
- **Watchdog**: 3-second timeout with 5 consecutive failure tolerance; exits handler loop if exceeded.

### Files to Edit

| File | Purpose |
|------|---------|
| `zygisk_entry.cpp` | Zygisk lifecycle, zygote detection, process filtering |
| `seccomp_engine.cpp` | BPF filter, handler loop, ADDFD redirect, decoy files |
| `virtualizer_core.cpp` | Trie, cache, rules, proc hider, anti-tamper |
| `virtualizer.h` | All types, patterns, config defaults, function declarations |
