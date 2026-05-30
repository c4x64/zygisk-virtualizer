# Changelog

## v1.0.0 (2025-01-01)
- Initial release
- SECCOMP_RET_USER_NOTIF-based path virtualization
- Zygisk integration via Magisk 27+ / ZygiskNext / KernelSU
- Decoy file projection for /proc/self/maps, /proc/self/status
- Blocked path patterns for root, magisk, frida, xposed detection
- PR_GET_SECCOMP seccomp state spoofing via __NR_prctl interception
- getdents64 filtering to hide notify fd from /proc scans
- ADDFD support for transparent fd redirection (Linux 5.8+)
- Watchdog timer with 3-second timeout and crash recovery
- Trie-based rules engine with LRU cache for fast path matching
- Compatible with Magisk 27+, KernelSU, APatch, and ZygiskNext
