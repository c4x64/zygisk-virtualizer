# Kernel Module Integration

## Overview
The Zygisk Virtualizer can optionally use a kernel module for deeper integration.
This provides VFS-level path virtualization that is undetectable from userspace.

## Building
Requires kernel source for your device. Not for general distribution.

## Installation
1. Build for your kernel version
2. insmod virtualizer_kern.ko
3. Verify with: cat /proc/virtualizer/status
