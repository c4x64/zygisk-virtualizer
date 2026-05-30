#!/system/bin/sh
# post-fs-data.sh - Zygisk Virtualizer early boot setup

MODDIR=/data/adb/modules/zygisk-virtualizer
VIRT_DIR=/data/local/tmp/virtualizer

# Clean mode: if called with --clean, remove runtime artifacts and exit
if [ "$1" = "--clean" ]; then
    rm -rf $VIRT_DIR
    rm -f /data/local/tmp/.virt_zygote_marker
    echo "[*] Cleanup complete: $(date)" >> /dev/null
    exit 0
fi

# Create runtime directories
mkdir -p $VIRT_DIR
mkdir -p $VIRT_DIR/logs

# KernelSU kernel module loading: if a .ko exists alongside the module, load it
if [ -f $MODDIR/virtualizer.ko ]; then
    if [ -x /system/bin/modprobe ]; then
        /system/bin/modprobe -d $MODDIR virtualizer 2>/dev/null || true
    elif [ -x /system/bin/insmod ]; then
        /system/bin/insmod $MODDIR/virtualizer.ko 2>/dev/null || true
    fi
fi

# Health check on boot: verify module files exist
if [ ! -f $MODDIR/module.prop ]; then
    echo "[!] Health check FAILED: module.prop missing" >> $VIRT_DIR/logs/boot.log 2>/dev/null || true
fi
if [ ! -f $MODDIR/zygisk/arm64-v8a.so ]; then
    echo "[!] Health check FAILED: arm64-v8a.so missing" >> $VIRT_DIR/logs/boot.log 2>/dev/null || true
    rm -f $MODDIR/zygisk/unloaded
    echo -n > $MODDIR/disable
    exit 1
fi
echo "[*] Health check passed: $(date)" >> $VIRT_DIR/logs/boot.log 2>/dev/null || true

# Safe mode flag check: if Magisk created a disable flag during safe mode,
# ensure we don't re-enable ourselves prematurely.
if [ -f /cache/.disable_magisk ] || [ -f /data/unencrypted/.disable_magisk ] || [ -f /persist/.disable_magisk ]; then
    echo "[!] Boot safe mode flag detected — keeping module disabled" >> $VIRT_DIR/logs/boot.log
    echo -n > $MODDIR/disable
    exit 1
fi
if [ -f /data/adb/ksu/.disable_ksu ]; then
    echo "[!] KernelSU safe mode flag detected — keeping module disabled" >> $VIRT_DIR/logs/boot.log
    echo -n > $MODDIR/disable
    exit 1
fi

# Record boot timestamp for uptime tracking
date +%s > $VIRT_DIR/.last_boot 2>/dev/null || true

# Create boot-complete marker (post-fs-data runs early; service.sh marks full completion)
echo "0" > $VIRT_DIR/.boot_complete 2>/dev/null || true

# Remove stale Zygisk unloaded flag from previous boot
rm -f $MODDIR/zygisk/unloaded

# Remove stale zygote marker so the first real zygote creates it fresh
rm -f /data/local/tmp/.virt_zygote_marker

# On KernelSU/APatch, ensure ZygiskNext compatibility
if [ -n "$KSU" ] || [ -n "$APATCH" ]; then
    # Create zygisk directory if it doesn't exist (for ZygiskNext)
    mkdir -p /data/adb/zygisk
fi

# Set proper SELinux context
chcon u:object_r:tmpfs:s0 $VIRT_DIR 2>/dev/null || true
