#!/system/bin/sh
# post-fs-data.sh - Zygisk Virtualizer early boot setup

# Create runtime directories
mkdir -p /data/local/tmp/virtualizer

# Remove stale Zygisk unloaded flag from previous boot
rm -f /data/adb/modules/zygisk-virtualizer/zygisk/unloaded

# Remove stale zygote marker so the first real zygote creates it fresh
rm -f /data/local/tmp/.virt_zygote_marker

# On KernelSU/APatch, ensure ZygiskNext compatibility
if [ -n "$KSU" ] || [ -n "$APATCH" ]; then
    # Create zygisk directory if it doesn't exist (for ZygiskNext)
    mkdir -p /data/adb/zygisk
fi

# Set proper SELinux context
chcon u:object_r:tmpfs:s0 /data/local/tmp/virtualizer 2>/dev/null || true
