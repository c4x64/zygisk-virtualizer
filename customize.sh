#!/system/bin/sh
# Zygisk Virtualizer Installation Script

# Detect environment: Magisk, KernelSU, or APatch
if [ -n "$KSU" ]; then
    ui_print "- KernelSU detected (version: $KSU_KERNEL_VER_CODE)"
    ENVIRONMENT="KernelSU"
elif [ -n "$APATCH" ]; then
    ui_print "- APatch detected"
    ENVIRONMENT="APatch"
elif [ "$MAGISK_VER_CODE" -ge 27000 ]; then
    ui_print "- Magisk $MAGISK_VER_CODE detected"
    ENVIRONMENT="Magisk"
else
    ui_print "- Unknown environment, assuming Magisk compatibility"
    ENVIRONMENT="Unknown"
fi

# Verify architecture
ARCH=$(getprop ro.product.cpu.abi)
case $ARCH in
    arm64-v8a|aarch64)
        ui_print "- Architecture: $ARCH (supported)"
        ;;
    *)
        ui_print "! Unsupported architecture: $ARCH"
        abort "This module only supports arm64-v8a"
        ;;
esac

# Extract files
ui_print "- Extracting module files"
unzip -o "$ZIPFILE" -d "$MODPATH" >/dev/null 2>&1

# Check for Zygisk support
if [ -d "$MODPATH/zygisk" ]; then
    ui_print "- Zygisk variant detected"
    if [ "$ENVIRONMENT" = "KernelSU" ] && [ ! -f /data/adb/zygisk/zygiskd ]; then
        ui_print "! Zygisk not found on KernelSU"
        ui_print "! Install ZygiskNext module for Zygisk support"
        ui_print "! Module will still be installed but may be inactive"
    fi
fi

# Set permissions
set_perm_recursive $MODPATH 0 0 0755 0644
set_perm $MODPATH/zygisk/arm64-v8a.so 0 0 0644

ui_print "- Installation complete"
ui_print "  Reboot for changes to take effect"
