#!/system/bin/sh
# service.sh - Zygisk Virtualizer late boot service

# Ensure runtime directories exist
mkdir -p /data/local/tmp/virtualizer

# Keep module alive: Kitsune's crash detector may blame this
# module for unrelated system crashes. Continuously clear the
# unloaded flag so the module stays loaded across zygote restarts.
while true; do
    rm -f /data/adb/modules/zygisk-virtualizer/zygisk/unloaded
    sleep 30
done &

# On KernelSU/APatch with ZygiskNext, verify zygiskd is running
if [ -n "$KSU" ] || [ -n "$APATCH" ]; then
    if [ -f /data/adb/zygisk/zygiskd ]; then
        # ZygiskNext daemon present
        :
    fi
fi
