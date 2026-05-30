#!/system/bin/sh
# Remove stale Zygisk unloaded flag from previous boot
rm -f /data/adb/modules/zygisk-virtualizer/zygisk/unloaded
# Remove stale zygote marker so the first real zygote creates it fresh
rm -f /data/local/tmp/.virt_zygote_marker
