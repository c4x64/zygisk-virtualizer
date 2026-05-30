#!/system/bin/sh
# Keep module alive: Kitsune's crash detector may blame this
# module for unrelated system crashes. Continuously clear the
# unloaded flag so the module stays loaded across zygote restarts.
while true; do
    rm -f /data/adb/modules/zygisk-virtualizer/zygisk/unloaded
    sleep 30
done &
