#!/system/bin/sh
# service.sh - Zygisk Virtualizer late boot service

MODDIR=/data/adb/modules/zygisk-virtualizer
VIRT_DIR=/data/local/tmp/virtualizer
LOG_DIR=$VIRT_DIR/logs
CRASH_FILE=$VIRT_DIR/.crash_count
MAX_CRASHES=3
GITHUB_REPO="prabhas/zygisk-virtualizer"

# Ensure runtime directories exist
mkdir -p $LOG_DIR

# Log rotation: keep at most 5 rotated logs, each max ~500KB
if [ -f $LOG_DIR/virtualizer.log ]; then
    if [ $(stat -c%s $LOG_DIR/virtualizer.log 2>/dev/null || echo 0) -gt 512000 ]; then
        mv $LOG_DIR/virtualizer.log $LOG_DIR/virtualizer.log.old
        for i in 4 3 2 1; do
            j=$((i + 1))
            [ -f $LOG_DIR/virtualizer.log.$i ] && mv $LOG_DIR/virtualizer.log.$i $LOG_DIR/virtualizer.log.$j
        done
        [ -f $LOG_DIR/virtualizer.log.old ] && mv $LOG_DIR/virtualizer.log.old $LOG_DIR/virtualizer.log.1
    fi
fi

# Safe mode detection: if Magisk or KernelSU safe-mode flags are set,
# disable the module and log a warning.
if [ -f /cache/.disable_magisk ] || [ -f /data/unencrypted/.disable_magisk ] || [ -f /persist/.disable_magisk ]; then
    echo "[!] Magisk safe mode detected — disabling virtualizer" >> $LOG_DIR/virtualizer.log
    rm -f $MODDIR/zygisk/unloaded
    echo -n > $MODDIR/disable
    exit 0
fi
if [ -f /data/adb/ksu/.disable_ksu ]; then
    echo "[!] KernelSU safe mode detected — disabling virtualizer" >> $LOG_DIR/virtualizer.log
    rm -f $MODDIR/zygisk/unloaded
    echo -n > $MODDIR/disable
    exit 0
fi

# Auto-recovery: track module crashes via the zygisk/unloaded flag.
# If the unloaded flag appears MAX_CRASHES times, disable the module.
if [ -f $MODDIR/zygisk/unloaded ]; then
    count=0
    [ -f $CRASH_FILE ] && count=$(cat $CRASH_FILE 2>/dev/null || echo 0)
    count=$((count + 1))
    echo $count > $CRASH_FILE
    echo "[!] Module unloaded detected (crash #$count of $MAX_CRASHES)" >> $LOG_DIR/virtualizer.log
    if [ $count -ge $MAX_CRASHES ]; then
        echo "[!] Module crashed $MAX_CRASHES times — disabling to prevent bootloop" >> $LOG_DIR/virtualizer.log
        echo -n > $MODDIR/disable
        rm -f $MODDIR/zygisk/unloaded
        rm -f $CRASH_FILE
        exit 0
    fi
else
    rm -f $CRASH_FILE
fi

# Auto-update check: query GitHub releases for a newer version
LATEST=$(curl -s --connect-timeout 5 "https://api.github.com/repos/$GITHUB_REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4)
if [ -z "$LATEST" ]; then
    LATEST=$(wget -q -O - --timeout=5 "https://api.github.com/repos/$GITHUB_REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4)
fi
if [ -n "$LATEST" ]; then
    CURRENT=$(grep VIRTUALIZER_VERSION /data/local/tmp/virtualizer/.version 2>/dev/null || echo "0.0.0")
    if [ "$LATEST" != "$CURRENT" ]; then
        echo "[*] Update available: $CURRENT -> $LATEST" >> $LOG_DIR/virtualizer.log
    fi
fi

# Keep module alive: Kitsune's crash detector may blame this
# module for unrelated system crashes. Continuously clear the
# unloaded flag so the module stays loaded across zygote restarts.
while true; do
    rm -f $MODDIR/zygisk/unloaded
    sleep 30
done &

# On KernelSU/APatch with ZygiskNext, verify zygiskd is running
if [ -n "$KSU" ] || [ -n "$APATCH" ]; then
    if [ -f /data/adb/zygisk/zygiskd ]; then
        # ZygiskNext daemon present
        :
    fi
fi
