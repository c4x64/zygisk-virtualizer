#!/system/bin/sh
# KernelSU/APatch Action Script
# Called from WebUI or ksud action command

case "$1" in
    status)
        echo "Zygisk Virtualizer Status"
        echo "========================"
        if [ -d /data/adb/modules/zygisk-virtualizer ]; then
            echo "Module: Installed"
        else
            echo "Module: Not installed"
            exit 1
        fi
        if [ -c /data/local/tmp/.virt_zygote_marker ]; then
            echo "Zygote: Active"
        else
            echo "Zygote: Inactive"
        fi
        dmesg | grep "seccomp-virt" | tail -5
        ;;
    clear-logs)
        rm -f /data/local/tmp/virtualizer/*.log 2>/dev/null
        echo "Logs cleared"
        ;;
    reset)
        rm -f /data/local/tmp/.virt_zygote_marker
        rm -rf /data/local/tmp/virtualizer/rules.json
        echo "Reset complete. Reboot required"
        ;;
    *)
        echo "Usage: $0 {status|clear-logs|reset}"
        exit 1
        ;;
esac
