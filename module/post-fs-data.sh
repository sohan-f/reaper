#!/system/bin/sh
MODDIR=${0%/*}
mkdir -p /data/adb/reaper
[ -f /data/adb/reaper/policy.toml ] || cp "$MODDIR/etc/policy.toml" /data/adb/reaper/policy.toml
# reaperd loads eBPF, so it must start after Android's load-bpf-programs action.
exit 0
