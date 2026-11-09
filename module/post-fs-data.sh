#!/system/bin/sh
MODDIR=${0%/*}
mkdir -p /data/adb/reaper
[ -f /data/adb/reaper/policy.toml ] || cp "$MODDIR/etc/policy.toml" /data/adb/reaper/policy.toml
# Deliberately fire and forget; never block post-fs-data.
nohup "$MODDIR/bin/reaperd" >/dev/null 2>&1 &
exit 0
