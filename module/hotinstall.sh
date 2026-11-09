#!/system/bin/sh
MODDIR=${0%/*}
pid=$(pidof reaperd)
[ -n "$pid" ] && kill "$pid"
sleep 1
# The framework is already up during a hot install.
mkdir -p /data/adb/reaper
: > /data/adb/reaper/armed
nohup "$MODDIR/bin/reaperd" >/dev/null 2>&1 &
exit 0
