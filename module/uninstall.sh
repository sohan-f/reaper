#!/system/bin/sh
PID=$(pidof reaperd)
[ -n "$PID" ] && kill "$PID" 2>/dev/null
rm -rf /data/adb/reaper
exit 0
