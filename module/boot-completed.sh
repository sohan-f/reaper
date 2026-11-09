#!/system/bin/sh
# Signal the daemon that the framework is up; it starts enforcing on the
# armed marker.
mkdir -p /data/adb/reaper
: > /data/adb/reaper/armed
exit 0
