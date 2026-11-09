#!/system/bin/sh
for pid in $(pidof reaperd); do
    kill "$pid" 2>/dev/null
done
sleep 1
for pid in $(pidof reaperd); do
    kill -9 "$pid" 2>/dev/null
done
rm -rf /data/adb/reaper
exit 0
