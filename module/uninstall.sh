#!/system/bin/sh
MODDIR=${0%/*}
for pid in $(pidof reaperd); do
    kill "$pid" 2>/dev/null
done
sleep 1
for pid in $(pidof reaperd); do
    kill -9 "$pid" 2>/dev/null
done
if "$MODDIR/bin/reaperd" --restore-layer1; then
    rm -rf /data/adb/reaper
else
    echo "reaperd: Layer 1 restore failed; keeping /data/adb/reaper/layer1-journal.toml" >&2
    exit 1
fi
exit 0
