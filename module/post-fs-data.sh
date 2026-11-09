#!/system/bin/sh
MODDIR=${0%/*}
# Deliberately fire and forget; never block post-fs-data.
nohup "$MODDIR/bin/reaperd" >/dev/null 2>&1 &
exit 0
