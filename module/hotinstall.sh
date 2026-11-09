#!/system/bin/sh
MODDIR=${0%/*}
pid=$(pidof reaperd)
[ -n "$pid" ] && kill "$pid"
sleep 1
nohup "$MODDIR/bin/reaperd" >/dev/null 2>&1 &
exit 0
