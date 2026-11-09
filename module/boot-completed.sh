#!/system/bin/sh
# Start reaperd after Android's bpfloader has finished: bpfloader aborts and
# reboots the device if a BPF object is loaded before its load-bpf-programs
# action.
MODDIR=${0%/*}
mkdir -p /data/adb/reaper
: > /data/adb/reaper/armed
nohup "$MODDIR/bin/reaperd" >/dev/null 2>&1 &
exit 0
