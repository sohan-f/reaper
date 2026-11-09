set_perm "$MODPATH/bin/reaperd" 0 0 0755
mkdir -p /data/adb/reaper
# Preserve an existing policy across updates.
[ -f /data/adb/reaper/policy.toml ] || cp "$MODPATH/etc/policy.toml" /data/adb/reaper/policy.toml
export MODULE_HOT_INSTALL_REQUEST=true
export MODULE_HOT_RUN_SCRIPT=hotinstall.sh
