//! Filesystem paths shared by the boot, daemon, and event-loop code.

/// Android's package-to-uid table.
pub const PACKAGES_LIST: &str = "/data/system/packages.list";
/// Directory holding the policy file and the marker files below.
pub const REAPER_DIR: &str = "/data/adb/reaper";
/// Present when the daemon may enforce.
pub const ARMED_FILE: &str = "/data/adb/reaper/armed";
/// Present to stop enforcement without losing state.
pub const DISABLE_FILE: &str = "/data/adb/reaper/disable";
/// Present to stop enforcement after a kernel-side fault.
pub const PANIC_FILE: &str = "/data/adb/reaper/panic";
/// Written when the kill budget trips; keeps the daemon in observe mode.
pub const BUDGET_FILE: &str = "/data/adb/reaper/budget-exceeded";
/// Journal of the Layer 1 changes that still need restoring.
pub const LAYER1_JOURNAL: &str = "/data/adb/reaper/layer1-journal.toml";
