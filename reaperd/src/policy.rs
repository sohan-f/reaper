//! Policy file parsing and validation.

use std::path::Path;

use anyhow::{Context, bail, ensure};
use log::warn;
use serde::Deserialize;

pub const APPID_START: u32 = 10_000;
pub const APPID_END: u32 = 19_999;
/// Upper bound on the effective grace, including backoff.
pub const MAX_GRACE_MS: u64 = 300_000;
const DEFAULT_GRACE_MS: u64 = 2_000;
const DEFAULT_KEEP_ADJ: i16 = 100;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Observe,
    Enforce,
}

#[derive(Clone, Debug)]
pub struct DenyRule {
    pub package: String,
    pub grace_ms: u64,
    pub keep_adj: i16,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub mode: Mode,
    pub grace_ms: u64,
    pub keep_adj: i16,
    pub kill_budget_per_min: u32,
    pub respawn_window_s: u64,
    pub respawn_max: u32,
    pub never_kill: Vec<String>,
    pub deny: Vec<DenyRule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            grace_ms: DEFAULT_GRACE_MS,
            keep_adj: DEFAULT_KEEP_ADJ,
            kill_budget_per_min: 20,
            respawn_window_s: 60,
            respawn_max: 3,
            never_kill: Vec::new(),
            deny: Vec::new(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGlobal {
    mode: Option<String>,
    grace_ms: Option<u64>,
    keep_adj: Option<i16>,
    kill_budget_per_min: Option<u32>,
    respawn_window_s: Option<u64>,
    respawn_max: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeny {
    package: String,
    grace_ms: Option<u64>,
    keep_adj: Option<i16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNeverKill {
    packages: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    global: Option<RawGlobal>,
    layer1: Option<toml::Value>,
    never_kill: Option<RawNeverKill>,
    deny: Option<Vec<RawDeny>>,
}

fn valid_appid(uid: u32) -> bool {
    let appid = uid % 100_000;
    (APPID_START..=APPID_END).contains(&appid)
}

impl Policy {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let raw: RawPolicy = toml::from_str(text).context("failed to parse policy TOML")?;

        let mut policy = Policy::default();
        if let Some(global) = raw.global {
            if let Some(mode) = global.mode {
                policy.mode = match mode.as_str() {
                    "observe" => Mode::Observe,
                    "enforce" => Mode::Enforce,
                    other => bail!("unknown mode {other:?} (expected observe or enforce)"),
                };
            }
            if let Some(v) = global.grace_ms {
                ensure!(v <= MAX_GRACE_MS, "grace_ms {v} exceeds {MAX_GRACE_MS}");
                policy.grace_ms = v;
            }
            if let Some(v) = global.keep_adj {
                ensure!((-1000..=1000).contains(&v), "keep_adj {v} out of range");
                policy.keep_adj = v;
            }
            if let Some(v) = global.kill_budget_per_min {
                policy.kill_budget_per_min = v;
            }
            if let Some(v) = global.respawn_window_s {
                policy.respawn_window_s = v;
            }
            if let Some(v) = global.respawn_max {
                policy.respawn_max = v;
            }
        }

        if raw.layer1.is_some() {
            warn!("policy [layer1] settings are not applied");
        }

        for package in raw
            .never_kill
            .and_then(|never_kill| never_kill.packages)
            .unwrap_or_default()
        {
            ensure!(
                !package.is_empty(),
                "policy contains an empty never_kill package name"
            );
            policy.never_kill.push(package);
        }

        for entry in raw.deny.unwrap_or_default() {
            ensure!(
                !entry.package.is_empty(),
                "policy contains an empty package name"
            );
            let keep_adj = entry.keep_adj.unwrap_or(policy.keep_adj);
            ensure!(
                (-1000..=1000).contains(&keep_adj),
                "keep_adj for {} out of range",
                entry.package
            );
            let grace_ms = entry.grace_ms.unwrap_or(policy.grace_ms);
            ensure!(
                grace_ms <= MAX_GRACE_MS,
                "grace_ms for {} exceeds {MAX_GRACE_MS}",
                entry.package
            );
            policy.deny.push(DenyRule {
                package: entry.package,
                grace_ms,
                keep_adj,
            });
        }
        Ok(policy)
    }
}

/// Returns the appid for a uid, or None if it is not a normal app uid.
pub fn appid_of(uid: u32) -> Option<u32> {
    if valid_appid(uid) {
        Some(uid % 100_000)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_example() {
        let text = r#"
[global]
mode = "observe"
grace_ms = 2000
keep_adj = 100
kill_budget_per_min = 20
respawn_window_s = 60
respawn_max = 3

[layer1]
disable_boot_receivers = true
appops = ["RUN_ANY_IN_BACKGROUND:ignore", "RUN_IN_BACKGROUND:ignore"]
standby_bucket = "restricted"

[never_kill]
packages = ["android", "com.android.systemui"]

[[deny]]
package = "com.facebook.katana"

[[deny]]
package = "com.instagram.android"
grace_ms = 30000
keep_adj = 200
"#;
        let policy = Policy::parse(text).expect("spec example must parse");
        assert_eq!(policy.mode, Mode::Observe);
        assert_eq!(policy.grace_ms, 2000);
        assert_eq!(policy.keep_adj, 100);
        assert_eq!(policy.deny.len(), 2);
        assert_eq!(policy.never_kill, ["android", "com.android.systemui"]);
        assert_eq!(policy.deny[1].grace_ms, 30000);
        assert_eq!(policy.deny[1].keep_adj, 200);
        assert_eq!(policy.deny[0].grace_ms, 2000);
        assert_eq!(policy.deny[0].keep_adj, 100);
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let text = "[global]\nmode = \"observe\"\n\n[neverkill]\npackages = [\"android\"]\n";
        assert!(Policy::parse(text).is_err());
    }

    #[test]
    fn rejects_unknown_never_kill_key() {
        let text = "[never_kill]\npackage = [\"android\"]\n";
        assert!(Policy::parse(text).is_err());
    }

    #[test]
    fn rejects_bad_mode() {
        let text = "[global]\nmode = \"maybe\"\n";
        assert!(Policy::parse(text).is_err());
    }

    #[test]
    fn rejects_keep_adj_out_of_range() {
        let text = "[global]\nkeep_adj = 1001\n";
        assert!(Policy::parse(text).is_err());
    }

    #[test]
    fn rejects_grace_above_cap() {
        let text = format!("[global]\ngrace_ms = {}\n", MAX_GRACE_MS + 1);
        assert!(Policy::parse(&text).is_err());
    }

    #[test]
    fn rejects_per_app_grace_above_cap() {
        let text = format!(
            "[[deny]]\npackage = \"com.example\"\ngrace_ms = {}\n",
            MAX_GRACE_MS + 1
        );
        assert!(Policy::parse(&text).is_err());
    }
}
