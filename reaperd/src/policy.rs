//! Policy file parsing and validation.

use std::path::Path;

use anyhow::{Context, bail, ensure};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppOpSetting {
    pub op: String,
    pub mode: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layer1Policy {
    pub disable_boot_receivers: bool,
    pub appops: Vec<AppOpSetting>,
    pub standby_bucket: Option<String>,
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
    pub layer1: Option<Layer1Policy>,
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
            layer1: None,
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
struct RawLayer1 {
    disable_boot_receivers: Option<bool>,
    appops: Option<Vec<String>>,
    standby_bucket: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    global: Option<RawGlobal>,
    layer1: Option<RawLayer1>,
    never_kill: Option<RawNeverKill>,
    deny: Option<Vec<RawDeny>>,
}

const APPOP_MODES: [&str; 4] = ["allow", "ignore", "deny", "default"];
// Only the ops verified on the target build; an unknown name must fail at parse
// time instead of on every reconcile.
const APPOP_NAMES: [&str; 2] = ["RUN_ANY_IN_BACKGROUND", "RUN_IN_BACKGROUND"];

fn parse_layer1(raw: RawLayer1) -> anyhow::Result<Layer1Policy> {
    let mut layer1 = Layer1Policy {
        disable_boot_receivers: raw.disable_boot_receivers.unwrap_or(false),
        ..Layer1Policy::default()
    };
    for entry in raw.appops.unwrap_or_default() {
        let (op, mode) = entry
            .split_once(':')
            .with_context(|| format!("appop {entry:?} is not OP:MODE"))?;
        ensure!(
            APPOP_NAMES.contains(&op),
            "unknown appop {op:?} in {entry:?}"
        );
        ensure!(
            APPOP_MODES.contains(&mode),
            "unknown appop mode {mode:?} in {entry:?}"
        );
        ensure!(
            !layer1.appops.iter().any(|setting| setting.op == op),
            "duplicate appop {op:?}"
        );
        layer1.appops.push(AppOpSetting {
            op: op.to_string(),
            mode: mode.to_string(),
        });
    }
    if let Some(bucket) = raw.standby_bucket {
        ensure!(
            crate::layer1::standby_bucket_id(&bucket).is_some(),
            "unknown standby_bucket {bucket:?}"
        );
        layer1.standby_bucket = Some(bucket);
    }
    Ok(layer1)
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
            apply_global(&mut policy, global)?;
        }
        if let Some(layer1) = raw.layer1 {
            policy.layer1 = Some(parse_layer1(layer1)?);
        }
        policy.never_kill = parse_never_kill(raw.never_kill)?;
        policy.deny = parse_deny(raw.deny, &policy)?;
        Ok(policy)
    }
}

fn apply_global(policy: &mut Policy, global: RawGlobal) -> anyhow::Result<()> {
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
    Ok(())
}

fn parse_never_kill(raw: Option<RawNeverKill>) -> anyhow::Result<Vec<String>> {
    let mut packages = Vec::new();
    for package in raw
        .and_then(|never_kill| never_kill.packages)
        .unwrap_or_default()
    {
        ensure!(
            !package.is_empty(),
            "policy contains an empty never_kill package name"
        );
        packages.push(package);
    }
    Ok(packages)
}

fn parse_deny(raw: Option<Vec<RawDeny>>, policy: &Policy) -> anyhow::Result<Vec<DenyRule>> {
    let mut rules = Vec::new();
    for entry in raw.unwrap_or_default() {
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
        rules.push(DenyRule {
            package: entry.package,
            grace_ms,
            keep_adj,
        });
    }
    Ok(rules)
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
#[allow(
    clippy::assert_is_empty,
    reason = "assert! is clearer than comparing with an empty collection"
)]
mod tests;
