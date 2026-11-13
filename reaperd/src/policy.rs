//! Policy file parsing and validation.

use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde::Deserialize;

/// First appid Android assigns to installed apps.
pub const APPID_START: u32 = 10_000;
/// Last appid Android assigns to installed apps.
pub const APPID_END: u32 = 19_999;
/// Upper bound on the effective grace, including backoff.
pub const MAX_GRACE_MS: u64 = 300_000;
const DEFAULT_GRACE_MS: u64 = 2_000;
const DEFAULT_KEEP_ADJ: i16 = 100;

/// Whether decisions are only logged or actually enforced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Log what would happen and never mutate the device.
    Observe,
    /// Force-stop denied apps once the decision survives the grace period.
    Enforce,
}

/// One `[[deny]]` entry, with the global defaults already applied.
#[derive(Clone, Debug)]
pub struct DenyRule {
    /// Package name the rule targets.
    pub package: String,
    /// Grace period between nomination and the decision.
    pub grace_ms: u64,
    /// Nominate only above this `oom_score_adj`.
    pub keep_adj: i16,
}

/// One `OP:MODE` entry from `[layer1] appops`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppOpSetting {
    /// App-op name, validated against the supported list at parse time.
    pub op: String,
    /// Mode to set the op to.
    pub mode: String,
}

/// The `[layer1]` table: device mutations that are reversed when denied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layer1Policy {
    /// Disable boot receivers of denied packages.
    pub disable_boot_receivers: bool,
    /// App ops to set for denied packages.
    pub appops: Vec<AppOpSetting>,
    /// Standby bucket to pin denied packages to.
    pub standby_bucket: Option<String>,
}

/// The effective policy: `[global]` defaults plus every `[[deny]]` rule.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Whether decisions are enforced.
    pub mode: Mode,
    /// Default grace period for rules that do not set their own.
    pub grace_ms: u64,
    /// Default `keep_adj` for rules that do not set their own.
    pub keep_adj: i16,
    /// Force-stops allowed per minute before switching to observe.
    pub kill_budget_per_min: u32,
    /// Window the respawn guard counts kills in.
    pub respawn_window_s: u64,
    /// Kills of one uid inside the window before it backs off.
    pub respawn_max: u32,
    /// Packages that must never be nominated.
    pub never_kill: Vec<String>,
    /// Denied packages, in file order.
    pub deny: Vec<DenyRule>,
    /// Reversible device mutations, absent when `[layer1]` is missing.
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
    /// Reads and parses the policy file at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or fails validation.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&text)
    }

    /// Parses a policy document and applies the global defaults to each rule.
    ///
    /// # Errors
    ///
    /// Returns an error on unknown keys, out-of-range values, or an app-op that
    /// this build does not support.
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
