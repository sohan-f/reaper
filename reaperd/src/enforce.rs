//! Enforcement state: kill budget, respawn backoff, and force-stop.

use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    process::Command,
    time::Duration,
};

use anyhow::{Context, ensure};

use crate::{command, policy::MAX_GRACE_MS};

const BUDGET_WINDOW_NS: u64 = 60_000_000_000;
const MAX_BACKOFF_SHIFT: u32 = 5;
const CMD_PATH: &str = "/system/bin/cmd";
const FORCE_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Sliding-window limit on force-stops across all apps.
pub struct KillBudget {
    limit: u32,
    kills: VecDeque<u64>,
    tripped: bool,
}

impl KillBudget {
    /// Creates a budget that denies every kill when `tripped` is set.
    pub fn new(limit: u32, tripped: bool) -> Self {
        Self {
            limit,
            kills: VecDeque::new(),
            tripped,
        }
    }

    /// Reports whether the budget has tripped.
    pub fn tripped(&self) -> bool {
        self.tripped
    }

    /// Replaces the per-window kill limit.
    pub fn set_limit(&mut self, limit: u32) {
        self.limit = limit;
    }

    /// Reports whether another kill fits in the window.
    pub fn allow_kill(&mut self, now_ns: u64) -> bool {
        if self.tripped {
            return false;
        }
        while let Some(&first) = self.kills.front() {
            if now_ns.saturating_sub(first) < BUDGET_WINDOW_NS {
                break;
            }
            self.kills.pop_front();
        }
        if self.kills.len() as u32 >= self.limit {
            self.tripped = true;
            return false;
        }
        true
    }

    /// Records a kill at `now_ns`.
    pub fn record_kill(&mut self, now_ns: u64) {
        self.kills.push_back(now_ns);
    }
}

/// Per-uid kill history and exponential grace backoff.
pub struct RespawnGuard {
    window_ns: u64,
    max: u32,
    kills: HashMap<u32, VecDeque<u64>>,
    backoff: HashMap<u32, Backoff>,
}

struct Backoff {
    level: u32,
    until_ns: u64,
}

impl RespawnGuard {
    /// Creates a guard with a `window_s` window and a `max` kill limit.
    pub fn new(window_s: u64, max: u32) -> Self {
        Self {
            window_ns: window_s.saturating_mul(1_000_000_000),
            max,
            kills: HashMap::new(),
            backoff: HashMap::new(),
        }
    }

    /// Replaces the window and kill limit.
    pub fn set_limits(&mut self, window_s: u64, max: u32) {
        self.window_ns = window_s.saturating_mul(1_000_000_000);
        self.max = max;
    }

    /// Records a kill for `uid` at `now_ns`.
    pub fn record_kill(&mut self, uid: u32, now_ns: u64) {
        self.kills.entry(uid).or_default().push_back(now_ns);
    }

    /// Reports whether `uid` has reached the kill limit in the window.
    pub fn tripped(&mut self, uid: u32, now_ns: u64) -> bool {
        let Some(kills) = self.kills.get_mut(&uid) else {
            return false;
        };
        while let Some(&first) = kills.front() {
            if now_ns.saturating_sub(first) < self.window_ns {
                break;
            }
            kills.pop_front();
        }
        kills.len() as u32 >= self.max
    }

    /// Raises the uid's backoff level for one more window.
    pub fn back_off(&mut self, uid: u32, now_ns: u64) {
        let backoff = self.backoff.entry(uid).or_insert(Backoff {
            level: 0,
            until_ns: 0,
        });
        backoff.level = backoff.level.saturating_add(1).min(MAX_BACKOFF_SHIFT);
        backoff.until_ns = now_ns.saturating_add(self.window_ns);
    }

    /// Returns `grace_ms` scaled by the uid's active backoff.
    pub fn effective_grace(&self, uid: u32, grace_ms: u64, now_ns: u64) -> u64 {
        let level = self
            .backoff
            .get(&uid)
            .filter(|backoff| now_ns < backoff.until_ns)
            .map(|backoff| backoff.level)
            .unwrap_or(0);
        grace_ms.saturating_mul(1u64 << level).min(MAX_GRACE_MS)
    }
}

/// Force-stops `package` for `user` by running Android's `cmd`.
///
/// # Errors
///
/// Returns an error if the command cannot be spawned, does not exit within
/// the timeout, or exits with a non-zero status.
pub fn force_stop(user: u32, package: &str) -> anyhow::Result<()> {
    run_force_stop(Path::new(CMD_PATH), user, package)
}

fn run_force_stop(cmd: &Path, user: u32, package: &str) -> anyhow::Result<()> {
    let mut process = Command::new(cmd);
    process
        .arg("activity")
        .arg("force-stop")
        .arg("--user")
        .arg(user.to_string())
        .arg(package);
    let output = command::output(&mut process, FORCE_STOP_TIMEOUT)
        .with_context(|| format!("failed to run {}", cmd.display()))?;
    ensure!(
        output.status.success(),
        "force-stop {package} exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_trips_after_limit() {
        let mut budget = KillBudget::new(2, false);
        assert!(budget.allow_kill(1_000));
        budget.record_kill(1_000);
        assert!(budget.allow_kill(2_000));
        budget.record_kill(2_000);
        assert!(!budget.allow_kill(3_000));
        assert!(budget.tripped());
        assert!(!budget.allow_kill(90_000_000_000));
    }

    #[test]
    fn budget_forgets_old_kills() {
        let mut budget = KillBudget::new(1, false);
        budget.record_kill(1_000);
        assert!(budget.allow_kill(BUDGET_WINDOW_NS + 2_000));
        assert!(!budget.tripped());
    }

    #[test]
    fn budget_honors_existing_marker() {
        let mut budget = KillBudget::new(20, true);
        assert!(!budget.allow_kill(1_000));
    }

    #[test]
    fn respawn_trips_after_max_kills() {
        let mut guard = RespawnGuard::new(60, 2);
        guard.record_kill(10293, 1_000);
        assert!(!guard.tripped(10293, 2_000));
        guard.record_kill(10293, 2_000);
        assert!(guard.tripped(10293, 3_000));
        assert!(!guard.tripped(10293, 61_000_000_000));
    }

    #[test]
    fn respawn_backoff_grows_and_expires() {
        let mut guard = RespawnGuard::new(60, 2);
        assert_eq!(guard.effective_grace(10293, 2_000, 1_000), 2_000);
        guard.back_off(10293, 1_000);
        assert_eq!(guard.effective_grace(10293, 2_000, 2_000), 4_000);
        guard.back_off(10293, 2_000);
        assert_eq!(guard.effective_grace(10293, 2_000, 3_000), 8_000);
        assert_eq!(guard.effective_grace(10293, 2_000, 61_000_000_000), 2_000);
    }

    #[test]
    fn respawn_grace_is_capped() {
        let mut guard = RespawnGuard::new(60, 1);
        for now in 0..6 {
            guard.back_off(10293, now);
        }
        assert_eq!(guard.effective_grace(10293, 60_000, 1_000), MAX_GRACE_MS);
    }

    #[test]
    fn force_stop_reports_exit_status() {
        run_force_stop(Path::new("/bin/true"), 0, "com.example").expect("true must succeed");
        assert!(run_force_stop(Path::new("/bin/false"), 0, "com.example").is_err());
    }
}
