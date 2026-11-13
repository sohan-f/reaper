//! The enforcement path: queueing nominations, deciding, and force-stopping.

use std::path::Path;

use log::{error, info, warn};

use crate::{
    decide::{self, Decision},
    deny::{DenyEntry, deny_params, never_kill_package},
    enforce, layer1,
    paths::{BUDGET_FILE, DISABLE_FILE, LAYER1_JOURNAL, PANIC_FILE},
    policy::Mode,
    sys,
};

use super::{Daemon, layer1_apply_allowed, owner_uid};

/// One denied app and the process that decided about it.
#[derive(Clone, Copy)]
struct StopTarget {
    user: u32,
    appid: u32,
    owner_uid: u32,
    min_adj: i16,
}

impl Daemon {
    /// Finds every backgrounded denied uid and queues it for a decision.
    pub fn sweep(&mut self) {
        let mut inserted = 0u32;
        let Ok(uid_dirs) = std::fs::read_dir("/sys/fs/cgroup/apps") else {
            warn!("sweep: /sys/fs/cgroup/apps unreadable");
            return;
        };
        let uid_dirs: Vec<u32> = uid_dirs
            .flatten()
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.strip_prefix("uid_"))?
                    .parse::<u32>()
                    .ok()
            })
            .collect();
        let entries = self.deny.clone();
        for entry in entries {
            inserted += self.queue_swept_uids(&uid_dirs, entry);
        }
        info!("sweep done: {inserted} pending");
    }

    fn queue_swept_uids(&mut self, uid_dirs: &[u32], entry: DenyEntry) -> u32 {
        let mut inserted = 0u32;
        for &uid in uid_dirs {
            if uid % 100_000 == entry.appid && self.queue_swept(uid, &entry) {
                inserted += 1;
            }
        }
        inserted
    }

    fn queue_swept(&mut self, uid: u32, entry: &DenyEntry) -> bool {
        let adj_values = decide::adj_values_of_uid(uid);
        let Decision::Background { min_adj } = decide::decide(&adj_values, entry.keep_adj) else {
            return false;
        };
        let now = sys::boottime_ns();
        let grace_ms = self.respawn.effective_grace(uid, entry.grace_ms, now);
        let deadline = now.saturating_add(grace_ms.saturating_mul(1_000_000));
        let inserted = self.pending.insert(uid / 100_000, entry.appid, deadline);
        info!("sweep: uid {uid} backgrounded (min adj {min_adj}); pending");
        inserted
    }

    /// Re-checks a pending (user, appid) and enforces when it is backgrounded.
    pub fn decide_and_log(&mut self, user: u32, appid: u32) {
        let Some(owner_uid) = owner_uid(user, appid) else {
            warn!("invalid (user={user}, appid={appid}); dropping");
            return;
        };
        if let Some(package) = never_kill_package(
            &self.policy,
            &self.builtin_never_kill,
            self.uid_map.packages_of(appid),
        ) {
            info!("not enforcing user {user} appid {appid}: {package} is in never_kill");
            return;
        }
        let Some((grace_ms, keep_adj)) = deny_params(&self.deny, appid) else {
            info!("dropping pending user {user} appid {appid}: no longer denied");
            return;
        };
        if !self.armed {
            info!(
                "pending expired for user {user} appid {appid} but daemon is not armed; dropping"
            );
            return;
        }
        if let Some(reason) = stop_reason() {
            info!("not enforcing user {user} appid {appid}: {reason}");
            return;
        }

        let adj_values = decide::adj_values_of_uid(owner_uid);
        match decide::decide(&adj_values, keep_adj) {
            Decision::Gone => {
                info!("uid {owner_uid}: no live processes; app already gone");
            }
            Decision::Keep { min_adj } => {
                info!("uid {owner_uid}: keep (foreground/visible, min adj {min_adj})");
            }
            Decision::Background { min_adj } => {
                self.stop_background(
                    StopTarget {
                        user,
                        appid,
                        owner_uid,
                        min_adj,
                    },
                    grace_ms,
                );
            }
        }
    }

    fn stop_background(&mut self, target: StopTarget, grace_ms: u64) {
        let now = sys::boottime_ns();
        if layer1_apply_allowed(self) {
            let mut ops = layer1::AndroidOps;
            let plan = layer1::Plan::new(&self.policy, &self.builtin_never_kill, true);
            for package in self.uid_map.packages_of(target.appid) {
                layer1::reapply_standby(
                    &plan,
                    &mut ops,
                    Path::new(LAYER1_JOURNAL),
                    target.user,
                    package,
                );
            }
        }
        if self.policy.mode == Mode::Observe || self.budget.tripped() {
            self.log_would_stop(target);
            return;
        }
        let packages: Vec<String> = self.uid_map.packages_of(target.appid).to_vec();
        if packages.is_empty() {
            warn!(
                "uid {}: backgrounded but no package name; cannot force-stop",
                target.owner_uid
            );
            return;
        }
        if !self.budget.allow_kill(now) {
            self.trip_budget();
            return;
        }
        if self.respawn.tripped(target.owner_uid, now) {
            self.back_off(target, grace_ms, now, &packages);
        }
        if Self::stop_packages(target, &packages) {
            self.stops += 1;
            self.budget.record_kill(now);
            self.respawn.record_kill(target.owner_uid, now);
        }
    }

    fn log_would_stop(&mut self, target: StopTarget) {
        let packages: Vec<&str> = self
            .uid_map
            .packages_of(target.appid)
            .iter()
            .map(String::as_str)
            .collect();
        let mode = if self.budget.tripped() {
            "observe (kill budget tripped)"
        } else {
            "observe"
        };
        info!(
            "{mode}: would force-stop user {} uid {} appid {} min_adj {} packages [{}]",
            target.user,
            target.owner_uid,
            target.appid,
            target.min_adj,
            packages.join(",")
        );
        self.would_stop += 1;
    }

    fn back_off(&mut self, target: StopTarget, grace_ms: u64, now: u64, packages: &[String]) {
        self.respawn.back_off(target.owner_uid, now);
        let backoff_grace = self
            .respawn
            .effective_grace(target.owner_uid, grace_ms, now);
        warn!(
            "respawn guard: uid {} hit {} kills in {} s; backing off to {backoff_grace} ms grace",
            target.owner_uid, self.policy.respawn_max, self.policy.respawn_window_s
        );
        if !layer1_apply_allowed(self) {
            return;
        }
        let mut ops = layer1::AndroidOps;
        let plan = layer1::Plan::new(&self.policy, &self.builtin_never_kill, true);
        for package in packages {
            layer1::reapply_package(
                &plan,
                &self.uid_map,
                &mut ops,
                Path::new(LAYER1_JOURNAL),
                package,
            );
        }
    }

    fn stop_packages(target: StopTarget, packages: &[String]) -> bool {
        let mut stopped = false;
        for package in packages {
            if let Some(reason) = stop_reason() {
                info!("stopping force-stop loop: {reason}");
                break;
            }
            match enforce::force_stop(target.user, package) {
                Ok(()) => {
                    info!(
                        "force-stopped user {} uid {} appid {} package {package}",
                        target.user, target.owner_uid, target.appid
                    );
                    stopped = true;
                }
                Err(err) => {
                    error!(
                        "force-stop user {} package {package} failed: {err:#}",
                        target.user
                    );
                }
            }
        }
        stopped
    }

    fn trip_budget(&mut self) {
        if self.budget_reported {
            return;
        }
        if let Err(err) = std::fs::write(BUDGET_FILE, b"kill budget exceeded\n") {
            error!("failed to write {BUDGET_FILE}: {err}");
            return;
        }
        self.budget_reported = true;
        error!("kill budget exceeded; switching to observe mode; marker {BUDGET_FILE}");
    }
}

/// Returns why enforcement is suspended, when a marker says so.
pub(super) fn stop_reason() -> Option<&'static str> {
    if Path::new(DISABLE_FILE).exists() {
        Some("kill-switch marker present")
    } else if Path::new(PANIC_FILE).exists() {
        Some("panic marker present")
    } else {
        None
    }
}
