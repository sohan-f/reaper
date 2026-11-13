//! Policy resolution, Layer 1 reconciliation, and enforcement state.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::Context;
use log::{error, info, warn};

use crate::{
    config::Config,
    decide::{self, Decision},
    deny::{
        DenyEntry, DenyMapMut, build_deny, deny_params, install_deny_map, never_kill_package,
        refresh_never_kill, watched_users,
    },
    enforce,
    enforce::{KillBudget, RespawnGuard},
    layer1, never_kill,
    paths::{ARMED_FILE, BUDGET_FILE, DISABLE_FILE, LAYER1_JOURNAL, PACKAGES_LIST, PANIC_FILE},
    pending::Pending,
    policy::{Mode, Policy},
    sys,
    uidmap::UidMap,
};

/// State shared by the boot code and the event loop.
pub struct Daemon {
    /// Nominations waiting for their deadline.
    pub pending: Pending,
    /// Policy currently in force.
    pub policy: Policy,
    /// Policy file reloaded on SIGHUP and on write.
    pub policy_path: PathBuf,
    /// Extra deny entries from the command line.
    pub deny_overrides: Vec<(u32, i16)>,
    /// Package table used to resolve appids.
    pub uid_map: UidMap,
    /// Deny entries installed in the eBPF map.
    pub deny: Vec<DenyEntry>,
    /// Packages that must never be killed on this device.
    pub builtin_never_kill: Vec<String>,
    /// Users whose safety packages have already been resolved.
    pub never_kill_users: Vec<u32>,
    /// Sliding-window kill budget.
    pub budget: KillBudget,
    /// Respawn guard per uid.
    pub respawn: RespawnGuard,
    /// Set once the budget marker is written.
    pub budget_reported: bool,
    /// Set while the armed marker exists.
    pub armed: bool,
    /// Set when the policy loaded at boot.
    pub policy_ready: bool,
    /// Set when the package table loaded at boot.
    pub uid_map_ready: bool,
    /// Nominations seen since start.
    pub nominations: u64,
    /// Force-stops logged instead of performed.
    pub would_stop: u64,
    /// Force-stops performed since start.
    pub stops: u64,
}

impl Daemon {
    /// Builds the daemon state and fills the DENY map from the policy.
    ///
    /// A missing or invalid policy or package table is reported and leaves the
    /// daemon in observe mode rather than aborting the boot.
    ///
    /// # Errors
    ///
    /// Returns an error only if the DENY map cannot be updated.
    pub fn load(cfg: &Config, deny_map: &mut DenyMapMut<'_>) -> anyhow::Result<Self> {
        let (policy, policy_ready) = load_policy(&cfg.policy);
        log_layer1_config(&policy);
        let (uid_map, uid_map_ready) = load_uid_map();
        let users = watched_users(&uid_map);
        let builtin_never_kill = never_kill::resolve(&users);
        let deny = build_deny(&policy, &builtin_never_kill, &uid_map, &cfg.deny_overrides);
        install_deny_map(deny_map, &deny)?;
        info!("populated DENY map with {} entries", deny.len());

        let armed = Path::new(ARMED_FILE).exists();
        let budget_tripped = Path::new(BUDGET_FILE).exists();
        if budget_tripped {
            warn!("{BUDGET_FILE} present; staying in observe mode");
        }
        let budget = KillBudget::new(policy.kill_budget_per_min, budget_tripped);
        let respawn = RespawnGuard::new(policy.respawn_window_s, policy.respawn_max);
        Ok(Self {
            pending: Pending::default(),
            policy,
            policy_path: cfg.policy.clone(),
            deny_overrides: cfg.deny_overrides.clone(),
            uid_map,
            deny,
            builtin_never_kill,
            never_kill_users: users,
            budget,
            respawn,
            budget_reported: budget_tripped,
            armed,
            policy_ready,
            uid_map_ready,
            nominations: 0,
            would_stop: 0,
            stops: 0,
        })
    }

    /// Applies the Layer 1 policy once, if the policy is loaded.
    pub fn reconcile_layer1(&self) {
        if !self.policy_ready {
            warn!("Layer 1 skipped: policy is not loaded");
            return;
        }
        let uid_map = if self.uid_map_ready && !self.uid_map.is_empty() {
            Some(&self.uid_map)
        } else {
            None
        };
        let mut ops = layer1::AndroidOps;
        layer1::reconcile(
            &self.policy,
            &self.builtin_never_kill,
            uid_map,
            &mut ops,
            Path::new(LAYER1_JOURNAL),
            layer1_apply_allowed(self),
        );
    }

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
        for entry in &self.deny {
            for &uid in &uid_dirs {
                if uid % 100_000 != entry.appid {
                    continue;
                }
                let user = uid / 100_000;
                let adj_values = decide::adj_values_of_uid(uid);
                if let Decision::Background { min_adj } =
                    decide::decide(&adj_values, entry.keep_adj)
                {
                    let now = sys::boottime_ns();
                    let grace_ms = self.respawn.effective_grace(uid, entry.grace_ms, now);
                    let deadline = now.saturating_add(grace_ms.saturating_mul(1_000_000));
                    if self.pending.insert(user, entry.appid, deadline) {
                        inserted += 1;
                    }
                    info!("sweep: uid {uid} backgrounded (min adj {min_adj}); pending");
                }
            }
        }
        info!("sweep done: {inserted} pending");
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
                self.stop_background(user, appid, owner_uid, min_adj, grace_ms);
            }
        }
    }

    fn stop_background(
        &mut self,
        user: u32,
        appid: u32,
        owner_uid: u32,
        min_adj: i16,
        grace_ms: u64,
    ) {
        let now = sys::boottime_ns();
        if layer1_apply_allowed(self) {
            let mut ops = layer1::AndroidOps;
            for package in self.uid_map.packages_of(appid) {
                layer1::reapply_standby(
                    &self.policy,
                    &self.builtin_never_kill,
                    &mut ops,
                    Path::new(LAYER1_JOURNAL),
                    true,
                    user,
                    package,
                );
            }
        }
        if self.policy.mode == Mode::Observe || self.budget.tripped() {
            self.log_would_stop(user, appid, owner_uid, min_adj);
            return;
        }
        let packages: Vec<String> = self.uid_map.packages_of(appid).to_vec();
        if packages.is_empty() {
            warn!("uid {owner_uid}: backgrounded but no package name; cannot force-stop");
            return;
        }
        if !self.budget.allow_kill(now) {
            self.trip_budget();
            return;
        }
        if self.respawn.tripped(owner_uid, now) {
            self.back_off(owner_uid, grace_ms, now, &packages);
        }
        if self.stop_packages(user, owner_uid, appid, &packages) {
            self.stops += 1;
            self.budget.record_kill(now);
            self.respawn.record_kill(owner_uid, now);
        }
    }

    fn log_would_stop(&mut self, user: u32, appid: u32, owner_uid: u32, min_adj: i16) {
        let packages: Vec<&str> = self
            .uid_map
            .packages_of(appid)
            .iter()
            .map(String::as_str)
            .collect();
        let mode = if self.budget.tripped() {
            "observe (kill budget tripped)"
        } else {
            "observe"
        };
        info!(
            "{mode}: would force-stop user {user} uid {owner_uid} appid {appid} min_adj {min_adj} packages [{}]",
            packages.join(",")
        );
        self.would_stop += 1;
    }

    fn back_off(&mut self, owner_uid: u32, grace_ms: u64, now: u64, packages: &[String]) {
        self.respawn.back_off(owner_uid, now);
        let backoff_grace = self.respawn.effective_grace(owner_uid, grace_ms, now);
        warn!(
            "respawn guard: uid {owner_uid} hit {} kills in {} s; backing off to {backoff_grace} ms grace",
            self.policy.respawn_max, self.policy.respawn_window_s
        );
        if !layer1_apply_allowed(self) {
            return;
        }
        let mut ops = layer1::AndroidOps;
        for package in packages {
            layer1::reapply_package(
                &self.policy,
                &self.builtin_never_kill,
                &self.uid_map,
                &mut ops,
                Path::new(LAYER1_JOURNAL),
                true,
                package,
            );
        }
    }

    fn stop_packages(&self, user: u32, owner_uid: u32, appid: u32, packages: &[String]) -> bool {
        let mut stopped = false;
        for package in packages {
            if let Some(reason) = stop_reason() {
                info!("stopping force-stop loop: {reason}");
                break;
            }
            match enforce::force_stop(user, package) {
                Ok(()) => {
                    info!(
                        "force-stopped user {user} uid {owner_uid} appid {appid} package {package}"
                    );
                    stopped = true;
                }
                Err(err) => {
                    error!("force-stop user {user} package {package} failed: {err:#}");
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

    /// Reloads the policy, the package table, and the DENY map.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy file cannot be read or parsed. The
    /// running policy is kept in that case.
    pub fn reload_policy(&mut self, deny_map: &mut DenyMapMut<'_>) -> anyhow::Result<()> {
        let policy = Policy::load(&self.policy_path).context("failed to reload policy")?;
        self.budget.set_limit(policy.kill_budget_per_min);
        self.respawn
            .set_limits(policy.respawn_window_s, policy.respawn_max);
        self.policy = policy;
        self.policy_ready = true;
        log_layer1_config(&self.policy);
        match UidMap::load(Path::new(PACKAGES_LIST)) {
            Ok(map) => {
                self.uid_map = map;
                self.uid_map_ready = true;
            }
            Err(err) => {
                warn!("uid map rebuild failed on policy reload: {err:#}");
                self.uid_map = UidMap::empty();
                self.uid_map_ready = false;
            }
        }
        self.rebuild_deny(deny_map);
        info!("policy reloaded: {} deny entries", self.deny.len());
        self.reconcile_layer1();
        Ok(())
    }

    /// Rebuilds the deny list from the current policy and package table.
    pub fn rebuild_deny(&mut self, deny_map: &mut DenyMapMut<'_>) {
        let users = watched_users(&self.uid_map);
        refresh_never_kill(
            &mut self.builtin_never_kill,
            &mut self.never_kill_users,
            &users,
        );
        self.deny = build_deny(
            &self.policy,
            &self.builtin_never_kill,
            &self.uid_map,
            &self.deny_overrides,
        );
        let appids: HashSet<u32> = self.deny.iter().map(|entry| entry.appid).collect();
        self.pending.retain_appids(&appids);
        if let Err(err) = install_deny_map(deny_map, &self.deny) {
            error!("failed to update DENY map: {err:#}");
        }
    }
}

fn owner_uid(user: u32, appid: u32) -> Option<u32> {
    user.checked_mul(100_000)?.checked_add(appid)
}

fn load_policy(path: &Path) -> (Policy, bool) {
    match Policy::load(path) {
        Ok(policy) => (policy, true),
        Err(err) => {
            error!(
                "failed to load {}: {err:#}; continuing with observe defaults",
                path.display()
            );
            (Policy::default(), false)
        }
    }
}

fn load_uid_map() -> (UidMap, bool) {
    match UidMap::load(Path::new(PACKAGES_LIST)) {
        Ok(map) => (map, true),
        Err(err) => {
            warn!("failed to build uid map: {err:#}");
            (UidMap::empty(), false)
        }
    }
}

fn stop_reason() -> Option<&'static str> {
    if Path::new(DISABLE_FILE).exists() {
        Some("kill-switch marker present")
    } else if Path::new(PANIC_FILE).exists() {
        Some("panic marker present")
    } else {
        None
    }
}

fn layer1_apply_allowed(daemon: &Daemon) -> bool {
    daemon.armed
        && daemon.policy.mode == Mode::Enforce
        && !daemon.budget.tripped()
        && stop_reason().is_none()
}

fn log_layer1_config(policy: &Policy) {
    match policy.layer1.as_ref() {
        Some(layer1) => info!(
            "Layer 1 config: receivers={} appops={} standby={}",
            layer1.disable_boot_receivers,
            layer1.appops.len(),
            layer1.standby_bucket.as_deref().unwrap_or("none")
        ),
        None => info!("Layer 1 config: none"),
    }
}
