//! Policy resolution, Layer 1 reconciliation, and enforcement state.

mod stops;

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::Context;
use log::{error, info, warn};

use crate::{
    config::Config,
    deny::{
        DenyEntry, DenyMapMut, build_deny, install_deny_map, refresh_never_kill, watched_users,
    },
    enforce::{KillBudget, RespawnGuard},
    layer1, never_kill,
    paths::{ARMED_FILE, BUDGET_FILE, LAYER1_JOURNAL, PACKAGES_LIST},
    pending::Pending,
    policy::{Mode, Policy},
    uidmap::UidMap,
};

use stops::stop_reason;

/// State shared by the boot code and the event loop.
#[allow(
    clippy::struct_excessive_bools,
    reason = "flags mirror independent device markers and load outcomes"
)]
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
            &layer1::Plan::new(
                &self.policy,
                &self.builtin_never_kill,
                layer1_apply_allowed(self),
            ),
            uid_map,
            &mut ops,
            Path::new(LAYER1_JOURNAL),
        );
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
