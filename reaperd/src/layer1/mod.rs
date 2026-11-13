//! Reversible Layer 1 suppression: receivers, app ops, and standby buckets.
//!
//! Layer 1 mutates device state for denied packages. Every mutation is
//! journaled with the value it replaces, and reconciliation restores the
//! journal when a package stops being denied or a category is disabled.

mod apply;
mod device;
mod journal;
mod parse;
mod restore;

use std::{
    collections::HashSet,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::ensure;
use log::{error, warn};

use crate::{policy::Policy, uidmap::UidMap};

use apply::{apply_instance, apply_standby};
pub use device::{AndroidOps, Ops, ReceiverFilter, standby_bucket_id};
use journal::{Item, Journal};
use restore::{restore_disabled_categories, restore_item, restore_removed};

const ACTIONS: [&str; 4] = [
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
    "android.intent.action.MY_PACKAGE_REPLACED",
];

// Reconcile runs on the epoll loop, and each command can block for its own
// timeout. Without a pass-level bound a stalled system_server multiplies that
// timeout by the number of packages and freezes event handling.
const RECONCILE_BUDGET: Duration = Duration::from_secs(10);

struct Deadline {
    at: Instant,
    announced: bool,
}

impl Deadline {
    fn new() -> Self {
        Self {
            at: Instant::now() + RECONCILE_BUDGET,
            announced: false,
        }
    }

    fn expired(&mut self) -> bool {
        if Instant::now() < self.at {
            return false;
        }
        if !self.announced {
            self.announced = true;
            warn!("Layer 1: reconcile budget exhausted; deferring remaining work");
        }
        true
    }
}

fn is_never_kill(policy: &Policy, builtin: &[String], package: &str) -> bool {
    policy.never_kill.iter().any(|p| p == package) || builtin.iter().any(|p| p == package)
}

pub fn desired_instances(
    policy: &Policy,
    builtin: &[String],
    uid_map: &UidMap,
) -> Vec<(u32, String)> {
    let mut seen = HashSet::new();
    let mut instances = Vec::new();
    for rule in &policy.deny {
        if is_never_kill(policy, builtin, &rule.package) {
            continue;
        }
        for instance in uid_map.instances_of(&rule.package) {
            if seen.insert((instance.user, rule.package.clone())) {
                instances.push((instance.user, rule.package.clone()));
            }
        }
    }
    instances
}

/// Applies and restores Layer 1 state for the current policy.
///
/// `uid_map` is `None` when the package map could not be trusted. In that case
/// reconciliation is skipped: an empty map would look like every package was
/// uninstalled. `apply` is false in observe mode, while disarmed, while the kill
/// budget is tripped, or while a kill-switch marker is present; restore still runs.
pub fn reconcile(
    policy: &Policy,
    builtin: &[String],
    uid_map: Option<&UidMap>,
    ops: &mut dyn Ops,
    journal_path: &Path,
    apply: bool,
) {
    let Some(uid_map) = uid_map else {
        warn!("Layer 1 skipped: package map is unavailable");
        return;
    };
    let mut journal = match Journal::load(journal_path) {
        Ok(journal) => journal,
        Err(err) => {
            error!("Layer 1 disabled: cannot read journal: {err:#}");
            return;
        }
    };

    reconcile_with_deadline(
        policy,
        builtin,
        uid_map,
        &mut journal,
        ops,
        apply,
        &mut Deadline::new(),
    );
}

fn reconcile_with_deadline(
    policy: &Policy,
    builtin: &[String],
    uid_map: &UidMap,
    journal: &mut Journal,
    ops: &mut dyn Ops,
    apply: bool,
    deadline: &mut Deadline,
) {
    let denied: HashSet<&str> = policy
        .deny
        .iter()
        .filter(|rule| !is_never_kill(policy, builtin, &rule.package))
        .map(|rule| rule.package.as_str())
        .collect();

    restore_removed(journal, &denied, uid_map, ops, deadline);
    restore_disabled_categories(journal, policy.layer1.as_ref(), ops, deadline);

    if !apply {
        return;
    }
    let Some(layer1) = policy.layer1.as_ref() else {
        return;
    };
    for (user, package) in desired_instances(policy, builtin, uid_map) {
        if deadline.expired() {
            return;
        }
        apply_instance(layer1, user, &package, journal, ops, deadline);
    }
}

/// Reapplies the enabled Layer 1 categories for one denied package.
pub fn reapply_package(
    policy: &Policy,
    builtin: &[String],
    uid_map: &UidMap,
    ops: &mut dyn Ops,
    journal_path: &Path,
    apply: bool,
    package: &str,
) {
    if !apply {
        return;
    }
    let Some(layer1) = policy.layer1.as_ref() else {
        return;
    };
    if is_never_kill(policy, builtin, package)
        || !policy.deny.iter().any(|rule| rule.package == package)
    {
        return;
    }
    let mut journal = match Journal::load(journal_path) {
        Ok(journal) => journal,
        Err(err) => {
            error!("Layer 1 disabled: cannot read journal: {err:#}");
            return;
        }
    };
    let mut deadline = Deadline::new();
    for instance in uid_map.instances_of(package) {
        if deadline.expired() {
            return;
        }
        apply_instance(
            layer1,
            instance.user,
            package,
            &mut journal,
            ops,
            &mut deadline,
        );
    }
}

/// Reapplies the configured standby bucket for one denied package and user.
///
/// The system re-buckets apps on its own, so a bucket set during reconcile
/// drifts back within seconds. Call this when the app drops to the background,
/// which is the event the bucket is meant to suppress.
pub fn reapply_standby(
    policy: &Policy,
    builtin: &[String],
    ops: &mut dyn Ops,
    journal_path: &Path,
    apply: bool,
    user: u32,
    package: &str,
) {
    if !apply {
        return;
    }
    let Some(bucket) = policy
        .layer1
        .as_ref()
        .and_then(|layer1| layer1.standby_bucket.as_ref())
    else {
        return;
    };
    if is_never_kill(policy, builtin, package)
        || !policy.deny.iter().any(|rule| rule.package == package)
    {
        return;
    }
    let mut journal = match Journal::load(journal_path) {
        Ok(journal) => journal,
        Err(err) => {
            error!("Layer 1 disabled: cannot read journal: {err:#}");
            return;
        }
    };
    apply_standby(
        user,
        package,
        bucket,
        &mut journal,
        ops,
        &mut Deadline::new(),
    );
}

/// Restores every journaled Layer 1 mutation.
///
/// # Errors
///
/// Returns an error if the journal cannot be read or any restore command fails.
/// Failed items stay in the journal so a later run can retry.
pub fn restore_all(journal_path: &Path, ops: &mut dyn Ops) -> anyhow::Result<()> {
    let mut journal = Journal::load(journal_path)?;
    let items: Vec<Item> = journal.items().to_vec();
    let mut failures = 0;
    for item in &items {
        if !restore_item(&mut journal, ops, item) {
            failures += 1;
        }
    }
    ensure!(
        failures == 0,
        "{failures} Layer 1 item(s) could not be restored"
    );
    Ok(())
}

fn save_or_log(journal: &Journal, action: &str) {
    if let Err(err) = journal.save() {
        error!("Layer 1: failed to {action}: {err:#}");
    }
}

#[cfg(test)]
mod tests;
