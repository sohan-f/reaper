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

/// What one pass should do: the policy, the built-in safety list, and whether
/// mutating the device is allowed.
#[derive(Clone, Copy)]
pub struct Plan<'a> {
    policy: &'a Policy,
    builtin: &'a [String],
    apply: bool,
}

impl<'a> Plan<'a> {
    /// Bundles the inputs that decide what Layer 1 suppresses.
    pub fn new(policy: &'a Policy, builtin: &'a [String], apply: bool) -> Self {
        Self {
            policy,
            builtin,
            apply,
        }
    }

    fn is_never_kill(&self, package: &str) -> bool {
        self.policy.never_kill.iter().any(|p| p == package)
            || self.builtin.iter().any(|p| p == package)
    }

    fn denied(&self) -> HashSet<&'a str> {
        self.policy
            .deny
            .iter()
            .filter(|rule| !self.is_never_kill(&rule.package))
            .map(|rule| rule.package.as_str())
            .collect()
    }

    fn denies(&self, package: &str) -> bool {
        !self.is_never_kill(package) && self.policy.deny.iter().any(|rule| rule.package == package)
    }
}

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

/// State shared by one pass: the journal, the device commands, and the budget.
pub(super) struct Pass<'a> {
    journal: Journal,
    ops: &'a mut dyn Ops,
    deadline: Deadline,
}

impl<'a> Pass<'a> {
    fn load(ops: &'a mut dyn Ops, journal_path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            journal: Journal::load(journal_path)?,
            ops,
            deadline: Deadline::new(),
        })
    }

    fn expired(&mut self) -> bool {
        self.deadline.expired()
    }

    fn save_or_log(&self, action: &str) {
        if let Err(err) = self.journal.save() {
            error!("Layer 1: failed to {action}: {err:#}");
        }
    }
}

fn load_pass<'a>(ops: &'a mut dyn Ops, journal_path: &Path) -> Option<Pass<'a>> {
    match Pass::load(ops, journal_path) {
        Ok(pass) => Some(pass),
        Err(err) => {
            error!("Layer 1 disabled: cannot read journal: {err:#}");
            None
        }
    }
}

/// The `(user, package)` pairs the current policy denies.
pub fn desired_instances(plan: &Plan<'_>, uid_map: &UidMap) -> Vec<(u32, String)> {
    let mut seen = HashSet::new();
    let mut instances = Vec::new();
    for rule in &plan.policy.deny {
        if plan.is_never_kill(&rule.package) {
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
/// uninstalled. The plan's `apply` flag is false in observe mode, while
/// disarmed, while the kill budget is tripped, or while a kill-switch marker is
/// present; restore still runs.
pub fn reconcile(
    plan: &Plan<'_>,
    uid_map: Option<&UidMap>,
    ops: &mut dyn Ops,
    journal_path: &Path,
) {
    let Some(uid_map) = uid_map else {
        warn!("Layer 1 skipped: package map is unavailable");
        return;
    };
    let Some(mut pass) = load_pass(ops, journal_path) else {
        return;
    };
    run(plan, uid_map, &mut pass);
}

fn run(plan: &Plan<'_>, uid_map: &UidMap, pass: &mut Pass<'_>) {
    let denied = plan.denied();
    restore_removed(&denied, uid_map, pass);
    restore_disabled_categories(plan.policy.layer1.as_ref(), pass);

    if !plan.apply {
        return;
    }
    let Some(layer1) = plan.policy.layer1.as_ref() else {
        return;
    };
    for (user, package) in desired_instances(plan, uid_map) {
        if pass.expired() {
            return;
        }
        apply_instance(layer1, user, &package, pass);
    }
}

/// Reapplies the enabled Layer 1 categories for one denied package.
pub fn reapply_package(
    plan: &Plan<'_>,
    uid_map: &UidMap,
    ops: &mut dyn Ops,
    journal_path: &Path,
    package: &str,
) {
    if !plan.apply || !plan.denies(package) {
        return;
    }
    let Some(layer1) = plan.policy.layer1.as_ref() else {
        return;
    };
    let Some(mut pass) = load_pass(ops, journal_path) else {
        return;
    };
    for instance in uid_map.instances_of(package) {
        if pass.expired() {
            return;
        }
        apply_instance(layer1, instance.user, package, &mut pass);
    }
}

/// Reapplies the configured standby bucket for one denied package and user.
///
/// The system re-buckets apps on its own, so a bucket set during reconcile
/// drifts back within seconds. Call this when the app drops to the background,
/// which is the event the bucket is meant to suppress.
pub fn reapply_standby(
    plan: &Plan<'_>,
    ops: &mut dyn Ops,
    journal_path: &Path,
    user: u32,
    package: &str,
) {
    if !plan.apply || !plan.denies(package) {
        return;
    }
    let Some(bucket) = plan
        .policy
        .layer1
        .as_ref()
        .and_then(|layer1| layer1.standby_bucket.as_deref())
    else {
        return;
    };
    let Some(mut pass) = load_pass(ops, journal_path) else {
        return;
    };
    apply_standby(user, package, bucket, &mut pass);
}

/// Restores every journaled Layer 1 mutation.
///
/// # Errors
///
/// Returns an error if the journal cannot be read or any restore command fails.
/// Failed items stay in the journal so a later run can retry.
pub fn restore_all(journal_path: &Path, ops: &mut dyn Ops) -> anyhow::Result<()> {
    let mut pass = Pass::load(ops, journal_path)?;
    let items: Vec<Item> = pass.journal.items().to_vec();
    let mut failures = 0;
    for item in &items {
        if !restore_item(item, &mut pass) {
            failures += 1;
        }
    }
    ensure!(
        failures == 0,
        "{failures} Layer 1 item(s) could not be restored"
    );
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::assert_is_empty,
    reason = "assert! is clearer than comparing with an empty collection"
)]
mod tests;
