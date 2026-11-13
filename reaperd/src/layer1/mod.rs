//! Reversible Layer 1 suppression: receivers, app ops, and standby buckets.
//!
//! Layer 1 mutates device state for denied packages. Every mutation is
//! journaled with the value it replaces, and reconciliation restores the
//! journal when a package stops being denied or a category is disabled.

mod device;
mod journal;

use std::{
    collections::HashSet,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::ensure;
use log::{error, info, warn};

use crate::{
    policy::{Layer1Policy, Policy},
    uidmap::UidMap,
};

pub use device::{AndroidOps, Ops, ReceiverFilter, standby_bucket_id};
use device::{ComponentState, RestoreOutcome};
use journal::{Item, Journal, Kind};

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

fn restore_removed(
    journal: &mut Journal,
    denied: &HashSet<&str>,
    uid_map: &UidMap,
    ops: &mut dyn Ops,
    deadline: &mut Deadline,
) {
    let packages: HashSet<String> = journal
        .items()
        .iter()
        .map(|item| item.package.clone())
        .collect();
    for package in packages {
        let instances = uid_map.instances_of(&package);
        let is_denied = denied.contains(package.as_str());
        if instances.is_empty() {
            if !is_denied {
                let removed = journal.remove_package(&package);
                if removed > 0 {
                    save_or_log(journal, "drop items for absent package");
                    info!("Layer 1: dropped {removed} item(s) for absent package {package}");
                }
            }
            continue;
        }
        let users: HashSet<u32> = instances.iter().map(|instance| instance.user).collect();
        let stale: Vec<Item> = journal
            .items()
            .iter()
            .filter(|item| item.package == package && (!is_denied || !users.contains(&item.user)))
            .cloned()
            .collect();
        for item in stale {
            if deadline.expired() {
                return;
            }
            restore_item(journal, ops, &item);
        }
    }
}

fn restore_disabled_categories(
    journal: &mut Journal,
    layer1: Option<&Layer1Policy>,
    ops: &mut dyn Ops,
    deadline: &mut Deadline,
) {
    let stale: Vec<Item> = journal
        .items()
        .iter()
        .filter(|item| match item.kind {
            Kind::Receiver => layer1.is_none_or(|cfg| !cfg.disable_boot_receivers),
            Kind::Appop => {
                layer1.is_none_or(|cfg| !cfg.appops.iter().any(|setting| setting.op == item.key))
            }
            Kind::Standby => layer1.is_none_or(|cfg| cfg.standby_bucket.is_none()),
        })
        .cloned()
        .collect();
    for item in stale {
        if deadline.expired() {
            return;
        }
        restore_item(journal, ops, &item);
    }
}

fn apply_instance(
    layer1: &Layer1Policy,
    user: u32,
    package: &str,
    journal: &mut Journal,
    ops: &mut dyn Ops,
    deadline: &mut Deadline,
) {
    if layer1.disable_boot_receivers {
        apply_receivers(user, package, journal, ops, deadline);
    }
    for setting in &layer1.appops {
        if deadline.expired() {
            return;
        }
        apply_appop(user, package, setting, journal, ops);
    }
    if let Some(bucket) = &layer1.standby_bucket {
        apply_standby(user, package, bucket, journal, ops, deadline);
    }
}

fn apply_receivers(
    user: u32,
    package: &str,
    journal: &mut Journal,
    ops: &mut dyn Ops,
    deadline: &mut Deadline,
) {
    let prefix = format!("{package}/");
    let mut components: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut queried = 0usize;
    for action in ACTIONS {
        if deadline.expired() {
            return;
        }
        match ops.receivers(user, action, ReceiverFilter::Enabled) {
            Ok(found) => {
                queried += found.len();
                for component in found {
                    if component.starts_with(&prefix) && seen.insert(component.clone()) {
                        components.push(component);
                    }
                }
            }
            Err(err) => {
                warn!(
                    "Layer 1: receiver query for {package} user {user} action {action} failed: {err:#}"
                );
            }
        }
    }
    if components.is_empty() {
        let disabled = journal
            .items()
            .iter()
            .filter(|item| {
                item.user == user && item.package == package && item.kind == Kind::Receiver
            })
            .count();
        if disabled > 0 {
            info!(
                "Layer 1: {disabled} boot receiver(s) for {package} user {user} already disabled"
            );
            return;
        }
        let mut hidden = HashSet::new();
        for action in ACTIONS {
            if deadline.expired() {
                break;
            }
            match ops.receivers(user, action, ReceiverFilter::IncludingDisabled) {
                Ok(found) => hidden.extend(
                    found
                        .into_iter()
                        .filter(|component| component.starts_with(&prefix)),
                ),
                Err(err) => {
                    warn!(
                        "Layer 1: disabled receiver query for {package} user {user} action {action} failed: {err:#}"
                    );
                }
            }
        }
        if hidden.is_empty() {
            info!(
                "Layer 1: no boot receivers for {package} user {user}; queries returned {queried}"
            );
        } else {
            info!(
                "Layer 1: {} boot receiver(s) for {package} user {user} already disabled, not journaled",
                hidden.len()
            );
        }
        return;
    }
    let states = match ops.component_states(user, package) {
        Ok(states) => Some(states),
        Err(err) => {
            warn!(
                "Layer 1: component state query for {package} user {user} failed: {err:#}; assuming enabled"
            );
            None
        }
    };
    for component in components {
        if deadline.expired() {
            return;
        }
        let previous = match &states {
            Some(states) => states
                .get(&device::component_key(&component))
                .copied()
                .unwrap_or(ComponentState::Default),
            // The query returns enabled components only, so `enabled` restores
            // the behavior that was replaced even without the exact prior state.
            None => ComponentState::Enabled,
        };
        if previous.is_disabled() {
            continue;
        }
        if journal
            .find(user, package, Kind::Receiver, &component)
            .is_some()
        {
            match ops.disable_component(user, &component) {
                Ok(()) => info!("Layer 1: reapplied receiver {component} user {user}"),
                Err(err) => {
                    warn!("Layer 1: reapply receiver {component} user {user} failed: {err:#}");
                }
            }
            continue;
        }
        let item = Item::new(user, package, Kind::Receiver, &component, previous.as_str());
        journal.append(item);
        if let Err(err) = journal.save() {
            journal.remove(user, package, Kind::Receiver, &component);
            error!("Layer 1: cannot journal receiver {component}; not mutating: {err:#}");
            continue;
        }
        match ops.disable_component(user, &component) {
            Ok(()) => info!("Layer 1: disabled receiver {component} user {user}"),
            Err(err) => {
                error!("Layer 1: disable receiver {component} user {user} failed: {err:#}");
                journal.remove(user, package, Kind::Receiver, &component);
                save_or_log(journal, "drop receiver after failed apply");
            }
        }
    }
}

fn apply_appop(
    user: u32,
    package: &str,
    setting: &crate::policy::AppOpSetting,
    journal: &mut Journal,
    ops: &mut dyn Ops,
) {
    let current = match ops.appop(user, package, &setting.op) {
        Ok(current) => current,
        Err(err) => {
            warn!(
                "Layer 1: appop query {} for {package} user {user} failed: {err:#}",
                setting.op
            );
            return;
        }
    };
    if journal
        .find(user, package, Kind::Appop, &setting.op)
        .is_some()
    {
        if current != setting.mode {
            match ops.set_appop(user, package, &setting.op, &setting.mode) {
                Ok(()) => info!(
                    "Layer 1: reapplied appop {} for {package} user {user}",
                    setting.op
                ),
                Err(err) => {
                    warn!(
                        "Layer 1: reapply appop {} for {package} user {user} failed: {err:#}",
                        setting.op
                    );
                }
            }
        }
        return;
    }
    if current == setting.mode {
        return;
    }
    let item = Item::new(user, package, Kind::Appop, &setting.op, current);
    journal.append(item);
    if let Err(err) = journal.save() {
        journal.remove(user, package, Kind::Appop, &setting.op);
        error!(
            "Layer 1: cannot journal appop {} for {package}; not mutating: {err:#}",
            setting.op
        );
        return;
    }
    match ops.set_appop(user, package, &setting.op, &setting.mode) {
        Ok(()) => info!(
            "Layer 1: appop {} set to {} for {package} user {user}",
            setting.op, setting.mode
        ),
        Err(err) => {
            error!(
                "Layer 1: set appop {} for {package} user {user} failed: {err:#}",
                setting.op
            );
            journal.remove(user, package, Kind::Appop, &setting.op);
            save_or_log(journal, "drop appop after failed apply");
        }
    }
}

fn apply_standby(
    user: u32,
    package: &str,
    bucket: &str,
    journal: &mut Journal,
    ops: &mut dyn Ops,
    deadline: &mut Deadline,
) {
    if deadline.expired() {
        return;
    }
    let Some(expected) = standby_bucket_id(bucket) else {
        error!("Layer 1: unknown standby bucket {bucket:?}");
        return;
    };
    let current = match ops.standby_bucket(user, package) {
        Ok(current) => current,
        Err(err) => {
            warn!("Layer 1: standby query for {package} user {user} failed: {err:#}");
            return;
        }
    };
    if journal
        .find(user, package, Kind::Standby, "bucket")
        .is_some()
    {
        if current != expected.to_string() {
            match ops.set_standby_bucket(user, package, bucket) {
                Ok(()) => info!("Layer 1: reapplied standby for {package} user {user}"),
                Err(err) => {
                    warn!("Layer 1: reapply standby for {package} user {user} failed: {err:#}");
                }
            }
        }
        return;
    }
    if current == expected.to_string() {
        return;
    }
    let item = Item::new(user, package, Kind::Standby, "bucket", current);
    journal.append(item);
    if let Err(err) = journal.save() {
        journal.remove(user, package, Kind::Standby, "bucket");
        error!("Layer 1: cannot journal standby for {package}; not mutating: {err:#}");
        return;
    }
    match ops.set_standby_bucket(user, package, bucket) {
        Ok(()) => info!("Layer 1: standby bucket set to {bucket} for {package} user {user}"),
        Err(err) => {
            error!("Layer 1: set standby for {package} user {user} failed: {err:#}");
            journal.remove(user, package, Kind::Standby, "bucket");
            save_or_log(journal, "drop standby after failed apply");
        }
    }
}

fn restore_item(journal: &mut Journal, ops: &mut dyn Ops, item: &Item) -> bool {
    let result = match item.kind {
        Kind::Receiver => {
            let Some(state) = ComponentState::parse(&item.previous) else {
                error!(
                    "Layer 1: journal has invalid receiver state {:?} for {}",
                    item.previous, item.key
                );
                return false;
            };
            ops.restore_component(item.user, &item.key, state)
        }
        Kind::Appop => ops
            .set_appop(item.user, &item.package, &item.key, &item.previous)
            .map(|()| RestoreOutcome::Restored),
        Kind::Standby => ops
            .set_standby_bucket(item.user, &item.package, &item.previous)
            .map(|()| RestoreOutcome::Restored),
    };
    match result {
        Ok(outcome) => {
            if outcome == RestoreOutcome::UnknownComponent {
                info!(
                    "Layer 1: dropping receiver {} for {} user {}: component no longer exists",
                    item.key, item.package, item.user
                );
            } else if item.kind == Kind::Standby {
                match ops.standby_bucket(item.user, &item.package) {
                    Ok(observed) => info!(
                        "Layer 1: restored standby for {} user {}; observed bucket {observed}",
                        item.package, item.user
                    ),
                    Err(err) => warn!(
                        "Layer 1: restored standby for {} user {}; readback failed: {err:#}",
                        item.package, item.user
                    ),
                }
            } else {
                info!(
                    "Layer 1: restored {} {} for {} user {}",
                    kind_name(item.kind),
                    item.key,
                    item.package,
                    item.user
                );
            }
            journal.remove(item.user, &item.package, item.kind, &item.key);
            save_or_log(journal, "drop restored item");
            true
        }
        Err(err) => {
            error!(
                "Layer 1: restore {} {} for {} user {} failed: {err:#}; keeping journal item",
                kind_name(item.kind),
                item.key,
                item.package,
                item.user
            );
            false
        }
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Receiver => "receiver",
        Kind::Appop => "appop",
        Kind::Standby => "standby",
    }
}

fn save_or_log(journal: &Journal, action: &str) {
    if let Err(err) = journal.save() {
        error!("Layer 1: failed to {action}: {err:#}");
    }
}

#[cfg(test)]
mod tests;
