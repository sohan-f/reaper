//! Restoring journaled Layer 1 state.

use std::collections::HashSet;

use log::{error, info, warn};

use super::device::{ComponentState, RestoreOutcome};
use super::journal::{Item, Journal, Kind};
use super::{Deadline, Ops, save_or_log};
use crate::policy::Layer1Policy;
use crate::uidmap::UidMap;

pub(super) fn restore_removed(
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

pub(super) fn restore_disabled_categories(
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

pub(super) fn restore_item(journal: &mut Journal, ops: &mut dyn Ops, item: &Item) -> bool {
    let Some(result) = restore_one(ops, item) else {
        return false;
    };
    match result {
        Ok(outcome) => {
            report_restored(ops, item, outcome);
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

fn restore_one(ops: &mut dyn Ops, item: &Item) -> Option<anyhow::Result<RestoreOutcome>> {
    match item.kind {
        Kind::Receiver => {
            let Some(state) = ComponentState::parse(&item.previous) else {
                error!(
                    "Layer 1: journal has invalid receiver state {:?} for {}",
                    item.previous, item.key
                );
                return None;
            };
            Some(ops.restore_component(item.user, &item.key, state))
        }
        Kind::Appop => Some(
            ops.set_appop(item.user, &item.package, &item.key, &item.previous)
                .map(|()| RestoreOutcome::Restored),
        ),
        Kind::Standby => Some(
            ops.set_standby_bucket(item.user, &item.package, &item.previous)
                .map(|()| RestoreOutcome::Restored),
        ),
    }
}

fn report_restored(ops: &mut dyn Ops, item: &Item, outcome: RestoreOutcome) {
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
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Receiver => "receiver",
        Kind::Appop => "appop",
        Kind::Standby => "standby",
    }
}
