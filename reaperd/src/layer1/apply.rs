//! Applying the enabled Layer 1 categories to one package instance.

use std::collections::{HashMap, HashSet};

use log::{error, info, warn};

use super::device::{self, ComponentState};
use super::journal::{Item, Journal, Kind};
use super::{ACTIONS, Deadline, Ops, ReceiverFilter, save_or_log, standby_bucket_id};
use crate::policy::{AppOpSetting, Layer1Policy};

pub(super) fn apply_instance(
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
    let (components, queried) = enabled_components(user, package, &prefix, ops, deadline);
    if components.is_empty() {
        report_missing_receivers(user, package, &prefix, queried, journal, ops, deadline);
        return;
    }
    let states = component_states(user, package, ops);
    for component in components {
        if deadline.expired() {
            return;
        }
        disable_component(user, package, component, states.as_ref(), journal, ops);
    }
}

fn enabled_components(
    user: u32,
    package: &str,
    prefix: &str,
    ops: &mut dyn Ops,
    deadline: &mut Deadline,
) -> (Vec<String>, usize) {
    let mut components: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut queried = 0usize;
    for action in ACTIONS {
        if deadline.expired() {
            return (components, queried);
        }
        match ops.receivers(user, action, ReceiverFilter::Enabled) {
            Ok(found) => {
                queried += found.len();
                for component in found {
                    if component.starts_with(prefix) && seen.insert(component.clone()) {
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
    (components, queried)
}

fn report_missing_receivers(
    user: u32,
    package: &str,
    prefix: &str,
    queried: usize,
    journal: &Journal,
    ops: &mut dyn Ops,
    deadline: &mut Deadline,
) {
    let disabled = journal
        .items()
        .iter()
        .filter(|item| item.user == user && item.package == package && item.kind == Kind::Receiver)
        .count();
    if disabled > 0 {
        info!("Layer 1: {disabled} boot receiver(s) for {package} user {user} already disabled");
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
                    .filter(|component| component.starts_with(prefix)),
            ),
            Err(err) => {
                warn!(
                    "Layer 1: disabled receiver query for {package} user {user} action {action} failed: {err:#}"
                );
            }
        }
    }
    if hidden.is_empty() {
        info!("Layer 1: no boot receivers for {package} user {user}; queries returned {queried}");
    } else {
        info!(
            "Layer 1: {} boot receiver(s) for {package} user {user} already disabled, not journaled",
            hidden.len()
        );
    }
}

fn component_states(
    user: u32,
    package: &str,
    ops: &mut dyn Ops,
) -> Option<HashMap<String, ComponentState>> {
    match ops.component_states(user, package) {
        Ok(states) => Some(states),
        Err(err) => {
            warn!(
                "Layer 1: component state query for {package} user {user} failed: {err:#}; assuming enabled"
            );
            None
        }
    }
}

fn disable_component(
    user: u32,
    package: &str,
    component: String,
    states: Option<&HashMap<String, ComponentState>>,
    journal: &mut Journal,
    ops: &mut dyn Ops,
) {
    let previous = match states {
        Some(states) => states
            .get(&device::component_key(&component))
            .copied()
            .unwrap_or(ComponentState::Default),
        // The query returns enabled components only, so `enabled` restores
        // the behavior that was replaced even without the exact prior state.
        None => ComponentState::Enabled,
    };
    if previous.is_disabled() {
        return;
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
        return;
    }
    let item = Item::new(user, package, Kind::Receiver, &component, previous.as_str());
    journal.append(item);
    if let Err(err) = journal.save() {
        journal.remove(user, package, Kind::Receiver, &component);
        error!("Layer 1: cannot journal receiver {component}; not mutating: {err:#}");
        return;
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

fn apply_appop(
    user: u32,
    package: &str,
    setting: &AppOpSetting,
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
        reapply_appop(user, package, setting, &current, ops);
        return;
    }
    if current == setting.mode {
        return;
    }
    journal_and_set_appop(user, package, setting, &current, journal, ops);
}

fn reapply_appop(
    user: u32,
    package: &str,
    setting: &AppOpSetting,
    current: &str,
    ops: &mut dyn Ops,
) {
    if current == setting.mode {
        return;
    }
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

fn journal_and_set_appop(
    user: u32,
    package: &str,
    setting: &AppOpSetting,
    current: &str,
    journal: &mut Journal,
    ops: &mut dyn Ops,
) {
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

pub(super) fn apply_standby(
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
    let expected = expected.to_string();
    if journal
        .find(user, package, Kind::Standby, "bucket")
        .is_some()
    {
        reapply_standby(user, package, bucket, &current, &expected, ops);
        return;
    }
    if current == expected {
        return;
    }
    journal_and_set_standby(user, package, bucket, &current, journal, ops);
}

fn reapply_standby(
    user: u32,
    package: &str,
    bucket: &str,
    current: &str,
    expected: &str,
    ops: &mut dyn Ops,
) {
    if current == expected {
        return;
    }
    match ops.set_standby_bucket(user, package, bucket) {
        Ok(()) => info!("Layer 1: reapplied standby for {package} user {user}"),
        Err(err) => {
            warn!("Layer 1: reapply standby for {package} user {user} failed: {err:#}");
        }
    }
}

fn journal_and_set_standby(
    user: u32,
    package: &str,
    bucket: &str,
    current: &str,
    journal: &mut Journal,
    ops: &mut dyn Ops,
) {
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
