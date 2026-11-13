//! Applying the enabled Layer 1 categories to one package instance.

use std::collections::{HashMap, HashSet};

use log::{error, info, warn};

use super::device::ComponentState;
use super::journal::{Item, Kind};
use super::parse::component_key;
use super::{ACTIONS, Pass, ReceiverFilter, standby_bucket_id};
use crate::policy::{AppOpSetting, Layer1Policy};

/// A standby bucket name and the id `am set-standby-bucket` reports for it.
struct StandbySetting<'a> {
    bucket: &'a str,
    id: String,
}

/// Applies every enabled category to one `(user, package)` instance.
pub(super) fn apply_instance(layer1: &Layer1Policy, user: u32, package: &str, pass: &mut Pass<'_>) {
    if layer1.disable_boot_receivers {
        apply_receivers(user, package, pass);
    }
    for setting in &layer1.appops {
        if pass.expired() {
            return;
        }
        apply_appop(user, package, setting, pass);
    }
    if let Some(bucket) = &layer1.standby_bucket {
        apply_standby(user, package, bucket, pass);
    }
}

fn apply_receivers(user: u32, package: &str, pass: &mut Pass<'_>) {
    let prefix = format!("{package}/");
    let (components, queried) = enabled_components(user, package, &prefix, pass);
    if components.is_empty() {
        report_missing_receivers(user, package, &prefix, queried, pass);
        return;
    }
    let states = component_states(user, package, pass);
    for component in &components {
        if pass.expired() {
            return;
        }
        disable_component(user, package, component, states.as_ref(), pass);
    }
}

fn enabled_components(
    user: u32,
    package: &str,
    prefix: &str,
    pass: &mut Pass<'_>,
) -> (Vec<String>, usize) {
    let mut components: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut queried = 0usize;
    for action in ACTIONS {
        if pass.expired() {
            return (components, queried);
        }
        match pass.ops.receivers(user, action, ReceiverFilter::Enabled) {
            Ok(found) => {
                queried += found.len();
                let mine = found.into_iter().filter(|entry| entry.starts_with(prefix));
                components.extend(mine.filter(|entry| seen.insert(entry.clone())));
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
    pass: &mut Pass<'_>,
) {
    let disabled = pass
        .journal
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
        if pass.expired() {
            break;
        }
        match pass
            .ops
            .receivers(user, action, ReceiverFilter::IncludingDisabled)
        {
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
    pass: &mut Pass<'_>,
) -> Option<HashMap<String, ComponentState>> {
    match pass.ops.component_states(user, package) {
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
    component: &str,
    states: Option<&HashMap<String, ComponentState>>,
    pass: &mut Pass<'_>,
) {
    let previous = match states {
        Some(states) => states
            .get(&component_key(component))
            .copied()
            .unwrap_or(ComponentState::Default),
        // The query returns enabled components only, so `enabled` restores
        // the behavior that was replaced even without the exact prior state.
        None => ComponentState::Enabled,
    };
    if previous.is_disabled() {
        return;
    }
    if pass
        .journal
        .find(user, package, Kind::Receiver, component)
        .is_some()
    {
        match pass.ops.disable_component(user, component) {
            Ok(()) => info!("Layer 1: reapplied receiver {component} user {user}"),
            Err(err) => {
                warn!("Layer 1: reapply receiver {component} user {user} failed: {err:#}");
            }
        }
        return;
    }
    let item = Item::new(user, package, Kind::Receiver, component, previous.as_str());
    pass.journal.append(item);
    if let Err(err) = pass.journal.save() {
        pass.journal
            .remove(user, package, Kind::Receiver, component);
        error!("Layer 1: cannot journal receiver {component}; not mutating: {err:#}");
        return;
    }
    match pass.ops.disable_component(user, component) {
        Ok(()) => info!("Layer 1: disabled receiver {component} user {user}"),
        Err(err) => {
            error!("Layer 1: disable receiver {component} user {user} failed: {err:#}");
            pass.journal
                .remove(user, package, Kind::Receiver, component);
            pass.save_or_log("drop receiver after failed apply");
        }
    }
}

fn apply_appop(user: u32, package: &str, setting: &AppOpSetting, pass: &mut Pass<'_>) {
    let current = match pass.ops.appop(user, package, &setting.op) {
        Ok(current) => current,
        Err(err) => {
            warn!(
                "Layer 1: appop query {} for {package} user {user} failed: {err:#}",
                setting.op
            );
            return;
        }
    };
    if pass
        .journal
        .find(user, package, Kind::Appop, &setting.op)
        .is_some()
    {
        reapply_appop(user, package, setting, &current, pass);
        return;
    }
    if current == setting.mode {
        return;
    }
    journal_and_set_appop(user, package, setting, &current, pass);
}

fn reapply_appop(
    user: u32,
    package: &str,
    setting: &AppOpSetting,
    current: &str,
    pass: &mut Pass<'_>,
) {
    if current == setting.mode {
        return;
    }
    match pass
        .ops
        .set_appop(user, package, &setting.op, &setting.mode)
    {
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
    pass: &mut Pass<'_>,
) {
    let item = Item::new(user, package, Kind::Appop, &setting.op, current);
    pass.journal.append(item);
    if let Err(err) = pass.journal.save() {
        pass.journal.remove(user, package, Kind::Appop, &setting.op);
        error!(
            "Layer 1: cannot journal appop {} for {package}; not mutating: {err:#}",
            setting.op
        );
        return;
    }
    match pass
        .ops
        .set_appop(user, package, &setting.op, &setting.mode)
    {
        Ok(()) => info!(
            "Layer 1: appop {} set to {} for {package} user {user}",
            setting.op, setting.mode
        ),
        Err(err) => {
            error!(
                "Layer 1: set appop {} for {package} user {user} failed: {err:#}",
                setting.op
            );
            pass.journal.remove(user, package, Kind::Appop, &setting.op);
            pass.save_or_log("drop appop after failed apply");
        }
    }
}

/// Applies the configured standby bucket to one `(user, package)` instance.
pub(super) fn apply_standby(user: u32, package: &str, bucket: &str, pass: &mut Pass<'_>) {
    if pass.expired() {
        return;
    }
    let Some(id) = standby_bucket_id(bucket) else {
        error!("Layer 1: unknown standby bucket {bucket:?}");
        return;
    };
    let current = match pass.ops.standby_bucket(user, package) {
        Ok(current) => current,
        Err(err) => {
            warn!("Layer 1: standby query for {package} user {user} failed: {err:#}");
            return;
        }
    };
    let setting = StandbySetting {
        bucket,
        id: id.to_string(),
    };
    if pass
        .journal
        .find(user, package, Kind::Standby, "bucket")
        .is_some()
    {
        reapply_standby(user, package, &setting, &current, pass);
        return;
    }
    if current == setting.id {
        return;
    }
    journal_and_set_standby(user, package, &setting, &current, pass);
}

fn reapply_standby(
    user: u32,
    package: &str,
    setting: &StandbySetting<'_>,
    current: &str,
    pass: &mut Pass<'_>,
) {
    if current == setting.id {
        return;
    }
    match pass.ops.set_standby_bucket(user, package, setting.bucket) {
        Ok(()) => info!("Layer 1: reapplied standby for {package} user {user}"),
        Err(err) => {
            warn!("Layer 1: reapply standby for {package} user {user} failed: {err:#}");
        }
    }
}

fn journal_and_set_standby(
    user: u32,
    package: &str,
    setting: &StandbySetting<'_>,
    current: &str,
    pass: &mut Pass<'_>,
) {
    let item = Item::new(user, package, Kind::Standby, "bucket", current);
    pass.journal.append(item);
    if let Err(err) = pass.journal.save() {
        pass.journal.remove(user, package, Kind::Standby, "bucket");
        error!("Layer 1: cannot journal standby for {package}; not mutating: {err:#}");
        return;
    }
    match pass.ops.set_standby_bucket(user, package, setting.bucket) {
        Ok(()) => info!(
            "Layer 1: standby bucket set to {} for {package} user {user}",
            setting.bucket
        ),
        Err(err) => {
            error!("Layer 1: set standby for {package} user {user} failed: {err:#}");
            pass.journal.remove(user, package, Kind::Standby, "bucket");
            pass.save_or_log("drop standby after failed apply");
        }
    }
}
