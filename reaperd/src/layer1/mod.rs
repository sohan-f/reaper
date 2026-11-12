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

pub use device::{AndroidOps, Ops, standby_bucket_id};
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
    for action in ACTIONS {
        if deadline.expired() {
            return;
        }
        match ops.receivers(user, action) {
            Ok(found) => {
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
        info!("Layer 1: no boot receivers for {package} user {user}");
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
        Kind::Receiver => match ComponentState::parse(&item.previous) {
            Some(state) => ops.restore_component(item.user, &item.key, state),
            None => {
                error!(
                    "Layer 1: journal has invalid receiver state {:?} for {}",
                    item.previous, item.key
                );
                return false;
            }
        },
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
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use crate::policy::{AppOpSetting, DenyRule};

    #[derive(Default)]
    struct FakeOps {
        receivers: HashMap<(u32, String), Vec<String>>,
        states: HashMap<(u32, String), ComponentState>,
        appops: HashMap<(u32, String, String), String>,
        buckets: HashMap<(u32, String), String>,
        calls: Vec<String>,
        fail_appop_query: HashSet<(u32, String, String)>,
        fail_state_query: HashSet<(u32, String)>,
        fail_apply: HashSet<String>,
        fail_restore: HashSet<String>,
        missing_components: HashSet<(u32, String)>,
    }

    impl FakeOps {
        fn call(&mut self, call: String) {
            self.calls.push(call);
        }

        fn state(&self, user: u32, component: &str) -> ComponentState {
            self.states
                .get(&(user, component.to_string()))
                .copied()
                .unwrap_or(ComponentState::Default)
        }

        fn set_state(&mut self, user: u32, component: &str, state: ComponentState) {
            self.states.insert((user, component.to_string()), state);
        }

        fn appop_mode(&self, user: u32, package: &str, op: &str) -> String {
            self.appops
                .get(&(user, package.to_string(), op.to_string()))
                .cloned()
                .unwrap_or_else(|| "default".to_string())
        }

        fn bucket(&self, user: u32, package: &str) -> String {
            self.buckets
                .get(&(user, package.to_string()))
                .cloned()
                .unwrap_or_else(|| "10".to_string())
        }

        fn has_call(&self, needle: &str) -> bool {
            self.calls.iter().any(|call| call.contains(needle))
        }
    }

    impl Ops for FakeOps {
        fn receivers(&mut self, user: u32, action: &str) -> anyhow::Result<Vec<String>> {
            Ok(self
                .receivers
                .get(&(user, action.to_string()))
                .cloned()
                .unwrap_or_default())
        }

        fn component_states(
            &mut self,
            user: u32,
            package: &str,
        ) -> anyhow::Result<HashMap<String, ComponentState>> {
            if self.fail_state_query.contains(&(user, package.to_string())) {
                anyhow::bail!("query failed");
            }
            let prefix = format!("{package}/");
            Ok(self
                .states
                .iter()
                .filter(|((u, component), _)| *u == user && component.starts_with(&prefix))
                .map(|((_, component), state)| (device::component_key(component), *state))
                .collect())
        }

        fn appop(&mut self, user: u32, package: &str, op: &str) -> anyhow::Result<String> {
            if self
                .fail_appop_query
                .contains(&(user, package.to_string(), op.to_string()))
            {
                anyhow::bail!("query failed");
            }
            Ok(self.appop_mode(user, package, op))
        }

        fn standby_bucket(&mut self, user: u32, package: &str) -> anyhow::Result<String> {
            Ok(self.bucket(user, package))
        }

        fn disable_component(&mut self, user: u32, component: &str) -> anyhow::Result<()> {
            let call = format!("disable:{user}:{component}");
            self.call(call.clone());
            if self.fail_apply.contains(&call) {
                anyhow::bail!("apply failed");
            }
            self.set_state(user, component, ComponentState::Disabled);
            Ok(())
        }

        fn restore_component(
            &mut self,
            user: u32,
            component: &str,
            state: ComponentState,
        ) -> anyhow::Result<RestoreOutcome> {
            let call = format!("restore-component:{user}:{component}:{}", state.as_str());
            self.call(call.clone());
            if self
                .missing_components
                .contains(&(user, component.to_string()))
            {
                return Ok(RestoreOutcome::UnknownComponent);
            }
            if self.fail_restore.contains(&call) {
                anyhow::bail!("restore failed");
            }
            self.set_state(user, component, state);
            Ok(RestoreOutcome::Restored)
        }

        fn set_appop(
            &mut self,
            user: u32,
            package: &str,
            op: &str,
            mode: &str,
        ) -> anyhow::Result<()> {
            let call = format!("appop:{user}:{package}:{op}:{mode}");
            self.call(call.clone());
            if self.fail_apply.contains(&call) {
                anyhow::bail!("apply failed");
            }
            self.appops.insert(
                (user, package.to_string(), op.to_string()),
                mode.to_string(),
            );
            Ok(())
        }

        fn set_standby_bucket(
            &mut self,
            user: u32,
            package: &str,
            bucket: &str,
        ) -> anyhow::Result<()> {
            let call = format!("standby:{user}:{package}:{bucket}");
            self.call(call.clone());
            if self.fail_apply.contains(&call) {
                anyhow::bail!("apply failed");
            }
            // The device accepts a bucket name and prints the integer back.
            let stored = match standby_bucket_id(bucket) {
                Some(id) => id.to_string(),
                None => bucket.to_string(),
            };
            self.buckets.insert((user, package.to_string()), stored);
            Ok(())
        }
    }

    fn layer1_all() -> Layer1Policy {
        Layer1Policy {
            disable_boot_receivers: true,
            appops: vec![AppOpSetting {
                op: "RUN_IN_BACKGROUND".to_string(),
                mode: "ignore".to_string(),
            }],
            standby_bucket: Some("restricted".to_string()),
        }
    }

    fn layer1_appops() -> Layer1Policy {
        Layer1Policy {
            disable_boot_receivers: false,
            appops: vec![AppOpSetting {
                op: "RUN_IN_BACKGROUND".to_string(),
                mode: "ignore".to_string(),
            }],
            standby_bucket: None,
        }
    }

    fn policy(deny: &[&str], layer1: Option<Layer1Policy>, never_kill: &[&str]) -> Policy {
        let mut policy = Policy {
            layer1,
            never_kill: never_kill.iter().map(|p| p.to_string()).collect(),
            ..Policy::default()
        };
        policy.deny = deny
            .iter()
            .map(|package| DenyRule {
                package: package.to_string(),
                grace_ms: 2000,
                keep_adj: 100,
            })
            .collect();
        policy
    }

    fn uid_map(text: &str) -> UidMap {
        UidMap::parse_packages_list(text)
    }

    fn reconcile_with(
        policy: &Policy,
        map: Option<&UidMap>,
        ops: &mut FakeOps,
        path: &Path,
        apply: bool,
    ) {
        reconcile(policy, &[], map, ops, path, apply);
    }

    fn journal_items(path: &Path) -> Vec<Item> {
        Journal::load(path).expect("journal loads").items().to_vec()
    }

    #[test]
    fn package_removed_from_deny_restores_all_items() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        ops.receivers.insert(
            (0, ACTIONS[0].to_string()),
            vec![
                "com.example/.Boot".to_string(),
                "com.other/.Boot".to_string(),
            ],
        );

        reconcile_with(
            &policy(&["com.example"], Some(layer1_all()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let items = journal_items(&path);
        assert_eq!(items.len(), 3);
        assert_eq!(ops.state(0, "com.example/.Boot"), ComponentState::Disabled);
        assert!(!ops.has_call("com.other"));

        reconcile_with(
            &policy(&[], Some(layer1_all()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert!(journal_items(&path).is_empty());
        assert_eq!(ops.state(0, "com.example/.Boot"), ComponentState::Default);
        assert_eq!(
            ops.appop_mode(0, "com.example", "RUN_IN_BACKGROUND"),
            "default"
        );
        assert_eq!(ops.bucket(0, "com.example"), "10");
    }

    #[test]
    fn disabled_category_restores_only_that_kind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        ops.receivers.insert(
            (0, ACTIONS[0].to_string()),
            vec!["com.example/.Boot".to_string()],
        );

        reconcile_with(
            &policy(&["com.example"], Some(layer1_all()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let mut receivers_only = layer1_all();
        receivers_only.disable_boot_receivers = false;
        reconcile_with(
            &policy(&["com.example"], Some(receivers_only), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let kinds: Vec<Kind> = journal_items(&path).iter().map(|item| item.kind).collect();
        assert_eq!(kinds, [Kind::Appop, Kind::Standby]);
        assert_eq!(ops.state(0, "com.example/.Boot"), ComponentState::Default);
    }

    #[test]
    fn removed_appop_restores_only_that_op() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        let two_ops = Layer1Policy {
            disable_boot_receivers: false,
            appops: vec![
                AppOpSetting {
                    op: "RUN_IN_BACKGROUND".to_string(),
                    mode: "ignore".to_string(),
                },
                AppOpSetting {
                    op: "RUN_ANY_IN_BACKGROUND".to_string(),
                    mode: "deny".to_string(),
                },
            ],
            standby_bucket: None,
        };
        reconcile_with(
            &policy(&["com.example"], Some(two_ops), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 2);

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let items = journal_items(&path);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key, "RUN_IN_BACKGROUND");
        assert_eq!(
            ops.appop_mode(0, "com.example", "RUN_ANY_IN_BACKGROUND"),
            "default"
        );
    }

    #[test]
    fn removed_standby_restores_only_the_bucket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        ops.receivers.insert(
            (0, ACTIONS[0].to_string()),
            vec!["com.example/.Boot".to_string()],
        );
        reconcile_with(
            &policy(&["com.example"], Some(layer1_all()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let mut without_standby = layer1_all();
        without_standby.standby_bucket = None;
        reconcile_with(
            &policy(&["com.example"], Some(without_standby), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let kinds: Vec<Kind> = journal_items(&path).iter().map(|item| item.kind).collect();
        assert_eq!(kinds, [Kind::Receiver, Kind::Appop]);
        assert_eq!(ops.bucket(0, "com.example"), "10");
    }

    #[test]
    fn absent_denied_package_keeps_its_items() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 1);
        ops.calls.clear();

        let empty = UidMap::empty();
        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&empty),
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 1);
        assert!(ops.calls.is_empty());
    }

    #[test]
    fn never_kill_addition_restores() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 1);

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &["com.example"]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert!(journal_items(&path).is_empty());
        assert_eq!(
            ops.appop_mode(0, "com.example", "RUN_IN_BACKGROUND"),
            "default"
        );
    }

    #[test]
    fn shared_appid_restores_only_the_removed_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.one 10123 0 /data\ncom.two 10123 0 /data\n");
        let mut ops = FakeOps::default();

        reconcile_with(
            &policy(&["com.one", "com.two"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 2);

        reconcile_with(
            &policy(&["com.one"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let items = journal_items(&path);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].package, "com.one");
        assert_eq!(ops.appop_mode(0, "com.two", "RUN_IN_BACKGROUND"), "default");
        assert_eq!(ops.appop_mode(0, "com.one", "RUN_IN_BACKGROUND"), "ignore");
    }

    #[test]
    fn failed_query_does_not_mutate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        ops.fail_appop_query.insert((
            0,
            "com.example".to_string(),
            "RUN_IN_BACKGROUND".to_string(),
        ));

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert!(journal_items(&path).is_empty());
        assert!(ops.calls.is_empty());
    }

    #[test]
    fn failed_state_query_still_disables_receiver() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        ops.receivers.insert(
            (0, ACTIONS[0].to_string()),
            vec!["com.example/.Boot".to_string()],
        );
        ops.fail_state_query.insert((0, "com.example".to_string()));

        reconcile_with(
            &policy(&["com.example"], Some(layer1_all()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );

        assert_eq!(ops.state(0, "com.example/.Boot"), ComponentState::Disabled);
        let item = journal_items(&path)
            .into_iter()
            .find(|item| item.kind == Kind::Receiver)
            .expect("receiver journaled");
        assert_eq!(item.previous, "enabled");
    }

    #[test]
    fn failed_apply_removes_the_item() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        ops.fail_apply
            .insert("appop:0:com.example:RUN_IN_BACKGROUND:ignore".to_string());

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert!(journal_items(&path).is_empty());
        assert!(ops.has_call("appop:0:com.example"));
    }

    #[test]
    fn failed_restore_keeps_the_item() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        ops.fail_apply
            .insert("appop:0:com.example:RUN_IN_BACKGROUND:default".to_string());
        reconcile_with(
            &policy(&[], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let items = journal_items(&path);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, Kind::Appop);
    }

    #[test]
    fn removed_component_is_dropped_without_a_restore() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        ops.receivers.insert(
            (0, ACTIONS[0].to_string()),
            vec!["com.example/.Boot".to_string()],
        );
        reconcile_with(
            &policy(&["com.example"], Some(layer1_all()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 3);

        ops.missing_components
            .insert((0, "com.example/.Boot".to_string()));
        reconcile_with(
            &policy(&[], Some(layer1_all()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert!(journal_items(&path).is_empty());
    }

    #[test]
    fn multi_user_package_gets_an_item_per_user() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\ncom.example 1010123 0 /data\n");
        let mut ops = FakeOps::default();

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let users: Vec<u32> = journal_items(&path).iter().map(|item| item.user).collect();
        assert_eq!(users, [0, 10]);
    }

    #[test]
    fn unavailable_uid_map_skips_reconciliation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 1);
        ops.calls.clear();

        reconcile_with(
            &policy(&[], Some(layer1_appops()), &[]),
            None,
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 1);
        assert!(ops.calls.is_empty());
    }

    #[test]
    fn corrupt_journal_disables_layer1() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        std::fs::write(&path, "not toml").expect("write");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();

        reconcile_with(
            &policy(&["com.example"], Some(layer1_all()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert!(ops.calls.is_empty());
    }

    #[test]
    fn reconcile_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        ops.receivers.insert(
            (0, ACTIONS[0].to_string()),
            vec!["com.example/.Boot".to_string()],
        );
        let policy = policy(&["com.example"], Some(layer1_all()), &[]);

        reconcile_with(&policy, Some(&map), &mut ops, &path, true);
        let first = journal_items(&path);
        reconcile_with(&policy, Some(&map), &mut ops, &path, true);
        assert_eq!(journal_items(&path), first);
    }

    #[test]
    fn observe_mode_restores_but_does_not_apply() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 1);

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            false,
        );
        assert_eq!(journal_items(&path).len(), 1);

        reconcile_with(
            &policy(&[], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            false,
        );
        assert!(journal_items(&path).is_empty());
    }

    #[test]
    fn reapply_does_not_duplicate_journal_items() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        let policy = policy(&["com.example"], Some(layer1_appops()), &[]);
        reconcile_with(&policy, Some(&map), &mut ops, &path, true);
        assert_eq!(journal_items(&path).len(), 1);
        ops.calls.clear();

        reapply_package(&policy, &[], &map, &mut ops, &path, true, "com.example");
        assert_eq!(journal_items(&path).len(), 1);
        assert!(!ops.has_call("appop:0:com.example:RUN_IN_BACKGROUND:ignore"));
    }

    #[test]
    fn reapply_repairs_a_stale_setting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        let policy = policy(&["com.example"], Some(layer1_appops()), &[]);
        reconcile_with(&policy, Some(&map), &mut ops, &path, true);
        ops.appops.insert(
            (
                0,
                "com.example".to_string(),
                "RUN_IN_BACKGROUND".to_string(),
            ),
            "allow".to_string(),
        );
        ops.calls.clear();

        reapply_package(&policy, &[], &map, &mut ops, &path, true, "com.example");
        assert!(ops.has_call("appop:0:com.example:RUN_IN_BACKGROUND:ignore"));
        assert_eq!(journal_items(&path).len(), 1);
    }

    #[test]
    fn standby_is_reapplied_after_the_system_rebuckets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        let policy = policy(&["com.example"], Some(layer1_all()), &[]);
        reconcile_with(&policy, Some(&map), &mut ops, &path, true);
        assert_eq!(ops.bucket(0, "com.example"), "45");

        ops.buckets
            .insert((0, "com.example".to_string()), "40".to_string());
        reapply_standby(&policy, &[], &mut ops, &path, false, 0, "com.example");
        assert_eq!(ops.bucket(0, "com.example"), "40");

        reapply_standby(&policy, &[], &mut ops, &path, true, 0, "com.example");
        assert_eq!(ops.bucket(0, "com.example"), "45");
        assert_eq!(journal_items(&path).len(), 2);
    }

    #[test]
    fn restore_all_reverts_every_journaled_item() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        ops.receivers.insert(
            (0, ACTIONS[0].to_string()),
            vec!["com.example/.Boot".to_string()],
        );
        reconcile_with(
            &policy(&["com.example"], Some(layer1_all()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        assert_eq!(journal_items(&path).len(), 3);
        assert!(ops.has_call("disable:0:com.example/.Boot"));

        restore_all(&path, &mut ops).expect("restore must succeed");
        assert!(journal_items(&path).is_empty());
        assert!(ops.has_call("restore-component:0:com.example/.Boot:default"));
        assert!(ops.has_call("appop:0:com.example:RUN_IN_BACKGROUND:default"));
        assert!(ops.has_call("standby:0:com.example:10"));
    }

    #[test]
    fn restore_all_keeps_items_that_fail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        ops.fail_apply
            .insert("appop:0:com.example:RUN_IN_BACKGROUND:default".to_string());

        let err = restore_all(&path, &mut ops).expect_err("restore must fail");
        assert!(err.to_string().contains("could not be restored"));
        assert_eq!(journal_items(&path).len(), 1);
    }

    #[test]
    fn restore_maps_every_journaled_component_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let mut journal = Journal::load(&path).expect("journal");
        for (index, state) in ["disabled", "disabled-user", "disabled-until-used"]
            .iter()
            .enumerate()
        {
            let component = format!("com.example/.R{index}");
            journal.append(Item::new(
                0,
                "com.example",
                Kind::Receiver,
                &component,
                *state,
            ));
        }
        journal.save().expect("save");

        let mut ops = FakeOps::default();
        restore_all(&path, &mut ops).expect("restore must succeed");
        assert!(ops.has_call("restore-component:0:com.example/.R0:disabled"));
        assert!(ops.has_call("restore-component:0:com.example/.R1:disabled-user"));
        assert!(ops.has_call("restore-component:0:com.example/.R2:disabled-until-used"));
    }

    #[test]
    fn expired_deadline_leaves_the_device_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();
        let policy = policy(&["com.example"], Some(layer1_all()), &[]);
        let mut journal = Journal::load(&path).expect("journal");
        let mut deadline = Deadline {
            at: Instant::now() - Duration::from_secs(1),
            announced: true,
        };
        reconcile_with_deadline(
            &policy,
            &[],
            &map,
            &mut journal,
            &mut ops,
            true,
            &mut deadline,
        );
        assert!(ops.calls.is_empty());
        assert!(journal.items().is_empty());
    }

    #[test]
    fn absent_package_without_deny_rule_is_pruned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.toml");
        let map = uid_map("com.example 10123 0 /data\n");
        let mut ops = FakeOps::default();

        reconcile_with(
            &policy(&["com.example"], Some(layer1_appops()), &[]),
            Some(&map),
            &mut ops,
            &path,
            true,
        );
        let empty = UidMap::empty();
        reconcile_with(
            &policy(&[], Some(layer1_appops()), &[]),
            Some(&empty),
            &mut ops,
            &path,
            true,
        );
        assert!(journal_items(&path).is_empty());
    }
}
