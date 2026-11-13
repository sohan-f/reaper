use std::collections::{HashMap, HashSet};

use super::*;
use crate::layer1::device::{ComponentState, RestoreOutcome};
use crate::layer1::journal::Kind;
use crate::layer1::parse::component_key;
use crate::policy::{AppOpSetting, DenyRule, Layer1Policy};

#[derive(Default)]
struct FakeOps {
    receivers: HashMap<(u32, String), Vec<String>>,
    hidden_receivers: HashMap<(u32, String), Vec<String>>,
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
    fn receivers(
        &mut self,
        user: u32,
        action: &str,
        filter: ReceiverFilter,
    ) -> anyhow::Result<Vec<String>> {
        let mut found = self
            .receivers
            .get(&(user, action.to_string()))
            .cloned()
            .unwrap_or_default();
        if filter == ReceiverFilter::IncludingDisabled {
            found.extend(
                self.hidden_receivers
                    .get(&(user, action.to_string()))
                    .cloned()
                    .unwrap_or_default(),
            );
        }
        Ok(found)
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
            .map(|((_, component), state)| (component_key(component), *state))
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

    fn set_appop(&mut self, user: u32, package: &str, op: &str, mode: &str) -> anyhow::Result<()> {
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

    fn set_standby_bucket(&mut self, user: u32, package: &str, bucket: &str) -> anyhow::Result<()> {
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
        never_kill: never_kill.iter().map(ToString::to_string).collect(),
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
    reconcile(&Plan::new(policy, &[], apply), map, ops, path);
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
fn disabled_receiver_is_kept_when_query_skips_it() {
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

    // The system leaves a disabled component out of the receiver query.
    ops.receivers.clear();
    ops.calls.clear();
    reconcile_with(
        &policy(&["com.example"], Some(layer1_all()), &[]),
        Some(&map),
        &mut ops,
        &path,
        true,
    );

    let kinds: Vec<Kind> = journal_items(&path).iter().map(|item| item.kind).collect();
    assert!(kinds.contains(&Kind::Receiver));
    assert!(ops.calls.is_empty());
    assert_eq!(ops.state(0, "com.example/.Boot"), ComponentState::Disabled);
}

#[test]
fn externally_disabled_receiver_is_not_adopted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.toml");
    let map = uid_map("com.example 10123 0 /data\n");
    let mut ops = FakeOps::default();
    ops.hidden_receivers.insert(
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

    let kinds: Vec<Kind> = journal_items(&path).iter().map(|item| item.kind).collect();
    assert!(!kinds.contains(&Kind::Receiver));
    assert!(!ops.has_call("disable:"));
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

    reapply_package(
        &Plan::new(&policy, &[], true),
        &map,
        &mut ops,
        &path,
        "com.example",
    );
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

    reapply_package(
        &Plan::new(&policy, &[], true),
        &map,
        &mut ops,
        &path,
        "com.example",
    );
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
    reapply_standby(
        &Plan::new(&policy, &[], false),
        &mut ops,
        &path,
        0,
        "com.example",
    );
    assert_eq!(ops.bucket(0, "com.example"), "40");

    reapply_standby(
        &Plan::new(&policy, &[], true),
        &mut ops,
        &path,
        0,
        "com.example",
    );
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
    let journal = Journal::load(&path).expect("journal");
    let deadline = Deadline {
        at: Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test clock supports subtraction"),
        announced: true,
    };
    {
        let mut pass = Pass {
            journal,
            ops: &mut ops,
            deadline,
        };
        run(&Plan::new(&policy, &[], true), &map, &mut pass);
        assert!(pass.journal.items().is_empty());
    }
    assert!(ops.calls.is_empty());
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
