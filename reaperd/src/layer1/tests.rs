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

mod apply_tests;
mod restore_tests;

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
