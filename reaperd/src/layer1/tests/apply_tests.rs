use super::*;

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
