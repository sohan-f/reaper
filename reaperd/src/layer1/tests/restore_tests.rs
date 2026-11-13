use super::*;

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
