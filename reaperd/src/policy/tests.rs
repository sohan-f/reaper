use super::*;

const SPEC_EXAMPLE: &str = r#"
[global]
mode = "observe"
grace_ms = 2000
keep_adj = 100
kill_budget_per_min = 20
respawn_window_s = 60
respawn_max = 3

[layer1]
disable_boot_receivers = true
appops = ["RUN_ANY_IN_BACKGROUND:ignore", "RUN_IN_BACKGROUND:ignore"]
standby_bucket = "restricted"

[never_kill]
packages = ["android", "com.android.systemui"]

[[deny]]
package = "com.facebook.katana"

[[deny]]
package = "com.instagram.android"
grace_ms = 30000
keep_adj = 200
"#;

#[test]
fn parses_spec_global_and_deny() {
    let policy = Policy::parse(SPEC_EXAMPLE).expect("spec example must parse");
    assert_eq!(policy.mode, Mode::Observe);
    assert_eq!(policy.grace_ms, 2000);
    assert_eq!(policy.keep_adj, 100);
    assert_eq!(policy.deny.len(), 2);
    assert_eq!(policy.deny[1].grace_ms, 30000);
    assert_eq!(policy.deny[1].keep_adj, 200);
    assert_eq!(policy.deny[0].grace_ms, 2000);
    assert_eq!(policy.deny[0].keep_adj, 100);
}

#[test]
fn parses_spec_layer1() {
    let policy = Policy::parse(SPEC_EXAMPLE).expect("spec example must parse");
    assert_eq!(policy.never_kill, ["android", "com.android.systemui"]);
    let layer1 = policy.layer1.expect("layer1 table must parse");
    assert!(layer1.disable_boot_receivers);
    assert_eq!(
        layer1.appops,
        [
            AppOpSetting {
                op: "RUN_ANY_IN_BACKGROUND".to_string(),
                mode: "ignore".to_string(),
            },
            AppOpSetting {
                op: "RUN_IN_BACKGROUND".to_string(),
                mode: "ignore".to_string(),
            },
        ]
    );
    assert_eq!(layer1.standby_bucket.as_deref(), Some("restricted"));
}

#[test]
fn layer1_absent_means_no_layer1() {
    let policy = Policy::parse("[global]\nmode = \"observe\"\n").expect("policy must parse");
    assert!(policy.layer1.is_none());
}

#[test]
fn empty_layer1_table_disables_every_category() {
    let policy = Policy::parse("[layer1]\n").expect("policy must parse");
    let layer1 = policy.layer1.expect("layer1 table must parse");
    assert!(!layer1.disable_boot_receivers);
    assert!(layer1.appops.is_empty());
    assert!(layer1.standby_bucket.is_none());
}

#[test]
fn rejects_unknown_layer1_key() {
    assert!(Policy::parse("[layer1]\ndisable_receivers = true\n").is_err());
}

#[test]
fn rejects_bad_appop_mode() {
    assert!(Policy::parse("[layer1]\nappops = [\"RUN_ANY_IN_BACKGROUND:always\"]\n").is_err());
}

#[test]
fn rejects_appop_without_mode() {
    assert!(Policy::parse("[layer1]\nappops = [\"RUN_ANY_IN_BACKGROUND\"]\n").is_err());
}

#[test]
fn rejects_unknown_appop_name() {
    assert!(Policy::parse("[layer1]\nappops = [\"RUN_IN_BACKGROND:ignore\"]\n").is_err());
}

#[test]
fn rejects_duplicate_appop() {
    assert!(
        Policy::parse(
            "[layer1]\nappops = [\"RUN_IN_BACKGROUND:ignore\", \"RUN_IN_BACKGROUND:deny\"]\n"
        )
        .is_err()
    );
}

#[test]
fn rejects_bad_standby_bucket() {
    assert!(Policy::parse("[layer1]\nstandby_bucket = \"cold\"\n").is_err());
}

#[test]
fn rejects_unknown_top_level_key() {
    let text = "[global]\nmode = \"observe\"\n\n[neverkill]\npackages = [\"android\"]\n";
    assert!(Policy::parse(text).is_err());
}

#[test]
fn rejects_unknown_never_kill_key() {
    let text = "[never_kill]\npackage = [\"android\"]\n";
    assert!(Policy::parse(text).is_err());
}

#[test]
fn rejects_bad_mode() {
    let text = "[global]\nmode = \"maybe\"\n";
    assert!(Policy::parse(text).is_err());
}

#[test]
fn rejects_keep_adj_out_of_range() {
    let text = "[global]\nkeep_adj = 1001\n";
    assert!(Policy::parse(text).is_err());
}

#[test]
fn rejects_grace_above_cap() {
    let text = format!("[global]\ngrace_ms = {}\n", MAX_GRACE_MS + 1);
    assert!(Policy::parse(&text).is_err());
}

#[test]
fn rejects_per_app_grace_above_cap() {
    let text = format!(
        "[[deny]]\npackage = \"com.example\"\ngrace_ms = {}\n",
        MAX_GRACE_MS + 1
    );
    assert!(Policy::parse(&text).is_err());
}
