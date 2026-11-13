//! The deny list installed in the eBPF map, and the never-kill safety set.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use aya::maps::{HashMap as BpfHashMap, MapData};
use log::warn;
use reaper_common::DenyCfg;

use crate::{never_kill, policy::Policy, uidmap::UidMap};

/// One appid the eBPF program nominates when its adj crosses `keep_adj`.
pub struct DenyEntry {
    /// Appid to watch.
    pub appid: u32,
    /// Nominate above this `oom_score_adj`.
    pub keep_adj: i16,
    /// Grace period between nomination and the decision.
    pub grace_ms: u64,
}

/// The DENY array as seen from userspace.
pub type DenyMapMut<'a> = BpfHashMap<&'a mut MapData, u32, DenyCfg>;

/// Lists the Android users present on the device, defaulting to user 0.
pub fn watched_users(uid_map: &UidMap) -> Vec<u32> {
    let mut users = uid_map.users();
    if users.is_empty() {
        users.push(0);
    }
    users
}

/// Makes the DENY map match `deny`, dropping stale appids.
///
/// # Errors
///
/// Returns an error if a key cannot be listed, removed, or inserted.
pub fn install_deny_map(deny_map: &mut DenyMapMut<'_>, deny: &[DenyEntry]) -> anyhow::Result<()> {
    let wanted: HashSet<u32> = deny.iter().map(|entry| entry.appid).collect();
    let current: Vec<u32> = deny_map
        .keys()
        .collect::<Result<_, _>>()
        .context("failed to list DENY map keys")?;
    for appid in current {
        if !wanted.contains(&appid) {
            deny_map
                .remove(&appid)
                .with_context(|| format!("failed to remove deny entry for appid {appid}"))?;
        }
    }
    for entry in deny {
        deny_map
            .insert(
                &entry.appid,
                &DenyCfg {
                    keep_adj: entry.keep_adj,
                    flags: 0,
                },
                0,
            )
            .with_context(|| format!("failed to insert deny entry for appid {}", entry.appid))?;
    }
    Ok(())
}

fn appid_is_never_kill(policy: &Policy, builtin: &[String], uid_map: &UidMap, appid: u32) -> bool {
    uid_map
        .packages_of(appid)
        .iter()
        .any(|package| policy.never_kill.contains(package) || builtin.contains(package))
}

/// Resolves the policy rules and `--deny` overrides into one entry per appid.
pub fn build_deny(
    policy: &Policy,
    builtin_never_kill: &[String],
    uid_map: &UidMap,
    overrides: &[(u32, i16)],
) -> Vec<DenyEntry> {
    let mut entries: HashMap<u32, DenyEntry> = HashMap::new();
    for rule in &policy.deny {
        if policy.never_kill.contains(&rule.package) || builtin_never_kill.contains(&rule.package) {
            warn!(
                "deny rule for {} ignored: package is in never_kill",
                rule.package
            );
            continue;
        }
        match uid_map.appid_of_package(&rule.package) {
            Some(appid) => {
                entries.insert(
                    appid,
                    DenyEntry {
                        appid,
                        keep_adj: rule.keep_adj,
                        grace_ms: rule.grace_ms,
                    },
                );
            }
            None => warn!(
                "deny rule for {} resolves to no appid; skipping",
                rule.package
            ),
        }
    }
    for &(appid, keep_adj) in overrides {
        if appid_is_never_kill(policy, builtin_never_kill, uid_map, appid) {
            warn!("--deny appid {appid} ignored: package is in never_kill");
            continue;
        }
        entries
            .entry(appid)
            .or_insert(DenyEntry {
                appid,
                keep_adj,
                grace_ms: policy.grace_ms,
            })
            .keep_adj = keep_adj;
    }
    entries.into_values().collect()
}

/// Returns the grace period and keep_adj for an appid, if it is denied.
pub fn deny_params(deny: &[DenyEntry], appid: u32) -> Option<(u64, i16)> {
    deny.iter()
        .find(|entry| entry.appid == appid)
        .map(|entry| (entry.grace_ms, entry.keep_adj))
}

/// Returns the first package on `appid` that is in a never-kill set.
pub fn never_kill_package<'a>(
    policy: &Policy,
    builtin: &[String],
    packages: &'a [String],
) -> Option<&'a str> {
    packages.iter().map(String::as_str).find(|package| {
        policy.never_kill.iter().any(|p| p == package) || builtin.iter().any(|p| p == package)
    })
}

/// Resolves the safety packages for users not seen before.
pub fn refresh_never_kill(packages: &mut Vec<String>, resolved: &mut Vec<u32>, users: &[u32]) {
    let fresh: Vec<u32> = users
        .iter()
        .copied()
        .filter(|user| !resolved.contains(user))
        .collect();
    if fresh.is_empty() {
        return;
    }
    extend_never_kill(packages, &fresh);
    resolved.extend(fresh);
    resolved.sort_unstable();
}

// A role lookup can fail while packages.list is being rewritten, so the set
// only grows: dropping a launcher or dialer from a safety list would let
// Layer 2 kill it.
fn extend_never_kill(packages: &mut Vec<String>, users: &[u32]) {
    packages.extend(never_kill::resolve(users));
    packages.sort();
    packages.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DenyRule;

    #[test]
    fn never_kill_matches_any_package_on_appid() {
        let mut policy = Policy::default();
        policy.never_kill.push("com.android.systemui".to_string());
        let packages = [
            "com.example.shared".to_string(),
            "com.android.systemui".to_string(),
        ];
        assert_eq!(
            never_kill_package(&policy, &[], &packages),
            Some("com.android.systemui")
        );
        assert_eq!(never_kill_package(&policy, &[], &[]), None);
    }

    #[test]
    fn never_kill_package_stays_out_of_deny_map() {
        let mut policy = Policy::default();
        policy.never_kill.push("com.android.systemui".to_string());
        for package in ["com.android.systemui", "com.facebook.katana"] {
            policy.deny.push(DenyRule {
                package: package.to_string(),
                grace_ms: 2000,
                keep_adj: 100,
            });
        }
        let uid_map = UidMap::parse_packages_list(
            "com.android.systemui 10139 0 /data\ncom.facebook.katana 10293 0 /data\n",
        );
        let deny = build_deny(&policy, &[], &uid_map, &[]);
        assert_eq!(deny.len(), 1);
        assert_eq!(deny[0].appid, 10293);
    }

    #[test]
    fn never_kill_refresh_skips_known_users() {
        let mut packages = Vec::new();
        let mut resolved = vec![0];
        refresh_never_kill(&mut packages, &mut resolved, &[0]);
        assert!(packages.is_empty());
        assert_eq!(resolved, vec![0]);
    }

    #[test]
    fn never_kill_set_only_grows() {
        let mut packages = vec!["com.example.custom".to_string()];
        extend_never_kill(&mut packages, &[]);
        assert!(
            packages
                .iter()
                .any(|package| package == "com.example.custom")
        );
        for package in never_kill::PACKAGES {
            assert!(packages.iter().any(|entry| entry == package));
        }
        let len = packages.len();
        extend_never_kill(&mut packages, &[]);
        assert_eq!(packages.len(), len);
        assert!(packages.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn builtin_never_kill_stays_out_of_deny_map() {
        let mut policy = Policy::default();
        policy.deny.push(DenyRule {
            package: "com.android.systemui".to_string(),
            grace_ms: 2000,
            keep_adj: 100,
        });
        let builtin = vec!["com.android.systemui".to_string()];
        let uid_map = UidMap::parse_packages_list("com.android.systemui 10139 0 /data\n");
        assert!(build_deny(&policy, &builtin, &uid_map, &[]).is_empty());
    }

    #[test]
    fn builtin_never_kill_override_stays_out_of_deny_map() {
        let policy = Policy::default();
        let builtin = vec!["com.android.systemui".to_string()];
        let uid_map = UidMap::parse_packages_list("com.android.systemui 10139 0 /data\n");
        assert!(build_deny(&policy, &builtin, &uid_map, &[(10139, 100)]).is_empty());
    }

    #[test]
    fn deny_override_for_normal_appid_lands() {
        let policy = Policy::default();
        let uid_map = UidMap::parse_packages_list("com.example 10123 0 /data\n");
        let deny = build_deny(&policy, &[], &uid_map, &[(10123, 100)]);
        assert_eq!(deny.len(), 1);
        assert_eq!(deny[0].appid, 10123);
    }
}
