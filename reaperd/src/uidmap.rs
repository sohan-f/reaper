//! Package to uid resolution.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, bail};

use crate::{command, policy::appid_of};

const LIST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageInstance {
    pub user: u32,
    pub uid: u32,
    pub appid: u32,
}

#[derive(Default)]
pub struct UidMap {
    packages_by_appid: HashMap<u32, Vec<String>>,
    instances_by_package: HashMap<String, Vec<PackageInstance>>,
    user_ids: HashSet<u32>,
}

impl UidMap {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn packages_of(&self, appid: u32) -> &[String] {
        self.packages_by_appid
            .get(&appid)
            .map_or(&[], Vec::as_slice)
    }

    pub fn instances_of(&self, package: &str) -> &[PackageInstance] {
        self.instances_by_package
            .get(package)
            .map_or(&[], Vec::as_slice)
    }

    pub fn uid_of(&self, package: &str) -> Option<u32> {
        self.instances_of(package)
            .first()
            .map(|instance| instance.uid)
    }

    pub fn appid_of_package(&self, package: &str) -> Option<u32> {
        self.uid_of(package).and_then(appid_of)
    }

    pub fn package_count(&self) -> usize {
        self.instances_by_package.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instances_by_package.is_empty()
    }

    /// Returns the user ids present in the map, sorted.
    pub fn users(&self) -> Vec<u32> {
        let mut users: Vec<u32> = self.user_ids.iter().copied().collect();
        users.sort_unstable();
        users
    }

    fn insert(&mut self, package: &str, uid: u32, appid: u32) {
        let user = uid / 100_000;
        self.user_ids.insert(user);
        let instances = self
            .instances_by_package
            .entry(package.to_string())
            .or_default();
        if !instances.iter().any(|instance| instance.uid == uid) {
            instances.push(PackageInstance { user, uid, appid });
        }
        let packages = self.packages_by_appid.entry(appid).or_default();
        if !packages.iter().any(|known| known == package) {
            packages.push(package.to_string());
        }
    }

    pub fn parse_packages_list(text: &str) -> Self {
        let mut map = Self::default();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(package) = parts.next() else {
                continue;
            };
            let Some(uid_str) = parts.next() else {
                continue;
            };
            let Ok(uid) = uid_str.parse::<u32>() else {
                continue;
            };
            let Some(appid) = appid_of(uid) else { continue };
            map.insert(package, uid, appid);
        }
        map
    }

    pub fn parse_cmd_list(text: &str) -> Self {
        let mut map = Self::default();
        for line in text.lines() {
            // format: package:<pkg> uid:<uid>
            let Some(pkg) = line.strip_prefix("package:") else {
                continue;
            };
            let Some((package, rest)) = pkg.split_once(' ') else {
                continue;
            };
            let Some(uid_str) = rest.strip_prefix("uid:") else {
                continue;
            };
            let Ok(uid) = uid_str.trim().parse::<u32>() else {
                continue;
            };
            let Some(appid) = appid_of(uid) else { continue };
            map.insert(package, uid, appid);
        }
        map
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Self::parse_packages_list(&text)),
            Err(fs_err) => {
                log::warn!(
                    "{} unreadable ({fs_err}); falling back to `cmd package list packages -U`",
                    path.display()
                );
                let mut command = Command::new("cmd");
                command.args(["package", "list", "packages", "-U"]);
                let output = command::output(&mut command, LIST_TIMEOUT)
                    .context("failed to run `cmd package list packages -U`")?;
                if !output.status.success() {
                    bail!(
                        "`cmd package list packages -U` failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Ok(Self::parse_cmd_list(&String::from_utf8_lossy(
                    &output.stdout,
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_packages_list_columns() {
        let text = "com.android.phone 1001 0 /data/user/0/com.android.phone release:targetSdkVersion=36:partition=system 3002,3003 0 1 1 @system\ncom.instagram.android 10293 0 /data/user/0/com.instagram.android release:targetSdkVersion=36:partition=product none 0 1 1 @product\n";
        let map = UidMap::parse_packages_list(text);
        assert_eq!(map.uid_of("com.instagram.android"), Some(10293));
        assert_eq!(
            map.packages_of(10293),
            &["com.instagram.android".to_string()]
        );
        assert_eq!(map.appid_of_package("com.instagram.android"), Some(10293));
        // system uid 1001 is outside the app id range
        assert_eq!(map.uid_of("com.android.phone"), None);
    }

    #[test]
    fn parses_cmd_list() {
        let text =
            "package:com.instagram.android uid:10293\npackage:com.twitter.android uid:10381\n";
        let map = UidMap::parse_cmd_list(text);
        assert_eq!(map.uid_of("com.twitter.android"), Some(10381));
        assert_eq!(map.packages_of(10381), &["com.twitter.android".to_string()]);
    }

    #[test]
    fn lists_users() {
        let text = "com.example 10123 0 /data\ncom.example 1010123 0 /data\n";
        let map = UidMap::parse_packages_list(text);
        assert_eq!(map.users(), vec![0, 10]);
        assert_eq!(
            map.instances_of("com.example"),
            [
                PackageInstance {
                    user: 0,
                    uid: 10123,
                    appid: 10123,
                },
                PackageInstance {
                    user: 10,
                    uid: 1_010_123,
                    appid: 10123,
                },
            ]
        );
        assert_eq!(map.packages_of(10123), &["com.example".to_string()]);
        assert_eq!(map.package_count(), 1);
    }

    #[test]
    fn shared_appid_keeps_every_package() {
        let text = "com.example.one 10123 0 /data\ncom.example.two 10123 0 /data\n";
        let map = UidMap::parse_packages_list(text);
        let mut packages = map.packages_of(10123).to_vec();
        packages.sort();
        assert_eq!(packages, ["com.example.one", "com.example.two"]);
        assert_eq!(map.instances_of("com.example.one").len(), 1);
        assert_eq!(map.instances_of("com.example.two").len(), 1);
    }
}
