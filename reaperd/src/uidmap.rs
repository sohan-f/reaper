//! Package to uid resolution.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};

use crate::policy::appid_of;

#[derive(Default)]
pub struct UidMap {
    packages_by_appid: HashMap<u32, Vec<String>>,
    uid_by_package: HashMap<String, u32>,
}

impl UidMap {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn packages_of(&self, appid: u32) -> &[String] {
        self.packages_by_appid
            .get(&appid)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn uid_of(&self, package: &str) -> Option<u32> {
        self.uid_by_package.get(package).copied()
    }

    pub fn appid_of_package(&self, package: &str) -> Option<u32> {
        self.uid_of(package).and_then(appid_of)
    }

    pub fn package_count(&self) -> usize {
        self.uid_by_package.len()
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
            map.packages_by_appid
                .entry(appid)
                .or_default()
                .push(package.to_string());
            map.uid_by_package.insert(package.to_string(), uid);
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
            map.packages_by_appid
                .entry(appid)
                .or_default()
                .push(package.to_string());
            map.uid_by_package.insert(package.to_string(), uid);
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
                let output = Command::new("cmd")
                    .args(["package", "list", "packages", "-U"])
                    .output()
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
}
