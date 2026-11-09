//! Built-in never-kill packages, including the current launcher, IME, and dialer.

use std::{process::Command, time::Duration};

use log::{info, warn};

use crate::command;

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

pub const PACKAGES: &[&str] = &[
    "android",
    "com.android.systemui",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.vending",
    "com.android.server.telecom",
];

pub fn resolve() -> Vec<String> {
    let mut packages: Vec<String> = PACKAGES.iter().map(|package| package.to_string()).collect();
    for (role, package) in [
        ("launcher", resolve_launcher()),
        ("ime", resolve_ime()),
        ("dialer", resolve_dialer()),
    ] {
        match package {
            Some(package) => {
                info!("never_kill: {role} is {package}");
                packages.push(package);
            }
            None => warn!("never_kill: cannot resolve {role}"),
        }
    }
    packages.sort();
    packages.dedup();
    packages
}

fn resolve_launcher() -> Option<String> {
    resolve_component(&[
        "package",
        "resolve-activity",
        "--brief",
        "-a",
        "android.intent.action.MAIN",
        "-c",
        "android.intent.category.HOME",
    ])
}

fn resolve_dialer() -> Option<String> {
    resolve_component(&[
        "package",
        "resolve-activity",
        "--brief",
        "-a",
        "android.intent.action.DIAL",
    ])
}

fn resolve_ime() -> Option<String> {
    let output = run(
        "/system/bin/settings",
        &["get", "secure", "default_input_method"],
    )?;
    package_from_component(&output)
}

fn resolve_component(args: &[&str]) -> Option<String> {
    let output = run("/system/bin/cmd", args)?;
    package_from_component(&output)
}

fn run(path: &str, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(path);
    cmd.args(args);
    let output = command::output(&mut cmd, RESOLVE_TIMEOUT).ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn package_from_component(output: &str) -> Option<String> {
    output
        .lines()
        .rev()
        .map(str::trim)
        .find_map(|line| line.split_once('/').map(|(package, _)| package))
        .filter(|package| !package.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_package_from_component() {
        assert_eq!(
            package_from_component("com.android.launcher3/.Launcher\n"),
            Some("com.android.launcher3".to_string())
        );
        assert_eq!(
            package_from_component("priority=0\ncom.google.android.dialer/.Dialer\n"),
            Some("com.google.android.dialer".to_string())
        );
        assert_eq!(package_from_component("null\n"), None);
        assert_eq!(package_from_component(""), None);
    }
}
