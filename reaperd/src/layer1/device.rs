//! Layer 1 device queries, mutations, and their output parsers.

use std::{collections::HashMap, process::Command, time::Duration};

use anyhow::{Context, bail, ensure};

use super::parse::{parse_appop, parse_component_states, parse_receivers, parse_standby_bucket};
use crate::command;

const CMD: &str = "/system/bin/cmd";
const PM: &str = "/system/bin/pm";
const AM: &str = "/system/bin/am";
const TIMEOUT: Duration = Duration::from_secs(5);

// MATCH_DIRECT_BOOT_AWARE | MATCH_DIRECT_BOOT_UNAWARE. Without an explicit
// opinion the query follows the user's lock state, and a locked user hides
// every receiver that is not direct-boot aware.
const MATCH_DIRECT_BOOT: u32 = 0x000C_0000;
// MATCH_DISABLED_COMPONENTS. A disabled component is otherwise left out of
// the result, so an already-suppressed receiver looks like an absent one.
const MATCH_DISABLED_COMPONENTS: u32 = 0x0000_0200;

/// Which components `query-receivers` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverFilter {
    /// Enabled components only, the default of the shell command.
    Enabled,
    /// Every component, including the ones the enabled-state checks hide.
    IncludingDisabled,
}

/// The enabled setting `dumpsys package` reports for one component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentState {
    /// No explicit setting; the manifest decides.
    Default,
    /// Explicitly enabled.
    Enabled,
    /// Disabled by the system or by reaperd.
    Disabled,
    /// Disabled by the user.
    DisabledUser,
    /// Disabled until the user launches it.
    DisabledUntilUsed,
}

impl ComponentState {
    /// Returns the spelling `pm` and `dumpsys` use for this state.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::DisabledUser => "disabled-user",
            Self::DisabledUntilUsed => "disabled-until-used",
        }
    }

    /// Parses the spelling `dumpsys package` printed.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "default" => Some(Self::Default),
            "enabled" => Some(Self::Enabled),
            "disabled" => Some(Self::Disabled),
            "disabled-user" => Some(Self::DisabledUser),
            "disabled-until-used" => Some(Self::DisabledUntilUsed),
            _ => None,
        }
    }

    /// Returns whether the setting keeps the component from starting.
    pub fn is_disabled(self) -> bool {
        !matches!(self, Self::Default | Self::Enabled)
    }
}

/// The device commands Layer 1 needs, behind a trait so tests can fake them.
pub trait Ops {
    /// Lists the receivers registered for `action` in `user`.
    fn receivers(
        &mut self,
        user: u32,
        action: &str,
        filter: ReceiverFilter,
    ) -> anyhow::Result<Vec<String>>;
    /// Reads the enabled setting of every component of `package`.
    fn component_states(
        &mut self,
        user: u32,
        package: &str,
    ) -> anyhow::Result<HashMap<String, ComponentState>>;
    /// Reads the current mode of one app op.
    fn appop(&mut self, user: u32, package: &str, op: &str) -> anyhow::Result<String>;
    /// Reads the current standby bucket as the integer `am` prints.
    fn standby_bucket(&mut self, user: u32, package: &str) -> anyhow::Result<String>;
    /// Disables one component of `package`.
    fn disable_component(&mut self, user: u32, component: &str) -> anyhow::Result<()>;
    /// Restores the recorded enabled setting of one component.
    fn restore_component(
        &mut self,
        user: u32,
        component: &str,
        state: ComponentState,
    ) -> anyhow::Result<RestoreOutcome>;
    /// Sets one app op of `package`.
    fn set_appop(&mut self, user: u32, package: &str, op: &str, mode: &str) -> anyhow::Result<()>;
    /// Sets the standby bucket of `package`.
    fn set_standby_bucket(&mut self, user: u32, package: &str, bucket: &str) -> anyhow::Result<()>;
}

/// What a restore command reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The previous setting is back.
    Restored,
    /// The component no longer exists in the package manifest.
    UnknownComponent,
}

/// [`Ops`] backed by the device's `cmd`, `pm`, `am`, and `dumpsys` binaries.
pub struct AndroidOps;

impl Ops for AndroidOps {
    fn receivers(
        &mut self,
        user: u32,
        action: &str,
        filter: ReceiverFilter,
    ) -> anyhow::Result<Vec<String>> {
        let output = query_receivers(user, action, filter)?;
        Ok(parse_receivers(&output))
    }

    fn component_states(
        &mut self,
        user: u32,
        package: &str,
    ) -> anyhow::Result<HashMap<String, ComponentState>> {
        let output = run("/system/bin/dumpsys", &["package", package])?;
        Ok(parse_component_states(&output, user, package))
    }

    fn appop(&mut self, user: u32, package: &str, op: &str) -> anyhow::Result<String> {
        let user = user.to_string();
        let output = run(CMD, &["appops", "get", "--user", &user, package, op])?;
        parse_appop(&output, op)
    }

    fn standby_bucket(&mut self, user: u32, package: &str) -> anyhow::Result<String> {
        let user = user.to_string();
        let output = run(AM, &["get-standby-bucket", "--user", &user, package])?;
        parse_standby_bucket(&output)
    }

    fn disable_component(&mut self, user: u32, component: &str) -> anyhow::Result<()> {
        let user = user.to_string();
        run(PM, &["disable", "--user", &user, component]).map(|_| ())
    }

    fn restore_component(
        &mut self,
        user: u32,
        component: &str,
        state: ComponentState,
    ) -> anyhow::Result<RestoreOutcome> {
        let user = user.to_string();
        let action = match state {
            ComponentState::Default => "default-state",
            ComponentState::Enabled => "enable",
            ComponentState::Disabled | ComponentState::DisabledUser => "disable-user",
            ComponentState::DisabledUntilUsed => "disable-until-used",
        };
        let output = run_output(PM, &[action, "--user", &user, component])?;
        if output.status.success() {
            return Ok(RestoreOutcome::Restored);
        }
        let message = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        // pm reports a component dropped from the manifest as
        // IllegalArgumentException("Unknown component: ..."); nothing is left to restore.
        if message.contains("Unknown component") {
            return Ok(RestoreOutcome::UnknownComponent);
        }
        bail!(
            "{PM} {action} --user {user} {component} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    fn set_appop(&mut self, user: u32, package: &str, op: &str, mode: &str) -> anyhow::Result<()> {
        let user = user.to_string();
        run(CMD, &["appops", "set", "--user", &user, package, op, mode]).map(|_| ())
    }

    fn set_standby_bucket(&mut self, user: u32, package: &str, bucket: &str) -> anyhow::Result<()> {
        let user = user.to_string();
        run(
            AM,
            &["set-standby-bucket", "--user", &user, package, bucket],
        )
        .map(|_| ())
    }
}

fn query_receivers(user: u32, action: &str, filter: ReceiverFilter) -> anyhow::Result<String> {
    let user = user.to_string();
    let flags = match filter {
        ReceiverFilter::Enabled => MATCH_DIRECT_BOOT,
        ReceiverFilter::IncludingDisabled => MATCH_DIRECT_BOOT | MATCH_DISABLED_COMPONENTS,
    }
    .to_string();
    run(
        CMD,
        &[
            "package",
            "query-receivers",
            "--brief",
            "--user",
            &user,
            "--query-flags",
            &flags,
            "-a",
            action,
        ],
    )
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = run_output(program, args)?;
    ensure!(
        output.status.success(),
        "{program} {} exited with {}: {}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_output(program: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let mut command = Command::new(program);
    command.args(args);
    command::output(&mut command, TIMEOUT)
        .with_context(|| format!("failed to run {program} {}", args.join(" ")))
}

/// Maps a configured standby bucket name to the integer `am` uses.
pub fn standby_bucket_id(name: &str) -> Option<u32> {
    match name {
        "active" => Some(10),
        "working_set" => Some(20),
        "frequent" => Some(30),
        "rare" => Some(40),
        "restricted" => Some(45),
        _ => None,
    }
}
