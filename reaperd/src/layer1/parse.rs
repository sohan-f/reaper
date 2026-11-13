//! Parsers for the text output of `cmd`, `dumpsys`, and `am`.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, ensure};

use super::device::ComponentState;

/// Extracts the component names from `cmd package query-receivers --brief`.
pub fn parse_receivers(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut components = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.contains('=') || line.contains(char::is_whitespace) {
            continue;
        }
        if !line.contains('/') {
            continue;
        }
        if seen.insert(line.to_string()) {
            components.push(line.to_string());
        }
    }
    components
}

/// Extracts one user's component settings from `dumpsys package <pkg>`.
///
/// Keys are normalized to `pkg/fully.qualified.Class`, because the dump prints
/// the stored class name and the receiver query prints the manifest spelling.
pub fn parse_component_states(
    text: &str,
    user: u32,
    package: &str,
) -> HashMap<String, ComponentState> {
    let mut states = HashMap::new();
    let mut current_user = None;
    let mut list = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(parsed) = parse_user_header(trimmed) {
            current_user = Some(parsed);
            list = None;
            continue;
        }
        if current_user != Some(user) {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("disabledComponents:") {
            list = Some(ComponentState::Disabled);
            insert_inline_components(&mut states, rest, ComponentState::Disabled, package);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("enabledComponents:") {
            list = Some(ComponentState::Enabled);
            insert_inline_components(&mut states, rest, ComponentState::Enabled, package);
            continue;
        }

        let Some(state) = list else {
            continue;
        };
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains([':', '=']) || trimmed.contains(char::is_whitespace) {
            list = None;
            continue;
        }
        insert_component(&mut states, trimmed, state, package);
    }
    states
}

/// Canonical `package/fully.qualified.Class` form of a component name.
///
/// `query-receivers --brief` prints `pkg/.Class`, while dumpsys stores the
/// fully qualified class name alone. Both spellings must produce the same key,
/// otherwise the state lookup misses and a user's own disable is overwritten
/// with `pm default-state` on restore.
pub fn component_key(component: &str) -> String {
    let Some((package, class)) = component.split_once('/') else {
        return component.to_string();
    };
    let class = if let Some(relative) = class.strip_prefix('.') {
        format!("{package}.{relative}")
    } else if class.contains('.') {
        class.to_string()
    } else {
        format!("{package}.{class}")
    };
    format!("{package}/{class}")
}

fn insert_component(
    states: &mut HashMap<String, ComponentState>,
    component: &str,
    state: ComponentState,
    package: &str,
) {
    let component = if component.contains('/') {
        component.to_string()
    } else {
        format!("{package}/{component}")
    };
    let component = component_key(&component);
    let entry = states.entry(component).or_insert(state);
    if state == ComponentState::Disabled {
        *entry = state;
    }
}

fn parse_user_header(line: &str) -> Option<u32> {
    let rest = line.strip_prefix("User ")?;
    let (user, _) = rest.split_once(':')?;
    user.trim().parse().ok()
}

fn insert_inline_components(
    states: &mut HashMap<String, ComponentState>,
    rest: &str,
    state: ComponentState,
    package: &str,
) {
    for component in rest
        .split([',', ' '])
        .filter(|part| !part.is_empty() && !part.contains([':', '=']))
    {
        insert_component(states, component, state, package);
    }
}

/// Reads the mode of one app op from `cmd appops get`.
///
/// # Errors
///
/// Returns an error when the output has neither an entry for `op` nor a
/// `No operations.` line, which means the query itself was malformed.
pub fn parse_appop(text: &str, op: &str) -> anyhow::Result<String> {
    let prefix = format!("{op}:");
    let mut saw_default = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            let mode = rest
                .split([' ', ';', ','])
                .find(|part| !part.is_empty())
                .unwrap_or("");
            ensure!(!mode.is_empty(), "empty mode in appops output for {op}");
            return Ok(mode.to_string());
        }
        if trimmed.starts_with("No operations.") {
            saw_default = true;
        }
        if trimmed.starts_with("Default mode:") {
            return Ok("default".to_string());
        }
    }
    ensure!(
        saw_default,
        "appops output has no entry for {op}: {}",
        text.trim()
    );
    Ok("default".to_string())
}

/// Normalizes `am get-standby-bucket` output to the integer the setter takes.
///
/// # Errors
///
/// Returns an error if the output is not an integer.
pub fn parse_standby_bucket(text: &str) -> anyhow::Result<String> {
    let value = text.trim();
    let bucket: u32 = value
        .parse()
        .with_context(|| format!("standby bucket is not an integer: {value:?}"))?;
    Ok(bucket.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer1::device::standby_bucket_id;

    #[test]
    fn receiver_parser_skips_headers_and_priorities() {
        let text = "5 receivers found:\n  Receiver #0:\n    priority=0\n    com.example/.Boot\n  Receiver #1:\n    priority=0\n    com.other/.Boot\n";
        assert_eq!(
            parse_receivers(text),
            ["com.example/.Boot", "com.other/.Boot"]
        );
    }

    #[test]
    fn component_parser_reads_both_lists_per_user() {
        let text = "\
Packages:
  Package [com.example] (abc):
    User 0: ceDataInode=1 installed=true enabled=0
      gids=[3003]
      disabledComponents:
        com.example/.Boot
      enabledComponents:
        com.example/.Enabled
    User 10: ceDataInode=2 installed=true enabled=0
      disabledComponents:
        com.example/.Other
      enabledComponents:
";
        let user0 = parse_component_states(text, 0, "com.example");
        assert_eq!(
            user0.get(&component_key("com.example/.Boot")),
            Some(&ComponentState::Disabled)
        );
        assert_eq!(
            user0.get(&component_key("com.example/.Enabled")),
            Some(&ComponentState::Enabled)
        );
        assert_eq!(user0.get(&component_key("com.example/.Missing")), None);

        let profile_10 = parse_component_states(text, 10, "com.example");
        assert_eq!(
            profile_10.get(&component_key("com.example/.Other")),
            Some(&ComponentState::Disabled)
        );
        assert_eq!(profile_10.get(&component_key("com.example/.Boot")), None);
    }

    #[test]
    fn component_parser_accepts_inline_lists() {
        let text = "  User 0: enabled=0\n    disabledComponents: .One,com.example.Two\n";
        let states = parse_component_states(text, 0, "com.example");
        assert_eq!(
            states.get(&component_key("com.example/.One")),
            Some(&ComponentState::Disabled)
        );
        assert_eq!(
            states.get(&component_key("com.example/com.example.Two")),
            Some(&ComponentState::Disabled)
        );
    }

    #[test]
    fn component_parser_normalizes_bare_class_names() {
        let text = "\
  User 0: enabled=0
    disabledComponents:
      com.example.BootReceiver
    enabledComponents:
      .EnabledReceiver
";
        let states = parse_component_states(text, 0, "com.example");
        assert_eq!(
            states.get(&component_key("com.example/com.example.BootReceiver")),
            Some(&ComponentState::Disabled)
        );
        assert_eq!(
            states.get(&component_key("com.example/.EnabledReceiver")),
            Some(&ComponentState::Enabled)
        );
    }

    #[test]
    fn receiver_keys_match_every_component_spelling() {
        let expected = component_key("com.example/.BootReceiver");
        for spelling in [
            "com.example/.BootReceiver",
            "com.example/com.example.BootReceiver",
            "com.example/BootReceiver",
        ] {
            assert_eq!(component_key(spelling), expected, "{spelling}");
        }
        assert_eq!(expected, "com.example/com.example.BootReceiver");
    }

    #[test]
    fn appop_parser_reads_explicit_and_unset_ops() {
        assert_eq!(
            parse_appop("RUN_IN_BACKGROUND: ignore\n", "RUN_IN_BACKGROUND").expect("explicit"),
            "ignore"
        );
        assert_eq!(
            parse_appop("RUN_IN_BACKGROUND: ignore; time=+1s\n", "RUN_IN_BACKGROUND")
                .expect("explicit with metadata"),
            "ignore"
        );
        assert_eq!(
            parse_appop(
                "No operations.\n  Default mode: allow\n",
                "RUN_IN_BACKGROUND"
            )
            .expect("unset"),
            "default"
        );
        assert!(parse_appop("No operations.\n", "RUN_IN_BACKGROUND").is_ok());
        assert!(parse_appop("something else\n", "RUN_IN_BACKGROUND").is_err());
    }

    #[test]
    fn standby_parser_round_trips_integer() {
        assert_eq!(parse_standby_bucket("10\n").expect("active"), "10");
        assert_eq!(parse_standby_bucket("45").expect("restricted"), "45");
        assert!(parse_standby_bucket("restricted\n").is_err());
        assert_eq!(standby_bucket_id("restricted"), Some(45));
        assert_eq!(standby_bucket_id("cold"), None);
    }

    #[test]
    fn component_state_round_trips_journal_strings() {
        for state in [
            ComponentState::Default,
            ComponentState::Enabled,
            ComponentState::Disabled,
            ComponentState::DisabledUser,
            ComponentState::DisabledUntilUsed,
        ] {
            assert_eq!(ComponentState::parse(state.as_str()), Some(state));
        }
        assert_eq!(ComponentState::parse("bogus"), None);
    }
}
