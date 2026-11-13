//! The re-verify step: decide whether a nominated uid looks backgrounded.

use std::fs;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// No live processes; the app already went away.
    Gone,
    /// At least one process is at or below `keep_adj`; the app is foreground or visible.
    Keep { min_adj: i16 },
    /// Every live process is above `keep_adj`.
    Background { min_adj: i16 },
}

pub fn decide(adj_values: &[i16], keep_adj: i16) -> Decision {
    let Some(min) = adj_values.iter().min().copied() else {
        return Decision::Gone;
    };
    if min <= keep_adj {
        Decision::Keep { min_adj: min }
    } else {
        Decision::Background { min_adj: min }
    }
}

fn adj_of_pid(pid: u32) -> Option<i16> {
    fs::read_to_string(
        Path::new("/proc")
            .join(pid.to_string())
            .join("oom_score_adj"),
    )
    .ok()?
    .trim()
    .parse()
    .ok()
}

/// Lists the pids of a uid via the per-uid cgroup directory, falling back to
/// a /proc scan when the cgroup path does not exist or is unreadable.
pub fn pids_of_uid(uid: u32) -> Vec<u32> {
    let dir = format!("/sys/fs/cgroup/apps/uid_{uid}");
    match fs::read_dir(&dir) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                name.strip_prefix("pid_")?.parse::<u32>().ok()
            })
            .collect(),
        Err(_) => {
            let mut pids = Vec::new();
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                        continue;
                    };
                    if metadata_uid(&entry.path()) == Some(uid) {
                        pids.push(pid);
                    }
                }
            }
            pids
        }
    }
}

fn metadata_uid(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| m.uid())
}

pub fn adj_values_of_uid(uid: u32) -> Vec<i16> {
    pids_of_uid(uid)
        .into_iter()
        .filter_map(adj_of_pid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_processes_is_gone() {
        assert_eq!(decide(&[], 100), Decision::Gone);
    }

    #[test]
    fn helper_at_low_adj_keeps() {
        // main process cached at 925, but a foreground helper at 0 keeps it
        assert_eq!(decide(&[925, 0], 100), Decision::Keep { min_adj: 0 });
    }

    #[test]
    fn all_cached_is_background() {
        assert_eq!(
            decide(&[925, 945, 999], 100),
            Decision::Background { min_adj: 925 }
        );
    }

    #[test]
    fn visible_keeps() {
        // PiP / visible process at 100 with keep_adj=100: keep
        assert_eq!(decide(&[900, 100], 100), Decision::Keep { min_adj: 100 });
    }
}
