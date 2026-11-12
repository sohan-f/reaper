//! reaperd: background-app enforcer daemon.
//!
//! Loads the reaper eBPF program, injects the kernel struct offsets resolved
//! from the device BTF, and drains adj events from the ring buffer through an
//! epoll loop. A backgrounded denied app is force-stopped in enforce mode and
//! logged in observe mode.

mod btf;
mod command;
mod decide;
mod enforce;
mod layer1;
mod never_kill;
mod pending;
mod policy;
mod uidmap;

use std::{
    collections::{HashMap, HashSet},
    os::fd::AsRawFd,
    os::unix::io::RawFd,
    path::{Path, PathBuf},
    process,
};

use anyhow::{Context, bail, ensure};
use aya::{
    EbpfLoader, Endianness,
    maps::{HashMap as BpfHashMap, RingBuf},
    programs::BtfTracePoint,
};
use log::{error, info, warn};
use reaper_common::{DenyCfg, Event};

use crate::decide::Decision;
use crate::enforce::{KillBudget, RespawnGuard};
use crate::pending::Pending;
use crate::policy::{Mode, Policy};
use crate::uidmap::UidMap;

const DEFAULT_BPF_OBJECT: &str = "/data/adb/modules/ksu-reaper/bin/reaper-ebpf.o";
const DEFAULT_BTF: &str = "/sys/kernel/btf/vmlinux";
const DEFAULT_POLICY: &str = "/data/adb/reaper/policy.toml";
const PACKAGES_LIST: &str = "/data/system/packages.list";
const REAPER_DIR: &str = "/data/adb/reaper";
const ARMED_FILE: &str = "/data/adb/reaper/armed";
const DISABLE_FILE: &str = "/data/adb/reaper/disable";
const PANIC_FILE: &str = "/data/adb/reaper/panic";
const BUDGET_FILE: &str = "/data/adb/reaper/budget-exceeded";
const LAYER1_JOURNAL: &str = "/data/adb/reaper/layer1-journal.toml";

struct Config {
    bpf_object: PathBuf,
    btf: PathBuf,
    policy: PathBuf,
    deny_overrides: Vec<(u32, i16)>,
    restore_layer1: bool,
}

struct DenyEntry {
    appid: u32,
    keep_adj: i16,
    grace_ms: u64,
}

struct Daemon {
    pending: Pending,
    policy: Policy,
    policy_path: PathBuf,
    deny_overrides: Vec<(u32, i16)>,
    uid_map: UidMap,
    deny: Vec<DenyEntry>,
    builtin_never_kill: Vec<String>,
    budget: KillBudget,
    respawn: RespawnGuard,
    budget_reported: bool,
    armed: bool,
    policy_ready: bool,
    uid_map_ready: bool,
    nominations: u64,
    would_stop: u64,
    stops: u64,
}

type DenyMapMut<'a> = BpfHashMap<&'a mut aya::maps::MapData, u32, DenyCfg>;

fn print_usage() {
    eprintln!(
        "usage: reaperd [--bpf-object PATH] [--btf PATH] [--policy PATH] [--deny APPID[:KEEP_ADJ]]... [--restore-layer1]
  --bpf-object PATH  eBPF object to load (default: {DEFAULT_BPF_OBJECT}, env REAPER_BPF_OBJECT)
  --btf PATH         vmlinux BTF (default: {DEFAULT_BTF})
  --policy PATH      policy file (default: {DEFAULT_POLICY})
  --deny APPID[:KEEP_ADJ]
                     additional deny entries; appid must be 10000..=19999
  --restore-layer1   restore journaled Layer 1 state and exit; needs no policy or kernel"
    );
}

fn parse_args() -> anyhow::Result<Config> {
    let mut cfg = Config {
        bpf_object: std::env::var_os("REAPER_BPF_OBJECT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BPF_OBJECT)),
        btf: PathBuf::from(DEFAULT_BTF),
        policy: PathBuf::from(DEFAULT_POLICY),
        deny_overrides: Vec::new(),
        restore_layer1: false,
    };

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bpf-object" => {
                cfg.bpf_object = PathBuf::from(args.next().context("--bpf-object needs a path")?)
            }
            "--btf" => cfg.btf = PathBuf::from(args.next().context("--btf needs a path")?),
            "--policy" => cfg.policy = PathBuf::from(args.next().context("--policy needs a path")?),
            "--deny" => {
                let spec = args.next().context("--deny needs APPID[:KEEP_ADJ]")?;
                cfg.deny_overrides.push(parse_deny(&spec)?);
            }
            "--restore-layer1" => cfg.restore_layer1 = true,
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            other => bail!("unknown argument {other:?} (see --help)"),
        }
    }
    Ok(cfg)
}

fn parse_deny(spec: &str) -> anyhow::Result<(u32, i16)> {
    let (appid, keep_adj) = match spec.split_once(':') {
        Some((a, k)) => (
            a.parse()
                .with_context(|| format!("invalid appid in {spec:?}"))?,
            k.parse()
                .with_context(|| format!("invalid keep_adj in {spec:?}"))?,
        ),
        None => (
            spec.parse()
                .with_context(|| format!("invalid appid in {spec:?}"))?,
            100,
        ),
    };
    if !(crate::policy::APPID_START..=crate::policy::APPID_END).contains(&appid) {
        bail!(
            "appid {appid} outside {}..={}",
            crate::policy::APPID_START,
            crate::policy::APPID_END
        );
    }
    Ok((appid, keep_adj))
}

fn init_logging() {
    let level = std::env::var("REAPER_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(log::LevelFilter::Info);

    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(level)
            .with_tag("reaperd"),
    );

    #[cfg(not(target_os = "android"))]
    {
        use std::io::Write as _;
        struct StderrLogger;
        impl log::Log for StderrLogger {
            fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
                true
            }
            fn log(&self, record: &log::Record<'_>) {
                let _ = writeln!(
                    std::io::stderr(),
                    "reaperd [{}] {}",
                    record.level(),
                    record.args()
                );
            }
            fn flush(&self) {}
        }
        static LOGGER: StderrLogger = StderrLogger;
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(level);
    }
}

fn parse_event(bytes: &[u8]) -> Option<Event> {
    let word = |i: usize| {
        bytes
            .get(i..i + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_ne_bytes)
    };
    Some(Event {
        uid: word(0)?,
        tgid: word(4)?,
        adj: i32::from_ne_bytes(bytes.get(8..12)?.try_into().ok()?),
        _pad: word(12)?,
        ts_ns: u64::from_ne_bytes(bytes.get(16..24)?.try_into().ok()?),
    })
}

fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a writable timespec and CLOCK_BOOTTIME is always supported.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn rearm_timer(fd: RawFd, deadline_ns: Option<u64>) -> anyhow::Result<()> {
    let rel = deadline_ns.map(|d| d.saturating_sub(boottime_ns()));
    let mut its = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    if let Some(rel) = rel {
        its.it_value.tv_sec = (rel / 1_000_000_000) as libc::time_t;
        its.it_value.tv_nsec = (rel % 1_000_000_000) as libc::c_long;
        if its.it_value.tv_sec == 0 && its.it_value.tv_nsec == 0 {
            its.it_value.tv_nsec = 1_000_000;
        }
    }
    // SAFETY: fd is a valid timerfd created by this process; its is a valid itimerspec.
    let rc = unsafe { libc::timerfd_settime(fd, 0, &its, std::ptr::null_mut()) };
    ensure!(
        rc == 0,
        "timerfd_settime failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn install_deny_map(deny_map: &mut DenyMapMut<'_>, deny: &[DenyEntry]) -> anyhow::Result<()> {
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

fn build_deny(
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

fn deny_params(daemon: &Daemon, appid: u32) -> Option<(u64, i16)> {
    daemon
        .deny
        .iter()
        .find(|entry| entry.appid == appid)
        .map(|entry| (entry.grace_ms, entry.keep_adj))
}

fn never_kill_package<'a>(
    policy: &Policy,
    builtin: &[String],
    packages: &'a [String],
) -> Option<&'a str> {
    packages.iter().map(String::as_str).find(|package| {
        policy.never_kill.iter().any(|p| p == package) || builtin.iter().any(|p| p == package)
    })
}

fn trip_budget(daemon: &mut Daemon) {
    if daemon.budget_reported {
        return;
    }
    if let Err(err) = std::fs::write(BUDGET_FILE, b"kill budget exceeded\n") {
        error!("failed to write {BUDGET_FILE}: {err}");
        return;
    }
    daemon.budget_reported = true;
    error!("kill budget exceeded; switching to observe mode; marker {BUDGET_FILE}");
}

fn stop_reason() -> Option<&'static str> {
    if Path::new(DISABLE_FILE).exists() {
        Some("kill-switch marker present")
    } else if Path::new(PANIC_FILE).exists() {
        Some("panic marker present")
    } else {
        None
    }
}

fn layer1_apply_allowed(daemon: &Daemon) -> bool {
    daemon.armed
        && daemon.policy.mode == Mode::Enforce
        && !daemon.budget.tripped()
        && stop_reason().is_none()
}

fn reconcile_layer1(daemon: &Daemon) {
    if !daemon.policy_ready {
        warn!("Layer 1 skipped: policy is not loaded");
        return;
    }
    let uid_map = if daemon.uid_map_ready && !daemon.uid_map.is_empty() {
        Some(&daemon.uid_map)
    } else {
        None
    };
    let mut ops = layer1::AndroidOps;
    layer1::reconcile(
        &daemon.policy,
        &daemon.builtin_never_kill,
        uid_map,
        &mut ops,
        Path::new(LAYER1_JOURNAL),
        layer1_apply_allowed(daemon),
    );
}

fn decide_and_log(daemon: &mut Daemon, user: u32, appid: u32) {
    let owner_uid = user
        .checked_mul(100_000)
        .and_then(|base| base.checked_add(appid));
    let Some(owner_uid) = owner_uid else {
        warn!("invalid (user={user}, appid={appid}); dropping");
        return;
    };
    if let Some(package) = never_kill_package(
        &daemon.policy,
        &daemon.builtin_never_kill,
        daemon.uid_map.packages_of(appid),
    ) {
        info!("not enforcing user {user} appid {appid}: {package} is in never_kill");
        return;
    }
    let Some((grace_ms, keep_adj)) = deny_params(daemon, appid) else {
        info!("dropping pending user {user} appid {appid}: no longer denied");
        return;
    };

    if !daemon.armed {
        info!("pending expired for user {user} appid {appid} but daemon is not armed; dropping");
        return;
    }
    if let Some(reason) = stop_reason() {
        info!("not enforcing user {user} appid {appid}: {reason}");
        return;
    }

    let adj_values = decide::adj_values_of_uid(owner_uid);
    match decide::decide(&adj_values, keep_adj) {
        Decision::Gone => {
            info!("uid {owner_uid}: no live processes; app already gone");
        }
        Decision::Keep { min_adj } => {
            info!("uid {owner_uid}: keep (foreground/visible, min adj {min_adj})");
        }
        Decision::Background { min_adj } => {
            let now = boottime_ns();
            if layer1_apply_allowed(daemon) {
                let mut ops = layer1::AndroidOps;
                for package in daemon.uid_map.packages_of(appid) {
                    layer1::reapply_standby(
                        &daemon.policy,
                        &daemon.builtin_never_kill,
                        &mut ops,
                        Path::new(LAYER1_JOURNAL),
                        true,
                        user,
                        package,
                    );
                }
            }
            if daemon.policy.mode == Mode::Observe || daemon.budget.tripped() {
                let packages: Vec<&str> = daemon
                    .uid_map
                    .packages_of(appid)
                    .iter()
                    .map(String::as_str)
                    .collect();
                let mode = if daemon.budget.tripped() {
                    "observe (kill budget tripped)"
                } else {
                    "observe"
                };
                info!(
                    "{mode}: would force-stop user {user} uid {owner_uid} appid {appid} min_adj {min_adj} packages [{}]",
                    packages.join(",")
                );
                daemon.would_stop += 1;
                return;
            }
            let packages: Vec<String> = daemon.uid_map.packages_of(appid).to_vec();
            if packages.is_empty() {
                warn!("uid {owner_uid}: backgrounded but no package name; cannot force-stop");
                return;
            }
            if !daemon.budget.allow_kill(now) {
                trip_budget(daemon);
                return;
            }
            if daemon.respawn.tripped(owner_uid, now) {
                daemon.respawn.back_off(owner_uid, now);
                let backoff_grace = daemon.respawn.effective_grace(owner_uid, grace_ms, now);
                warn!(
                    "respawn guard: uid {owner_uid} hit {} kills in {} s; backing off to {backoff_grace} ms grace",
                    daemon.policy.respawn_max, daemon.policy.respawn_window_s
                );
                if layer1_apply_allowed(daemon) {
                    let mut ops = layer1::AndroidOps;
                    for package in &packages {
                        layer1::reapply_package(
                            &daemon.policy,
                            &daemon.builtin_never_kill,
                            &daemon.uid_map,
                            &mut ops,
                            Path::new(LAYER1_JOURNAL),
                            true,
                            package,
                        );
                    }
                }
            }
            let mut stopped = false;
            for package in &packages {
                if let Some(reason) = stop_reason() {
                    info!("stopping force-stop loop: {reason}");
                    break;
                }
                match enforce::force_stop(user, package) {
                    Ok(()) => {
                        info!(
                            "force-stopped user {user} uid {owner_uid} appid {appid} package {package}"
                        );
                        stopped = true;
                    }
                    Err(err) => {
                        error!("force-stop user {user} package {package} failed: {err:#}");
                    }
                }
            }
            if stopped {
                daemon.stops += 1;
                daemon.budget.record_kill(now);
                daemon.respawn.record_kill(owner_uid, now);
            }
        }
    }
}

fn sweep(daemon: &mut Daemon) {
    let mut inserted = 0u32;
    let Ok(uid_dirs) = std::fs::read_dir("/sys/fs/cgroup/apps") else {
        warn!("sweep: /sys/fs/cgroup/apps unreadable");
        return;
    };
    let uid_dirs: Vec<u32> = uid_dirs
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("uid_"))?
                .parse::<u32>()
                .ok()
        })
        .collect();
    for entry in &daemon.deny {
        for &uid in &uid_dirs {
            if uid % 100_000 != entry.appid {
                continue;
            }
            let user = uid / 100_000;
            let adj_values = decide::adj_values_of_uid(uid);
            if let Decision::Background { min_adj } = decide::decide(&adj_values, entry.keep_adj) {
                let now = boottime_ns();
                let grace_ms = daemon.respawn.effective_grace(uid, entry.grace_ms, now);
                let deadline = now.saturating_add(grace_ms.saturating_mul(1_000_000));
                if daemon.pending.insert(user, entry.appid, deadline) {
                    inserted += 1;
                }
                info!("sweep: uid {uid} backgrounded (min adj {min_adj}); pending");
            }
        }
    }
    info!("sweep done: {inserted} pending");
}

fn rebuild_deny(daemon: &mut Daemon, deny_map: &mut DenyMapMut<'_>) {
    refresh_never_kill(daemon);
    daemon.deny = build_deny(
        &daemon.policy,
        &daemon.builtin_never_kill,
        &daemon.uid_map,
        &daemon.deny_overrides,
    );
    let appids: HashSet<u32> = daemon.deny.iter().map(|entry| entry.appid).collect();
    daemon.pending.retain_appids(&appids);
    if let Err(err) = install_deny_map(deny_map, &daemon.deny) {
        error!("failed to update DENY map: {err:#}");
    }
}

fn refresh_never_kill(daemon: &mut Daemon) {
    let mut users = daemon.uid_map.users();
    if users.is_empty() {
        users.push(0);
    }
    extend_never_kill(&mut daemon.builtin_never_kill, &users);
}

// A role lookup can fail while packages.list is being rewritten, so the set
// only grows: dropping a launcher or dialer from a safety list would let
// Layer 2 kill it.
fn extend_never_kill(packages: &mut Vec<String>, users: &[u32]) {
    packages.extend(never_kill::resolve(users));
    packages.sort();
    packages.dedup();
}

fn reload_policy(daemon: &mut Daemon, deny_map: &mut DenyMapMut<'_>) -> anyhow::Result<()> {
    let policy = Policy::load(&daemon.policy_path).context("failed to reload policy")?;
    daemon.budget.set_limit(policy.kill_budget_per_min);
    daemon
        .respawn
        .set_limits(policy.respawn_window_s, policy.respawn_max);
    daemon.policy = policy;
    daemon.policy_ready = true;
    match UidMap::load(Path::new(PACKAGES_LIST)) {
        Ok(map) => {
            daemon.uid_map = map;
            daemon.uid_map_ready = true;
        }
        Err(err) => {
            warn!("uid map rebuild failed on policy reload: {err:#}");
            daemon.uid_map = UidMap::empty();
            daemon.uid_map_ready = false;
        }
    }
    rebuild_deny(daemon, deny_map);
    info!("policy reloaded: {} deny entries", daemon.deny.len());
    reconcile_layer1(daemon);
    Ok(())
}

fn run() -> anyhow::Result<()> {
    let cfg = parse_args()?;
    if cfg.restore_layer1 {
        let mut ops = layer1::AndroidOps;
        layer1::restore_all(Path::new(LAYER1_JOURNAL), &mut ops)
            .context("failed to restore Layer 1 state")?;
        info!("Layer 1 state restored");
        return Ok(());
    }

    let btf_bytes =
        std::fs::read(&cfg.btf).with_context(|| format!("failed to read {}", cfg.btf.display()))?;
    let layout = btf::resolve_layout(&btf_bytes)
        .context("failed to resolve struct offsets from vmlinux BTF")?;
    info!(
        "resolved offsets from vmlinux BTF: tgid={} signal={} real_cred={} cred_uid={} sig_oom_adj={}",
        layout.tgid, layout.signal, layout.real_cred, layout.cred_uid, layout.sig_oom_adj,
    );

    let object = std::fs::read(&cfg.bpf_object)
        .with_context(|| format!("failed to read {}", cfg.bpf_object.display()))?;
    let mut loader = EbpfLoader::new();
    loader
        .override_global("OFF_TGID", &layout.tgid, true)
        .override_global("OFF_SIGNAL", &layout.signal, true)
        .override_global("OFF_REAL_CRED", &layout.real_cred, true)
        .override_global("OFF_CRED_UID", &layout.cred_uid, true)
        .override_global("OFF_SIG_OOM_ADJ", &layout.sig_oom_adj, true);
    let mut bpf = loader
        .load(&object)
        .context("failed to load reaper eBPF object")?;

    let vmlinux = aya::Btf::parse(&btf_bytes, Endianness::Little)
        .context("failed to parse vmlinux BTF for attach")?;
    let program: &mut BtfTracePoint = bpf
        .program_mut("oom_score_adj_update")
        .context("program oom_score_adj_update not found in object")?
        .try_into()
        .context("program oom_score_adj_update is not a BTF tracepoint")?;
    program
        .load("oom_score_adj_update", &vmlinux)
        .context("failed to load BTF tracepoint program")?;
    program
        .attach()
        .context("failed to attach to tp_btf/oom_score_adj_update")?;

    let _ = std::fs::create_dir_all(REAPER_DIR);

    let policy_result = Policy::load(&cfg.policy);
    let policy_ready = policy_result.is_ok();
    let policy = match policy_result {
        Ok(policy) => policy,
        Err(err) => {
            error!(
                "failed to load {}: {err:#}; continuing with observe defaults",
                cfg.policy.display()
            );
            Policy::default()
        }
    };
    let uid_map_result = UidMap::load(Path::new(PACKAGES_LIST));
    let uid_map_ready = uid_map_result.is_ok();
    let uid_map = match uid_map_result {
        Ok(map) => map,
        Err(err) => {
            warn!("failed to build uid map: {err:#}");
            UidMap::empty()
        }
    };
    let mut users = uid_map.users();
    if users.is_empty() {
        users.push(0);
    }
    let builtin_never_kill = never_kill::resolve(&users);
    let deny = build_deny(&policy, &builtin_never_kill, &uid_map, &cfg.deny_overrides);
    let [deny_map_raw, ring_map] = bpf.maps_disjoint_mut(["DENY", "RING"]);
    let mut deny_map: DenyMapMut<'_> =
        BpfHashMap::try_from(deny_map_raw.context("DENY map not found in object")?)
            .context("DENY map has unexpected shape")?;
    install_deny_map(&mut deny_map, &deny)?;
    info!("populated DENY map with {} entries", deny.len());
    let mut ring = RingBuf::try_from(ring_map.context("RING map not found in object")?)
        .context("RING map is not a ring buffer")?;

    let armed = Path::new(ARMED_FILE).exists();
    let budget_tripped = Path::new(BUDGET_FILE).exists();
    if budget_tripped {
        warn!("{BUDGET_FILE} present; staying in observe mode");
    }
    let budget = KillBudget::new(policy.kill_budget_per_min, budget_tripped);
    let respawn = RespawnGuard::new(policy.respawn_window_s, policy.respawn_max);

    let mut daemon = Daemon {
        pending: Pending::default(),
        policy,
        policy_path: cfg.policy,
        deny_overrides: cfg.deny_overrides,
        uid_map,
        deny,
        builtin_never_kill,
        budget,
        respawn,
        budget_reported: budget_tripped,
        armed,
        policy_ready,
        uid_map_ready,
        nominations: 0,
        would_stop: 0,
        stops: 0,
    };

    if policy_ready && uid_map_ready {
        reconcile_layer1(&daemon);
    }

    // SAFETY: no preconditions; failure reported as -1 and checked.
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    ensure!(inotify_fd >= 0, "inotify_init1 failed");
    let reaper_wd = unsafe {
        // SAFETY: inotify_fd is valid; the path is a valid C string.
        libc::inotify_add_watch(
            inotify_fd,
            c"/data/adb/reaper".as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_DELETE | libc::IN_CREATE,
        )
    };
    ensure!(reaper_wd >= 0, "inotify_add_watch on {REAPER_DIR} failed");
    let system_wd = unsafe {
        // SAFETY: inotify_fd is valid; the path is a valid C string.
        libc::inotify_add_watch(
            inotify_fd,
            c"/data/system".as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO,
        )
    };
    if system_wd < 0 {
        warn!("cannot watch /data/system for packages.list; package changes need SIGHUP to reload");
    }

    // SAFETY: sigset_t is zero-initializable POD.
    let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: sigset points to a valid sigset_t.
    unsafe { libc::sigemptyset(&mut sigset) };
    for sig in [libc::SIGHUP, libc::SIGTERM, libc::SIGUSR1, libc::SIGUSR2] {
        // SAFETY: sigset is valid and sig is a valid signal number.
        unsafe { libc::sigaddset(&mut sigset, sig) };
    }
    // SAFETY: sigset is a valid sigset_t.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &sigset, std::ptr::null_mut()) };
    let signal_fd = unsafe {
        // SAFETY: signal_fd outlives the loop; flags are valid.
        libc::signalfd(-1, &sigset, libc::SFD_CLOEXEC)
    };
    ensure!(signal_fd >= 0, "signalfd failed");

    let timer_fd = unsafe {
        // SAFETY: CLOCK_BOOTTIME is supported on this kernel.
        libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_CLOEXEC)
    };
    ensure!(timer_fd >= 0, "timerfd_create failed");

    // SAFETY: no preconditions; failure reported as -1 and checked.
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    ensure!(epfd >= 0, "epoll_create1 failed");

    let watch = |fd: RawFd, tag: u64| -> anyhow::Result<()> {
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: tag,
        };
        // SAFETY: epfd and fd are valid open fds; event outlives the call.
        let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut event) };
        ensure!(
            rc == 0,
            "epoll_ctl(ADD, fd={fd}) failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    };
    watch(ring.as_raw_fd(), 1)?;
    watch(timer_fd, 2)?;
    watch(inotify_fd, 3)?;
    watch(signal_fd, 4)?;

    // boot-completed.sh creates the marker before starting the daemon, so the
    // inotify transition is not observed on a normal boot.
    if daemon.armed {
        sweep(&mut daemon);
        rearm_timer(timer_fd, daemon.pending.earliest())?;
    }

    info!(
        "watching nominations; armed={}; blocking in epoll_wait",
        daemon.armed
    );

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 16];
    loop {
        // SAFETY: events is a writable buffer of the reported size.
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, -1) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            error!("epoll_wait failed: {err}");
            bail!("epoll_wait: {err}");
        }
        for event in events.iter().take(n as usize) {
            match event.u64 {
                1 => {
                    while let Some(item) = ring.next() {
                        match parse_event(&item) {
                            Some(ev) => {
                                daemon.nominations += 1;
                                let user = ev.uid / 100_000;
                                let appid = ev.uid % 100_000;
                                let now = boottime_ns();
                                let Some((grace_ms, _)) = deny_params(&daemon, appid) else {
                                    info!(
                                        "dropping nomination for user {user} appid {appid}: no longer denied"
                                    );
                                    continue;
                                };
                                let grace_ms =
                                    daemon.respawn.effective_grace(ev.uid, grace_ms, now);
                                let deadline =
                                    now.saturating_add(grace_ms.saturating_mul(1_000_000));
                                if daemon.pending.insert(user, appid, deadline) {
                                    info!(
                                        "pending user {user} appid {appid} adj {} in {} ms",
                                        ev.adj, grace_ms
                                    );
                                }
                                rearm_timer(timer_fd, daemon.pending.earliest())?;
                            }
                            None => warn!("malformed ring buffer event (len {})", item.len()),
                        }
                    }
                }
                2 => {
                    let mut expirations: u64 = 0;
                    // SAFETY: expirations is a writable u64; timer_fd is valid.
                    let rc = unsafe {
                        libc::read(
                            timer_fd,
                            &mut expirations as *mut u64 as *mut libc::c_void,
                            8,
                        )
                    };
                    if rc != 8 {
                        warn!("timerfd read returned {rc}");
                    }
                    let now = boottime_ns();
                    let due = daemon.pending.pop_due(now);
                    for (user, appid) in due {
                        decide_and_log(&mut daemon, user, appid);
                    }
                    rearm_timer(timer_fd, daemon.pending.earliest())?;
                }
                3 => {
                    let mut buf = [0u8; 4096];
                    // SAFETY: buf is writable; inotify_fd is a valid nonblocking fd.
                    let rc = unsafe {
                        libc::read(inotify_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                    };
                    if rc > 0 {
                        let mut offset = 0usize;
                        while offset + 16 <= rc as usize {
                            let wd =
                                i32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap());
                            let mask =
                                u32::from_ne_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
                            let len = u32::from_ne_bytes(
                                buf[offset + 12..offset + 16].try_into().unwrap(),
                            ) as usize;
                            let name_start = offset + 16;
                            let name_end = (name_start + len).min(rc as usize);
                            let name = String::from_utf8_lossy(&buf[name_start..name_end]);
                            let name = name.trim_end_matches('\0').to_string();
                            if wd == reaper_wd {
                                if name == "armed" {
                                    let armed = Path::new(ARMED_FILE).exists();
                                    if armed && !daemon.armed {
                                        daemon.armed = true;
                                        info!("armed; enforcing");
                                        sweep(&mut daemon);
                                        rearm_timer(timer_fd, daemon.pending.earliest())?;
                                        reconcile_layer1(&daemon);
                                    } else if !armed && daemon.armed {
                                        daemon.armed = false;
                                        info!("disarmed");
                                    }
                                } else if name == "disable" {
                                    info!("kill-switch marker changed");
                                } else if name == "panic" {
                                    info!("panic marker changed");
                                } else if name == "policy.toml"
                                    && mask & (libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO) != 0
                                    && let Err(err) = reload_policy(&mut daemon, &mut deny_map)
                                {
                                    error!("policy reload failed: {err:#}");
                                }
                            } else if wd == system_wd
                                && name == "packages.list"
                                && mask & (libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO) != 0
                            {
                                match UidMap::load(Path::new(PACKAGES_LIST)) {
                                    Ok(map) => {
                                        info!("uid map rebuilt: {} packages", map.package_count());
                                        daemon.uid_map = map;
                                        daemon.uid_map_ready = true;
                                        rebuild_deny(&mut daemon, &mut deny_map);
                                        reconcile_layer1(&daemon);
                                    }
                                    Err(err) => {
                                        error!("failed to rebuild uid map: {err:#}");
                                        daemon.uid_map_ready = false;
                                    }
                                }
                            }
                            offset = name_start + len;
                        }
                    }
                }
                4 => {
                    // SAFETY: signalfd_siginfo is zero-initializable POD.
                    let mut siginfo: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
                    // SAFETY: siginfo is a valid signalfd_siginfo; signal_fd is valid.
                    let rc = unsafe {
                        libc::read(
                            signal_fd,
                            &mut siginfo as *mut _ as *mut libc::c_void,
                            std::mem::size_of::<libc::signalfd_siginfo>(),
                        )
                    };
                    if rc == std::mem::size_of::<libc::signalfd_siginfo>() as isize {
                        match siginfo.ssi_signo as i32 {
                            libc::SIGHUP => {
                                if let Err(err) = reload_policy(&mut daemon, &mut deny_map) {
                                    error!("policy reload failed: {err:#}");
                                }
                            }
                            libc::SIGTERM => {
                                info!("SIGTERM received; exiting");
                                return Ok(());
                            }
                            libc::SIGUSR1 => {
                                daemon.armed = true;
                                info!("SIGUSR1: armed; enforcing");
                                sweep(&mut daemon);
                                rearm_timer(timer_fd, daemon.pending.earliest())?;
                                reconcile_layer1(&daemon);
                            }
                            libc::SIGUSR2 => {
                                info!(
                                    "stats: nominations={} would_stop={} stops={} pending={} armed={} deny_entries={} budget_tripped={}",
                                    daemon.nominations,
                                    daemon.would_stop,
                                    daemon.stops,
                                    daemon.pending.len(),
                                    daemon.armed,
                                    daemon.deny.len(),
                                    daemon.budget.tripped(),
                                );
                            }
                            _ => {}
                        }
                    }
                }
                other => warn!("unknown epoll tag {other}"),
            }
        }
    }
}

fn main() {
    init_logging();
    if let Err(err) = run() {
        error!("{err:#}");
        process::exit(1);
    }
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
