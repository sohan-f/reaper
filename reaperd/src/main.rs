//! reaperd: background-app enforcer daemon.
//!
//! Loads the reaper eBPF program, injects the kernel struct offsets resolved
//! from the device BTF, and drains adj events from the ring buffer through an
//! epoll loop. A backgrounded denied app is force-stopped in enforce mode and
//! logged in observe mode.

#![deny(unsafe_code)]

mod btf;
mod command;
mod config;
mod daemon;
mod decide;
mod enforce;
mod layer1;
mod never_kill;
mod paths;
mod pending;
mod policy;
mod sys;
mod uidmap;

use std::{os::fd::AsRawFd, os::unix::io::RawFd, path::Path, process, time::Duration};

use anyhow::{Context, bail};
use aya::{
    EbpfLoader, Endianness,
    maps::{HashMap as BpfHashMap, RingBuf},
    programs::BtfTracePoint,
};
use log::{error, info, warn};
use reaper_common::Event;

use crate::config::Config;
use crate::daemon::{Daemon, DenyMapMut, deny_params};
use crate::paths::{ARMED_FILE, LAYER1_JOURNAL, PACKAGES_LIST, REAPER_DIR};
use crate::uidmap::UidMap;

fn init_logging() {
    let level = std::env::var("REAPER_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(log::LevelFilter::Info);

    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(level)
                .with_tag("reaperd")
                // With an explicit tag android_logger prefixes the message with
                // the module path, so every line would repeat "reaperd".
                .format(|f, record| write!(f, "{}", record.args())),
        );
    }

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

fn ne_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_ne_bytes)
}

fn parse_event(bytes: &[u8]) -> Option<Event> {
    Some(Event {
        uid: ne_u32(bytes, 0)?,
        tgid: ne_u32(bytes, 4)?,
        adj: i32::from_ne_bytes(bytes.get(8..12)?.try_into().ok()?),
        _pad: ne_u32(bytes, 12)?,
        ts_ns: u64::from_ne_bytes(bytes.get(16..24)?.try_into().ok()?),
    })
}

fn inotify_header(bytes: &[u8], offset: usize) -> Option<(i32, u32, usize)> {
    let wd = ne_u32(bytes, offset)? as i32;
    let mask = ne_u32(bytes, offset + 4)?;
    let len = ne_u32(bytes, offset + 12)? as usize;
    Some((wd, mask, len))
}

fn rearm_timer(fd: RawFd, deadline_ns: Option<u64>) -> anyhow::Result<()> {
    let rel = deadline_ns.map(|d| Duration::from_nanos(d.saturating_sub(sys::boottime_ns())));
    sys::timer_arm(fd, rel).context("timerfd_settime failed")?;
    Ok(())
}

fn run() -> anyhow::Result<()> {
    let cfg = Config::parse()?;
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

    let [deny_map_raw, ring_map] = bpf.maps_disjoint_mut(["DENY", "RING"]);
    let mut deny_map: DenyMapMut<'_> =
        BpfHashMap::try_from(deny_map_raw.context("DENY map not found in object")?)
            .context("DENY map has unexpected shape")?;
    let mut ring = RingBuf::try_from(ring_map.context("RING map not found in object")?)
        .context("RING map is not a ring buffer")?;

    let mut daemon = Daemon::load(&cfg, &mut deny_map)?;
    if daemon.policy_ready && daemon.uid_map_ready {
        daemon.reconcile_layer1();
    }

    let inotify_fd = sys::inotify_create().context("inotify_init1 failed")?;
    let reaper_wd = sys::inotify_add(
        inotify_fd,
        c"/data/adb/reaper",
        libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_DELETE | libc::IN_CREATE,
    )
    .with_context(|| format!("inotify_add_watch on {REAPER_DIR} failed"))?;
    let system_wd = sys::inotify_add(
        inotify_fd,
        c"/data/system",
        libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO,
    )
    .ok();
    if system_wd.is_none() {
        warn!("cannot watch /data/system for packages.list; package changes need SIGHUP to reload");
    }

    let signal_fd = sys::signal_fd(&[libc::SIGHUP, libc::SIGTERM, libc::SIGUSR1, libc::SIGUSR2])
        .context("signalfd failed")?;

    let timer_fd = sys::timer_create().context("timerfd_create failed")?;

    let epfd = sys::epoll_create().context("epoll_create1 failed")?;

    let watch = |fd: RawFd, tag: u64| -> anyhow::Result<()> {
        sys::epoll_add(epfd, fd, tag).with_context(|| format!("epoll_ctl(ADD, fd={fd}) failed"))?;
        Ok(())
    };
    watch(ring.as_raw_fd(), 1)?;
    watch(timer_fd, 2)?;
    watch(inotify_fd, 3)?;
    watch(signal_fd, 4)?;

    // boot-completed.sh creates the marker before starting the daemon, so the
    // inotify transition is not observed on a normal boot.
    if daemon.armed {
        daemon.sweep();
        rearm_timer(timer_fd, daemon.pending.earliest())?;
    }

    info!(
        "watching nominations; armed={}; blocking in epoll_wait",
        daemon.armed
    );

    let mut tags = [0u64; 16];
    loop {
        let n = match sys::epoll_wait(epfd, &mut tags) {
            Ok(n) => n,
            Err(err) if err.raw_os_error() == Some(libc::EINTR) => continue,
            Err(err) => {
                error!("epoll_wait failed: {err}");
                bail!("epoll_wait: {err}");
            }
        };
        for tag in tags.iter().take(n) {
            match tag {
                1 => {
                    while let Some(item) = ring.next() {
                        match parse_event(&item) {
                            Some(ev) => {
                                daemon.nominations += 1;
                                let user = ev.uid / 100_000;
                                let appid = ev.uid % 100_000;
                                let now = sys::boottime_ns();
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
                    if let Err(err) = sys::read_u64(timer_fd) {
                        warn!("timerfd read failed: {err}");
                    }
                    let now = sys::boottime_ns();
                    let due = daemon.pending.pop_due(now);
                    for (user, appid) in due {
                        daemon.decide_and_log(user, appid);
                    }
                    rearm_timer(timer_fd, daemon.pending.earliest())?;
                }
                3 => {
                    let mut buf = [0u8; 4096];
                    match sys::read_bytes(inotify_fd, &mut buf) {
                        Ok(0) => {}
                        Err(err) => warn!("inotify read failed: {err}"),
                        Ok(read_len) => {
                            let read = &buf[..read_len];
                            let mut offset = 0usize;
                            while offset + 16 <= read.len() {
                                let Some((wd, mask, len)) = inotify_header(read, offset) else {
                                    break;
                                };
                                let name_start = offset + 16;
                                let name_end = (name_start + len).min(read.len());
                                let name = String::from_utf8_lossy(&read[name_start..name_end]);
                                let name = name.trim_end_matches('\0').to_string();
                                if wd == reaper_wd {
                                    if name == "armed" {
                                        let armed = Path::new(ARMED_FILE).exists();
                                        if armed && !daemon.armed {
                                            daemon.armed = true;
                                            info!("armed; enforcing");
                                            daemon.sweep();
                                            rearm_timer(timer_fd, daemon.pending.earliest())?;
                                            daemon.reconcile_layer1();
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
                                        && let Err(err) = daemon.reload_policy(&mut deny_map)
                                    {
                                        error!("policy reload failed: {err:#}");
                                    }
                                } else if Some(wd) == system_wd
                                    && name == "packages.list"
                                    && mask & (libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO) != 0
                                {
                                    match UidMap::load(Path::new(PACKAGES_LIST)) {
                                        Ok(map) => {
                                            info!(
                                                "uid map rebuilt: {} packages",
                                                map.package_count()
                                            );
                                            daemon.uid_map = map;
                                            daemon.uid_map_ready = true;
                                            daemon.rebuild_deny(&mut deny_map);
                                            daemon.reconcile_layer1();
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
                }
                4 => match sys::read_signal(signal_fd) {
                    Ok(Some(libc::SIGHUP)) => {
                        if let Err(err) = daemon.reload_policy(&mut deny_map) {
                            error!("policy reload failed: {err:#}");
                        }
                    }
                    Ok(Some(libc::SIGTERM)) => {
                        info!("SIGTERM received; exiting");
                        return Ok(());
                    }
                    Ok(Some(libc::SIGUSR1)) => {
                        daemon.armed = true;
                        info!("SIGUSR1: armed; enforcing");
                        daemon.sweep();
                        rearm_timer(timer_fd, daemon.pending.earliest())?;
                        daemon.reconcile_layer1();
                    }
                    Ok(Some(libc::SIGUSR2)) => {
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
                    Ok(Some(_) | None) => {}
                    Err(err) => warn!("signalfd read failed: {err}"),
                },
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
