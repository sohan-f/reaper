//! The epoll loop and the handlers for its four event sources.

use std::{
    os::fd::{AsRawFd, RawFd},
    path::Path,
    time::Duration,
};

use anyhow::{Context, bail};
use aya::maps::{MapData, RingBuf};
use log::{error, info, warn};
use reaper_common::Event;

use crate::{
    daemon::Daemon,
    deny::{DenyMapMut, deny_params},
    paths::{ARMED_FILE, PACKAGES_LIST},
    sys,
    uidmap::UidMap,
};

const RING_TAG: u64 = 1;
const TIMER_TAG: u64 = 2;
const INOTIFY_TAG: u64 = 3;
const SIGNAL_TAG: u64 = 4;

/// The RING buffer as seen from userspace.
pub type RingMut<'a> = RingBuf<&'a mut MapData>;

/// Descriptors registered with the epoll instance.
pub struct Fds {
    /// epoll instance the loop blocks on.
    pub epoll: RawFd,
    /// `CLOCK_BOOTTIME` timer holding the next pending deadline.
    pub timer: RawFd,
    /// inotify instance watching the policy directory and packages.list.
    pub inotify: RawFd,
    /// signalfd for the daemon's control signals.
    pub signal: RawFd,
    /// Watch descriptor for the policy directory.
    pub reaper_wd: RawFd,
    /// Watch descriptor for `/data/system`, absent when it cannot be watched.
    pub system_wd: Option<RawFd>,
}

impl Fds {
    /// Creates the descriptors and registers them with epoll.
    ///
    /// # Errors
    ///
    /// Returns an error if a descriptor cannot be created or registered.
    pub fn open(ring: &RingMut<'_>) -> anyhow::Result<Self> {
        let inotify = sys::inotify_create().context("inotify_init1 failed")?;
        let reaper_wd = sys::inotify_add(
            inotify,
            c"/data/adb/reaper",
            libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_DELETE | libc::IN_CREATE,
        )
        .with_context(|| format!("inotify_add_watch on {} failed", crate::paths::REAPER_DIR))?;
        let system_wd = sys::inotify_add(
            inotify,
            c"/data/system",
            libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO,
        )
        .ok();
        if system_wd.is_none() {
            warn!(
                "cannot watch /data/system for packages.list; package changes need SIGHUP to reload"
            );
        }
        let signal = sys::signal_fd(&[libc::SIGHUP, libc::SIGTERM, libc::SIGUSR1, libc::SIGUSR2])
            .context("signalfd failed")?;
        let timer = sys::timer_create().context("timerfd_create failed")?;
        let epoll = sys::epoll_create().context("epoll_create1 failed")?;
        watch(epoll, ring.as_raw_fd(), RING_TAG)?;
        watch(epoll, timer, TIMER_TAG)?;
        watch(epoll, inotify, INOTIFY_TAG)?;
        watch(epoll, signal, SIGNAL_TAG)?;
        Ok(Self {
            epoll,
            timer,
            inotify,
            signal,
            reaper_wd,
            system_wd,
        })
    }
}

fn watch(epoll: RawFd, fd: RawFd, tag: u64) -> anyhow::Result<()> {
    sys::epoll_add(epoll, fd, tag).with_context(|| format!("epoll_ctl(ADD, fd={fd}) failed"))?;
    Ok(())
}

/// Arms `fd` for the next deadline, or disarms it when `deadline_ns` is `None`.
///
/// # Errors
///
/// Returns an error if the timer cannot be armed.
pub fn rearm_timer(fd: RawFd, deadline_ns: Option<u64>) -> anyhow::Result<()> {
    let rel = deadline_ns.map(|d| Duration::from_nanos(d.saturating_sub(sys::boottime_ns())));
    sys::timer_arm(fd, rel).context("timerfd_settime failed")?;
    Ok(())
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
        pad: ne_u32(bytes, 12)?,
        ts_ns: u64::from_ne_bytes(bytes.get(16..24)?.try_into().ok()?),
    })
}

fn inotify_header(bytes: &[u8], offset: usize) -> Option<(i32, u32, usize)> {
    let wd = ne_u32(bytes, offset)?.cast_signed();
    let mask = ne_u32(bytes, offset + 4)?;
    let len = ne_u32(bytes, offset + 12)? as usize;
    Some((wd, mask, len))
}

/// Runs the loop until SIGTERM.
///
/// # Errors
///
/// Returns an error if epoll fails or a timer cannot be re-armed.
pub fn run(
    daemon: &mut Daemon,
    deny_map: &mut DenyMapMut<'_>,
    ring: &mut RingMut<'_>,
    fds: &Fds,
) -> anyhow::Result<()> {
    // boot-completed.sh creates the marker before starting the daemon, so the
    // inotify transition is not observed on a normal boot.
    if daemon.armed {
        daemon.sweep();
        rearm_timer(fds.timer, daemon.pending.earliest())?;
    }
    info!(
        "watching nominations; armed={}; blocking in epoll_wait",
        daemon.armed
    );

    let mut tags = [0u64; 16];
    loop {
        let n = match sys::epoll_wait(fds.epoll, &mut tags) {
            Ok(n) => n,
            Err(err) if err.raw_os_error() == Some(libc::EINTR) => continue,
            Err(err) => {
                error!("epoll_wait failed: {err}");
                bail!("epoll_wait: {err}");
            }
        };
        for tag in tags.iter().take(n) {
            if !dispatch(*tag, daemon, deny_map, ring, fds)? {
                return Ok(());
            }
        }
    }
}

fn dispatch(
    tag: u64,
    daemon: &mut Daemon,
    deny_map: &mut DenyMapMut<'_>,
    ring: &mut RingMut<'_>,
    fds: &Fds,
) -> anyhow::Result<bool> {
    match tag {
        RING_TAG => handle_ring(daemon, ring, fds)?,
        TIMER_TAG => handle_timer(daemon, fds)?,
        INOTIFY_TAG => handle_inotify(daemon, deny_map, fds)?,
        SIGNAL_TAG => return handle_signal(daemon, deny_map, fds),
        other => warn!("unknown epoll tag {other}"),
    }
    Ok(true)
}

fn handle_ring(daemon: &mut Daemon, ring: &mut RingMut<'_>, fds: &Fds) -> anyhow::Result<()> {
    while let Some(item) = ring.next() {
        match parse_event(&item) {
            Some(ev) => queue_nomination(daemon, &ev, fds.timer)?,
            None => warn!("malformed ring buffer event (len {})", item.len()),
        }
    }
    Ok(())
}

fn queue_nomination(daemon: &mut Daemon, ev: &Event, timer: RawFd) -> anyhow::Result<()> {
    daemon.nominations += 1;
    let user = ev.uid / 100_000;
    let appid = ev.uid % 100_000;
    let now = sys::boottime_ns();
    let Some((grace_ms, _)) = deny_params(&daemon.deny, appid) else {
        info!("dropping nomination for user {user} appid {appid}: no longer denied");
        return Ok(());
    };
    let grace_ms = daemon.respawn.effective_grace(ev.uid, grace_ms, now);
    let deadline = now.saturating_add(grace_ms.saturating_mul(1_000_000));
    if daemon.pending.insert(user, appid, deadline) {
        info!(
            "pending user {user} appid {appid} adj {} in {} ms",
            ev.adj, grace_ms
        );
    }
    rearm_timer(timer, daemon.pending.earliest())
}

fn handle_timer(daemon: &mut Daemon, fds: &Fds) -> anyhow::Result<()> {
    if let Err(err) = sys::read_u64(fds.timer) {
        warn!("timerfd read failed: {err}");
    }
    let now = sys::boottime_ns();
    let due = daemon.pending.pop_due(now);
    for (user, appid) in due {
        daemon.decide_and_log(user, appid);
    }
    rearm_timer(fds.timer, daemon.pending.earliest())
}

fn handle_inotify(
    daemon: &mut Daemon,
    deny_map: &mut DenyMapMut<'_>,
    fds: &Fds,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    match sys::read_bytes(fds.inotify, &mut buf) {
        Ok(0) => {}
        Err(err) => warn!("inotify read failed: {err}"),
        Ok(read_len) => handle_inotify_events(daemon, deny_map, fds, &buf[..read_len])?,
    }
    Ok(())
}

fn handle_inotify_events(
    daemon: &mut Daemon,
    deny_map: &mut DenyMapMut<'_>,
    fds: &Fds,
    read: &[u8],
) -> anyhow::Result<()> {
    let mut offset = 0usize;
    while offset + 16 <= read.len() {
        let Some((wd, mask, len)) = inotify_header(read, offset) else {
            break;
        };
        let name_start = offset + 16;
        let name_end = (name_start + len).min(read.len());
        let name = String::from_utf8_lossy(&read[name_start..name_end]);
        let event = InotifyEvent {
            wd,
            mask,
            name: name.trim_end_matches('\0'),
        };
        handle_inotify_name(daemon, deny_map, fds, &event)?;
        offset = name_start + len;
    }
    Ok(())
}

/// One parsed inotify event, tagged with the watch descriptor that reported it.
struct InotifyEvent<'a> {
    wd: i32,
    mask: u32,
    name: &'a str,
}

fn handle_inotify_name(
    daemon: &mut Daemon,
    deny_map: &mut DenyMapMut<'_>,
    fds: &Fds,
    event: &InotifyEvent<'_>,
) -> anyhow::Result<()> {
    if event.wd == fds.reaper_wd {
        return handle_reaper_file(daemon, deny_map, fds, event);
    }
    if Some(event.wd) == fds.system_wd {
        handle_packages_list(daemon, deny_map, event);
    }
    Ok(())
}

fn handle_reaper_file(
    daemon: &mut Daemon,
    deny_map: &mut DenyMapMut<'_>,
    fds: &Fds,
    event: &InotifyEvent<'_>,
) -> anyhow::Result<()> {
    match event.name {
        "armed" => handle_armed(daemon, fds)?,
        "disable" => info!("kill-switch marker changed"),
        "panic" => info!("panic marker changed"),
        "policy.toml" if event.mask & (libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO) != 0 => {
            if let Err(err) = daemon.reload_policy(deny_map) {
                error!("policy reload failed: {err:#}");
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_armed(daemon: &mut Daemon, fds: &Fds) -> anyhow::Result<()> {
    let armed = Path::new(ARMED_FILE).exists();
    if armed && !daemon.armed {
        daemon.armed = true;
        info!("armed; enforcing");
        daemon.sweep();
        rearm_timer(fds.timer, daemon.pending.earliest())?;
        daemon.reconcile_layer1();
    } else if !armed && daemon.armed {
        daemon.armed = false;
        info!("disarmed");
    }
    Ok(())
}

fn handle_packages_list(
    daemon: &mut Daemon,
    deny_map: &mut DenyMapMut<'_>,
    event: &InotifyEvent<'_>,
) {
    if event.name != "packages.list" || event.mask & (libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO) == 0
    {
        return;
    }
    match UidMap::load(Path::new(PACKAGES_LIST)) {
        Ok(map) => {
            info!("uid map rebuilt: {} packages", map.package_count());
            daemon.uid_map = map;
            daemon.uid_map_ready = true;
            daemon.rebuild_deny(deny_map);
            daemon.reconcile_layer1();
        }
        Err(err) => {
            error!("failed to rebuild uid map: {err:#}");
            daemon.uid_map_ready = false;
        }
    }
}

fn handle_signal(
    daemon: &mut Daemon,
    deny_map: &mut DenyMapMut<'_>,
    fds: &Fds,
) -> anyhow::Result<bool> {
    match sys::read_signal(fds.signal) {
        Ok(Some(libc::SIGHUP)) => {
            if let Err(err) = daemon.reload_policy(deny_map) {
                error!("policy reload failed: {err:#}");
            }
        }
        Ok(Some(libc::SIGTERM)) => {
            info!("SIGTERM received; exiting");
            return Ok(false);
        }
        Ok(Some(libc::SIGUSR1)) => {
            daemon.armed = true;
            info!("SIGUSR1: armed; enforcing");
            daemon.sweep();
            rearm_timer(fds.timer, daemon.pending.earliest())?;
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
    }
    Ok(true)
}
