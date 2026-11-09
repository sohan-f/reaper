//! reaperd: event-driven background-app enforcer daemon.
//!
//! Loads the reaper eBPF program, injects the struct offsets resolved from the
//! device BTF, and drains nominations from the ring buffer. Enforcement and
//! the epoll fd set beyond the ring buffer land in later milestones.

mod btf;

use std::{os::fd::AsRawFd, path::PathBuf, process};

use anyhow::{Context, bail, ensure};
use aya::{
    EbpfLoader, Endianness,
    maps::{HashMap, RingBuf},
    programs::BtfTracePoint,
};
use log::{error, info, warn};
use reaper_common::{DenyCfg, Event};

const DEFAULT_BPF_OBJECT: &str = "/data/adb/modules/ksu-reaper/bin/reaper-ebpf.o";
const DEFAULT_BTF: &str = "/sys/kernel/btf/vmlinux";
const APPID_START: u32 = 10_000;
const APPID_END: u32 = 19_999;

struct Config {
    bpf_object: PathBuf,
    btf: PathBuf,
    deny: Vec<(u32, i16)>,
}

fn print_usage() {
    eprintln!(
        "usage: reaperd [--bpf-object PATH] [--btf PATH] [--deny APPID[:KEEP_ADJ]]...
  --bpf-object PATH  eBPF object to load (default: {DEFAULT_BPF_OBJECT}, env REAPER_BPF_OBJECT)
  --btf PATH         vmlinux BTF (default: {DEFAULT_BTF})
  --deny APPID[:KEEP_ADJ]
                     populate the DENY map (repeatable); appid must be 10000..=19999,
                     keep_adj defaults to 100 and is the largest adj worth keeping"
    );
}

fn parse_args() -> anyhow::Result<Config> {
    let mut cfg = Config {
        bpf_object: std::env::var_os("REAPER_BPF_OBJECT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BPF_OBJECT)),
        btf: PathBuf::from(DEFAULT_BTF),
        deny: Vec::new(),
    };

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bpf-object" => {
                cfg.bpf_object = PathBuf::from(args.next().context("--bpf-object needs a path")?)
            }
            "--btf" => cfg.btf = PathBuf::from(args.next().context("--btf needs a path")?),
            "--deny" => {
                let spec = args.next().context("--deny needs APPID[:KEEP_ADJ]")?;
                cfg.deny.push(parse_deny(&spec)?);
            }
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
    if !(APPID_START..=APPID_END).contains(&appid) {
        bail!("appid {appid} outside {APPID_START}..={APPID_END}");
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
        _pad: word(3 * 4)?,
        ts_ns: u64::from_ne_bytes(bytes.get(16..24)?.try_into().ok()?),
    })
}

fn run() -> anyhow::Result<()> {
    let cfg = parse_args()?;

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

    if !cfg.deny.is_empty() {
        let map = bpf
            .map_mut("DENY")
            .context("DENY map not found in object")?;
        let mut deny: HashMap<_, u32, DenyCfg> =
            HashMap::try_from(map).context("DENY map has unexpected shape")?;
        for &(appid, keep_adj) in &cfg.deny {
            deny.insert(&appid, &DenyCfg { keep_adj, flags: 0 }, 0)
                .with_context(|| format!("failed to insert deny entry for appid {appid}"))?;
        }
        info!("populated DENY map with {} entries", cfg.deny.len());
    }

    let ring_map = bpf
        .map_mut("RING")
        .context("RING map not found in object")?;
    let mut ring = RingBuf::try_from(ring_map).context("RING map is not a ring buffer")?;

    // SAFETY: epoll_create1 has no preconditions; failure is reported as -1 and checked.
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    ensure!(epfd >= 0, "epoll_create1 failed");
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 1,
    };
    // SAFETY: epfd and ring_fd are valid open fds; event references outlive the call.
    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ring.as_raw_fd(), &mut event) };
    ensure!(
        rc == 0,
        "epoll_ctl(ADD) failed: {}",
        std::io::Error::last_os_error()
    );

    info!("watching nominations; blocking in epoll_wait");
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
        for _ in 0..n {
            while let Some(item) = ring.next() {
                match parse_event(&item) {
                    Some(ev) => info!(
                        "nomination uid={} tgid={} adj={} ts_ns={}",
                        ev.uid, ev.tgid, ev.adj, ev.ts_ns
                    ),
                    None => warn!("malformed ring buffer event (len {})", item.len()),
                }
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
