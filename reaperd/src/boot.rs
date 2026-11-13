//! Startup: restore mode, eBPF load, and the hand-off to the event loop.

use std::path::Path;

use anyhow::Context;
use aya::{
    Ebpf, EbpfLoader, Endianness,
    maps::{HashMap as BpfHashMap, RingBuf},
    programs::BtfTracePoint,
};
use log::info;

use crate::{
    btf,
    config::Config,
    daemon::Daemon,
    deny::DenyMapMut,
    eventloop::{self, Fds, RingMut},
    layer1,
    paths::{LAYER1_JOURNAL, REAPER_DIR},
};

/// Runs the daemon until SIGTERM.
///
/// # Errors
///
/// Returns an error if the journal cannot be restored, the BTF or eBPF object
/// cannot be loaded, or the event loop fails.
pub fn run() -> anyhow::Result<()> {
    let cfg = Config::parse()?;
    if cfg.restore_layer1 {
        return restore_layer1();
    }

    let btf_bytes =
        std::fs::read(&cfg.btf).with_context(|| format!("failed to read {}", cfg.btf.display()))?;
    let mut bpf = load_program(&cfg, &btf_bytes)?;
    let _ = std::fs::create_dir_all(REAPER_DIR);

    let [deny_map_raw, ring_map] = bpf.maps_disjoint_mut(["DENY", "RING"]);
    let mut deny_map: DenyMapMut<'_> =
        BpfHashMap::try_from(deny_map_raw.context("DENY map not found in object")?)
            .context("DENY map has unexpected shape")?;
    let mut ring: RingMut<'_> =
        RingBuf::try_from(ring_map.context("RING map not found in object")?)
            .context("RING map is not a ring buffer")?;

    let mut daemon = Daemon::load(&cfg, &mut deny_map)?;
    if daemon.policy_ready && daemon.uid_map_ready {
        daemon.reconcile_layer1();
    }
    let fds = Fds::open(&ring)?;
    eventloop::run(&mut daemon, &mut deny_map, &mut ring, &fds)
}

fn restore_layer1() -> anyhow::Result<()> {
    let mut ops = layer1::AndroidOps;
    layer1::restore_all(Path::new(LAYER1_JOURNAL), &mut ops)
        .context("failed to restore Layer 1 state")?;
    info!("Layer 1 state restored");
    Ok(())
}

fn load_program(cfg: &Config, btf_bytes: &[u8]) -> anyhow::Result<Ebpf> {
    let layout = btf::resolve_layout(btf_bytes)
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
    attach_tracepoint(&mut bpf, btf_bytes)?;
    Ok(bpf)
}

fn attach_tracepoint(bpf: &mut Ebpf, btf_bytes: &[u8]) -> anyhow::Result<()> {
    let vmlinux = aya::Btf::parse(btf_bytes, Endianness::Little)
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
    Ok(())
}
