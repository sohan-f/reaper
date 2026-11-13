//! Command-line configuration.

use std::{path::PathBuf, process};

use anyhow::{Context, bail};

use crate::policy::{APPID_END, APPID_START};

const DEFAULT_BPF_OBJECT: &str = "/data/adb/modules/ksu-reaper/bin/reaper-ebpf.o";
const DEFAULT_BTF: &str = "/sys/kernel/btf/vmlinux";
const DEFAULT_POLICY: &str = "/data/adb/reaper/policy.toml";

/// Paths and deny overrides supplied on the command line.
pub struct Config {
    /// eBPF object to load.
    pub bpf_object: PathBuf,
    /// vmlinux BTF used to resolve struct offsets.
    pub btf: PathBuf,
    /// Policy file watched for reloads.
    pub policy: PathBuf,
    /// Extra deny entries, as (appid, `keep_adj`).
    pub deny_overrides: Vec<(u32, i16)>,
    /// Restore the Layer 1 journal and exit instead of running the daemon.
    pub restore_layer1: bool,
}

impl Config {
    /// Parses the arguments in `std::env::args`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown flag, a flag without its value, or an
    /// appid outside the app range.
    pub fn parse() -> anyhow::Result<Self> {
        let mut cfg = Self {
            bpf_object: std::env::var_os("REAPER_BPF_OBJECT")
                .map_or_else(|| PathBuf::from(DEFAULT_BPF_OBJECT), PathBuf::from),
            btf: PathBuf::from(DEFAULT_BTF),
            policy: PathBuf::from(DEFAULT_POLICY),
            deny_overrides: Vec::new(),
            restore_layer1: false,
        };

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--bpf-object" => {
                    cfg.bpf_object =
                        PathBuf::from(args.next().context("--bpf-object needs a path")?);
                }
                "--btf" => cfg.btf = PathBuf::from(args.next().context("--btf needs a path")?),
                "--policy" => {
                    cfg.policy = PathBuf::from(args.next().context("--policy needs a path")?);
                }
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
}

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
