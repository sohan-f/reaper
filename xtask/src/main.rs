//! Build and packaging tasks for ksu-reaper.
//!
//! `cargo xtask build-ebpf` compiles the eBPF program for bpfel-unknown-none
//! using the nightly toolchain, `cargo xtask build` additionally compiles
//! reaperd for aarch64-linux-android against the NDK, and `cargo xtask package`
//! writes a KernelSU module zip to `dist/`.

use std::{
    env,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, bail, ensure};
use zip::{ZipWriter, write::SimpleFileOptions};

const API_LEVEL: &str = "35";
const EBPF_TARGET_DIR: &str = "target/bpf";
const EBPF_ARTIFACT: &str = "target/bpf/bpfel-unknown-none/release/reaper-ebpf";
const REAPERD_BIN: &str = "target/aarch64-linux-android/release/reaperd";
const SEPARATOR: char = '\x1f';

fn main() -> anyhow::Result<()> {
    let arg = env::args().nth(1);
    match arg.as_deref() {
        Some("build-ebpf") => build_ebpf(),
        Some("build") => {
            build_ebpf()?;
            build_reaperd()
        }
        Some("package") => package(),
        _ => {
            eprintln!("usage: cargo xtask <build-ebpf|build|package>");
            std::process::exit(2);
        }
    }
}

fn workspace_root() -> anyhow::Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .context("xtask is not inside the workspace")
}

fn bpf_target_arch() -> &'static str {
    match env::consts::ARCH {
        // aya-ebpf-bindings names the module for riscv64 without the width.
        a if a.starts_with("riscv64") => "riscv64",
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        "arm" => "armv7",
        "powerpc64" => "powerpc64",
        "s390x" => "s390x",
        "loongarch64" => "loongarch64",
        other => {
            eprintln!("unsupported host architecture for eBPF build: {other}");
            std::process::exit(2);
        }
    }
}

fn build_ebpf() -> anyhow::Result<()> {
    let root = workspace_root()?;
    let rustflags = format!(
        "--cfg=bpf_target_arch=\"{}\"{}-Cdebuginfo=2{}-Clink-arg=--btf",
        bpf_target_arch(),
        SEPARATOR,
        SEPARATOR,
    );
    let status = Command::new("rustup")
        .current_dir(&root)
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "-p",
            "reaper-ebpf",
            "--bins",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--target-dir",
            EBPF_TARGET_DIR,
        ])
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .status()
        .context("failed to spawn cargo for the eBPF build")?;
    ensure!(status.success(), "eBPF build failed");
    Ok(())
}

fn find_ndk() -> anyhow::Result<PathBuf> {
    let mut candidates = Vec::new();
    for var in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"] {
        if let Some(dir) = env::var_os(var) {
            candidates.push(PathBuf::from(dir));
        }
    }
    for sdk in [
        env::var_os("ANDROID_HOME").map(PathBuf::from),
        env::var_os("ANDROID_SDK_ROOT").map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    .chain([dirs_home().join("Android/Sdk")])
    {
        if let Some(ndk) = newest_child(&sdk.join("ndk")) {
            candidates.push(ndk);
        }
    }

    for dir in candidates {
        let clang = ndk_clang(&dir);
        if clang.is_file() {
            return Ok(dir);
        }
    }
    bail!("Android NDK not found; set ANDROID_NDK_HOME or install one under <sdk>/ndk")
}

fn dirs_home() -> PathBuf {
    env::var_os("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from)
}

fn newest_child(dir: &Path) -> Option<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_dir())
        .collect();
    entries.sort_by(|a, b| {
        let key = |p: &Path| {
            p.file_name()
                .map(|n| {
                    n.to_string_lossy()
                        .split('.')
                        .map(|s| s.parse::<u64>().unwrap_or(0))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        key(a).cmp(&key(b))
    });
    entries.pop()
}

fn ndk_clang(ndk: &Path) -> PathBuf {
    ndk.join("toolchains/llvm/prebuilt/linux-x86_64/bin")
        .join(format!("aarch64-linux-android{API_LEVEL}-clang"))
}

fn build_reaperd() -> anyhow::Result<()> {
    let root = workspace_root()?;
    let ndk = find_ndk()?;
    let clang = ndk_clang(&ndk);
    let linker = clang
        .to_str()
        .context("NDK clang path is not valid UTF-8")?
        .to_owned();
    let status = Command::new("cargo")
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "reaperd",
            "--release",
            "--target",
            "aarch64-linux-android",
            "--config",
            &format!("target.aarch64-linux-android.linker=\"{linker}\""),
        ])
        .status()
        .context("failed to spawn cargo for reaperd")?;
    ensure!(status.success(), "reaperd build failed");
    Ok(())
}

fn package() -> anyhow::Result<()> {
    let root = workspace_root()?;
    let version = env!("CARGO_PKG_VERSION");
    let artifacts = [
        (
            root.join(EBPF_ARTIFACT),
            "bin/reaper-ebpf.o".to_owned(),
            0o644,
        ),
        (root.join(REAPERD_BIN), "bin/reaperd".to_owned(), 0o755),
    ];
    for (path, _, _) in &artifacts {
        ensure!(
            path.is_file(),
            "{} missing; run `cargo xtask build` first",
            path.display()
        );
    }

    let module_files = [
        ("module/customize.sh", "customize.sh", 0o755),
        ("module/module.prop", "module.prop", 0o644),
        ("module/post-fs-data.sh", "post-fs-data.sh", 0o755),
        ("module/hotinstall.sh", "hotinstall.sh", 0o755),
        ("module/boot-completed.sh", "boot-completed.sh", 0o755),
        ("module/uninstall.sh", "uninstall.sh", 0o755),
        ("module/etc/policy.toml", "etc/policy.toml", 0o644),
    ];

    let dist = root.join("dist");
    fs::create_dir_all(&dist)?;
    let zip_path = dist.join(format!("ksu-reaper-v{version}.zip"));
    let file = File::create(&zip_path)?;
    let mut zip = ZipWriter::new(file);
    let raw = SimpleFileOptions::default();
    let mut entries: Vec<(PathBuf, String, u32)> = module_files
        .iter()
        .map(|(src, dst, mode)| (root.join(src), dst.to_string(), *mode))
        .collect();
    entries.extend(artifacts);
    for (src, dst, mode) in entries {
        zip.start_file(&dst, raw.unix_permissions(mode))
            .with_context(|| format!("failed to add {dst}"))?;
        let mut input =
            File::open(&src).with_context(|| format!("failed to read {}", src.display()))?;
        io::copy(&mut input, &mut zip).with_context(|| format!("failed to write {dst}"))?;
    }
    zip.finish()?;
    eprintln!("wrote {}", zip_path.display());
    Ok(())
}
