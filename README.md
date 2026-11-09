# ksu-reaper

Event-driven background-app enforcer for Android 16 with KernelSU. Denied apps
may run only while foreground or visible; a daemon (`reaperd`) started by the
KernelSU module is woken by an eBPF program attached to
`oom_score_adj_update` and force-stops denied apps that drop to the
background. No accessibility service, no polling, no companion APK.

This repository currently contains the workspace, the nominating eBPF program,
a log-only loader, and the KernelSU module skeleton. Enforcement and Layer 1
static restrictions are not implemented; the module ships in observe mode and
takes no action on its own.

## Build

Requires stable and nightly Rust, `bpf-linker`, and an Android NDK. Builds the
eBPF program and the Android daemon:

    cargo xtask build

Package the module zip into `dist/`:

    cargo xtask package

## Module layout

`cargo xtask package` produces a KernelSU module zip with a `module.prop`,
`post-fs-data.sh` (seeds the policy), `boot-completed.sh` (starts and arms the
daemon), `uninstall.sh`, `etc/policy.toml`, `bin/reaperd` and
`bin/reaper-ebpf.o`.
The daemon loads `bin/reaper-ebpf.o` at startup and resolves the kernel
struct offsets it needs from the device BTF; if that check fails it refuses
to load.

## Policy

The policy file ships at `etc/policy.toml` inside the module and is applied
from `/data/adb/reaper/policy.toml` at install time. See the comments in
`module/etc/policy.toml`.

## License

MIT OR Apache-2.0, at your option.
