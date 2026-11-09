# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Workspace layout: `reaper-common` (shared types), `reaper-ebpf` (nominating
  program attached to `tp_btf/oom_score_adj_update`), `reaperd` (userspace
  loader), `xtask` (build and module packaging).
- `reaperd` resolves `task_struct`/`signal_struct` offsets from the device
  vmlinux BTF at load and refuses to load on any mismatch.
- KernelSU module skeleton in `module/` (post-fs-data, boot-completed,
  uninstall, policy defaulting to observe mode).
