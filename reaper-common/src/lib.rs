#![no_std]
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

//! Types shared between `reaper-ebpf` (kernel side) and `reaperd` (userspace).

/// A nomination pushed to userspace when an owned process crosses `keep_adj`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    /// Full uid (user * 100000 + appid) of the process's owner.
    pub uid: u32,
    /// Thread group id of the target process.
    pub tgid: u32,
    /// `oom_score_adj` of the target task at the time of the write.
    pub adj: i32,
    /// Explicit padding so the layout matches on both sides.
    pub _pad: u32,
    /// Kernel timestamp from `bpf_ktime_get_ns`, nanoseconds since boot.
    pub ts_ns: u64,
}

/// Per-app policy stored in the `DENY` map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DenyCfg {
    /// Nominate only when `adj` exceeds this value.
    pub keep_adj: i16,
    /// Reserved for future use. Must be zero.
    pub flags: u16,
}

// SAFETY: both structs are repr(C), every byte is initialized by writers, and
// any bit pattern is valid, so they may be copied to and from byte slices.
#[cfg(feature = "pod")]
unsafe impl aya::Pod for Event {}
#[cfg(feature = "pod")]
unsafe impl aya::Pod for DenyCfg {}
