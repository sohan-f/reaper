#![no_std]
#![no_main]

use aya_ebpf::{
    helpers,
    macros::{btf_tracepoint, map},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::BtfTracePointContext,
};
use reaper_common::{DenyCfg, Event};

const APPID_START: u32 = 10_000;
const APPID_END: u32 = 19_999;
const UIDS_PER_USER: u32 = 100_000;
const RATE_LIMIT_NS: u64 = 250_000_000;

// Map and .rodata names are the ABI with reaperd's loader.
#[map]
static DENY: HashMap<u32, DenyCfg> = HashMap::with_max_entries(512, 0);

#[map]
static LAST_EMIT: LruHashMap<u32, u64> = LruHashMap::with_max_entries(4096, 0);

#[map]
static RING: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// Offsets are injected from device BTF before load; 0 means injection never ran.
#[unsafe(no_mangle)]
static OFF_TGID: u32 = 0;
#[unsafe(no_mangle)]
static OFF_SIGNAL: u32 = 0;
#[unsafe(no_mangle)]
static OFF_REAL_CRED: u32 = 0;
#[unsafe(no_mangle)]
static OFF_CRED_UID: u32 = 0;
#[unsafe(no_mangle)]
static OFF_SIG_OOM_ADJ: u32 = 0;

#[btf_tracepoint(function = "oom_score_adj_update")]
pub fn oom_score_adj_update(ctx: BtfTracePointContext) -> i32 {
    let _ = try_run(&ctx);
    0
}

fn try_run(ctx: &BtfTracePointContext) -> Result<(), i32> {
    let task: *const u8 = ctx.arg(0);

    // SAFETY: OFF_* are injected from the device BTF at load time and reads go
    // through bpf_probe_read_kernel, which cannot trap on a bad address.
    let signal: *const u8 = unsafe {
        helpers::bpf_probe_read_kernel(task.add(OFF_SIGNAL as usize).cast::<*const u8>())?
    };
    let adj: i16 = unsafe {
        helpers::bpf_probe_read_kernel(signal.add(OFF_SIG_OOM_ADJ as usize).cast::<i16>())?
    };

    if adj <= 0 {
        return Ok(());
    }

    // SAFETY: see above.
    let tgid: u32 =
        unsafe { helpers::bpf_probe_read_kernel(task.add(OFF_TGID as usize).cast::<u32>())? };
    // SAFETY: see above.
    let cred: *const u8 = unsafe {
        helpers::bpf_probe_read_kernel(task.add(OFF_REAL_CRED as usize).cast::<*const u8>())?
    };
    // SAFETY: see above.
    let uid: u32 =
        unsafe { helpers::bpf_probe_read_kernel(cred.add(OFF_CRED_UID as usize).cast::<u32>())? };

    let appid = uid % UIDS_PER_USER;
    if !(APPID_START..=APPID_END).contains(&appid) {
        return Ok(());
    }

    // SAFETY: hash map values are copied out at our size. A torn read against a
    // concurrent userspace update can only produce a spurious or missed
    // nomination, never corruption.
    let cfg = match (unsafe { DENY.get(&appid) }).copied() {
        Some(cfg) => cfg,
        None => return Ok(()),
    };
    if i32::from(adj) <= i32::from(cfg.keep_adj) {
        return Ok(());
    }

    // SAFETY: bpf_ktime_get_ns has no preconditions.
    let now = unsafe { helpers::generated::bpf_ktime_get_ns() };

    if let Some(last) = LAST_EMIT.get_ptr(&uid).map(|ptr| {
        // SAFETY: LAST_EMIT values are u64 written atomically by the kernel.
        unsafe { *ptr }
    }) && now.saturating_sub(last) < RATE_LIMIT_NS
    {
        return Ok(());
    }
    LAST_EMIT.insert(&uid, &now, 0)?;

    let Some(mut entry) = RING.reserve::<Event>(0) else {
        if let Some(drops) = DROPS.get_ptr_mut(0) {
            // SAFETY: per-CPU array slot 0 is local to this CPU.
            unsafe { *drops += 1 };
        }
        return Ok(());
    };
    entry.write(Event {
        uid,
        tgid,
        adj: i32::from(adj),
        _pad: 0,
        ts_ns: now,
    });
    entry.submit(0);

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
