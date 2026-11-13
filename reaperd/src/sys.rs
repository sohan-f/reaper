//! Thin wrappers over the libc calls the daemon needs.
//!
//! The crate denies `unsafe_code`; this module is the single exception. Each
//! wrapper checks the C return value and reports the errno as [`io::Error`], so
//! callers hold only descriptors this module created and never raw pointers.

#![allow(unsafe_code)]

use std::{ffi::CStr, io, os::fd::RawFd, time::Duration};

const MAX_EVENTS: usize = 16;

fn check(rc: i32) -> io::Result<()> {
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn fd_or_error(fd: RawFd) -> io::Result<RawFd> {
    if fd == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

/// Returns nanoseconds since boot from `CLOCK_BOOTTIME`.
pub fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is writable and CLOCK_BOOTTIME is a valid clock id; the call
    // cannot fail for that id.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) };
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

/// Creates a non-blocking epoll instance.
pub fn epoll_create() -> io::Result<RawFd> {
    // SAFETY: EPOLL_CLOEXEC is the only flag; no other preconditions.
    fd_or_error(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })
}

/// Registers `fd` for read readiness, tagged with `tag`.
pub fn epoll_add(epoll_fd: RawFd, fd: RawFd, tag: u64) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: tag,
    };
    // SAFETY: both descriptors belong to this process and are open; `event` is
    // writable and EPOLL_CTL_ADD copies it before returning.
    check(unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &raw mut event) })
}

/// Blocks until at least one registered descriptor is ready.
///
/// Writes the tags of the ready descriptors into `tags` and returns how many
/// were written.
pub fn epoll_wait(epoll_fd: RawFd, tags: &mut [u64]) -> io::Result<usize> {
    let capacity = tags.len().min(MAX_EVENTS);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; MAX_EVENTS];
    let timeout = -1;
    // SAFETY: `events` holds MAX_EVENTS writable entries and the count passed to
    // the kernel is at most that.
    let n = unsafe {
        libc::epoll_wait(
            epoll_fd,
            events.as_mut_ptr(),
            libc::c_int::try_from(capacity).unwrap_or(libc::c_int::MAX),
            timeout,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = usize::try_from(n).unwrap_or(0).min(capacity);
    for (tag, event) in tags.iter_mut().zip(&events[..n]) {
        *tag = event.u64;
    }
    Ok(n)
}

/// Creates a `CLOCK_BOOTTIME` timerfd.
pub fn timer_create() -> io::Result<RawFd> {
    // SAFETY: both flags are valid; the clock id is always supported on Linux.
    fd_or_error(unsafe { libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_CLOEXEC) })
}

/// Arms, re-arms, or disarms (`None`) a timerfd.
pub fn timer_arm(fd: RawFd, rel: Option<Duration>) -> io::Result<()> {
    let mut spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    if let Some(rel) = rel {
        let secs = libc::time_t::try_from(rel.as_secs()).unwrap_or(libc::time_t::MAX);
        let nanos = libc::c_long::from(rel.subsec_nanos());
        spec.it_value.tv_sec = secs;
        spec.it_value.tv_nsec = nanos;
        // A zero expiration disarms the timer, which is not what a due deadline
        // means; fire after 1 ms instead.
        if spec.it_value.tv_sec == 0 && spec.it_value.tv_nsec == 0 {
            spec.it_value.tv_nsec = 1_000_000;
        }
    }
    // SAFETY: `fd` is a timerfd created by `timer_create`, and `spec` is a fully
    // initialized itimerspec that outlives the call.
    check(unsafe { libc::timerfd_settime(fd, 0, &raw const spec, std::ptr::null_mut()) })
}

/// Creates a non-blocking inotify instance.
pub fn inotify_create() -> io::Result<RawFd> {
    // SAFETY: both flags are valid; no other preconditions.
    fd_or_error(unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) })
}

/// Watches `path` and returns the watch descriptor.
pub fn inotify_add(fd: RawFd, path: &CStr, mask: u32) -> io::Result<RawFd> {
    // SAFETY: `fd` is an inotify instance and `path` is a NUL-terminated C string
    // that outlives the call.
    fd_or_error(unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) })
}

/// Blocks `signals` on the calling thread and returns a descriptor that reports
/// them.
///
/// The returned descriptor stays in blocking mode: reads are only issued after
/// epoll reports the signal fd readable.
pub fn signal_fd(signals: &[i32]) -> io::Result<RawFd> {
    // SAFETY: sigset_t is plain data with no invalid bit patterns.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is writable and lives for the whole function.
    check(unsafe { libc::sigemptyset(&raw mut set) })?;
    for &signal in signals {
        // SAFETY: `set` is initialized and `signal` is a valid signal number.
        check(unsafe { libc::sigaddset(&raw mut set, signal) })?;
    }
    // SAFETY: `set` holds the signals to block and is readable for the call.
    check(unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) })?;
    // SAFETY: the mask is valid and was just installed on this thread.
    fd_or_error(unsafe { libc::signalfd(-1, &raw const set, libc::SFD_CLOEXEC) })
}

/// Reads one `u64` from a timerfd.
pub fn read_u64(fd: RawFd) -> io::Result<u64> {
    let mut value: u64 = 0;
    // SAFETY: `value` is an 8-byte writable buffer and `fd` is a timerfd owned by
    // this process.
    let rc = unsafe { libc::read(fd, (&raw mut value).cast::<libc::c_void>(), 8) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if rc != 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short read from timerfd",
        ));
    }
    Ok(value)
}

/// Reads one signal number from the signal fd.
///
/// Returns `None` when the read is shorter than a `signalfd_siginfo` or the
/// signal number does not fit in `i32`.
pub fn read_signal(fd: RawFd) -> io::Result<Option<i32>> {
    // SAFETY: signalfd_siginfo is plain data with no invalid bit patterns.
    let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::signalfd_siginfo>();
    // SAFETY: `info` is `size` writable bytes and `fd` is a signalfd owned by this
    // process.
    let rc = unsafe { libc::read(fd, (&raw mut info).cast::<libc::c_void>(), size) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(rc).ok() != Some(size) {
        return Ok(None);
    }
    Ok(i32::try_from(info.ssi_signo).ok())
}

/// Reads up to `buf.len()` bytes, returning how many were read.
pub fn read_bytes(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is writable for its whole length and `fd` is an inotify
    // instance owned by this process.
    let rc = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(rc).unwrap_or(0).min(buf.len()))
}
