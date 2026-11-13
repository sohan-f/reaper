//! reaperd: background-app enforcer daemon.
//!
//! Loads the reaper eBPF program, injects the kernel struct offsets resolved
//! from the device BTF, and drains adj events from the ring buffer through an
//! epoll loop. A backgrounded denied app is force-stopped in enforce mode and
//! logged in observe mode.

#![deny(unsafe_code)]

mod boot;
mod btf;
mod command;
mod config;
mod daemon;
mod decide;
mod deny;
mod enforce;
mod eventloop;
mod layer1;
mod never_kill;
mod paths;
mod pending;
mod policy;
mod sys;
mod uidmap;

use std::process;

use log::error;

fn init_logging() {
    let level = std::env::var("REAPER_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(log::LevelFilter::Info);

    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(level)
                .with_tag("reaperd")
                // With an explicit tag android_logger prefixes the message with
                // the module path, so every line would repeat "reaperd".
                .format(|f, record| write!(f, "{}", record.args())),
        );
    }

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

fn main() {
    init_logging();
    if let Err(err) = boot::run() {
        error!("{err:#}");
        process::exit(1);
    }
}
