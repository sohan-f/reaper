//! External command execution with a bounded wait.

use std::{
    io,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Runs `command`, returning its captured output.
///
/// # Errors
///
/// Returns an error if the command cannot be spawned or does not exit within
/// `timeout`. A timed-out child is killed and reaped.
pub fn output(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output(),
            Ok(None) => {}
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(io::ErrorKind::TimedOut, "command timed out"));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output() {
        let mut command = Command::new("/bin/echo");
        command.arg("hello");
        let output = output(&mut command, Duration::from_secs(1)).expect("echo must run");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"hello\n");
    }

    #[test]
    fn kills_a_child_that_exceeds_the_timeout() {
        let mut command = Command::new("/bin/sleep");
        command.arg("10");
        let err =
            output(&mut command, Duration::from_millis(100)).expect_err("sleep must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
