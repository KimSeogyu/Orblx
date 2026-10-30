//! PTY shell for one SSH session.
//!
//! The server opens one pseudo-terminal pair for each shell session.
//! The shell is the session leader of a new session and owns the terminal.
//! The server keeps the master side. It does not share it with other sessions.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

/// The terminal of one PTY request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PtySpec {
    /// Terminal type. Only letters, digits, `-`, `.`, and `_`.
    pub(crate) term: String,
    /// Columns.
    pub(crate) cols: u16,
    /// Rows.
    pub(crate) rows: u16,
}

impl PtySpec {
    /// Make a terminal spec from the client request.
    ///
    /// A bad terminal type becomes `xterm`. A zero size becomes 80 x 24.
    pub(crate) fn from_request(term: &str, cols: u32, rows: u32) -> Self {
        let term_ok = !term.is_empty()
            && term.len() <= 32
            && term
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'));
        Self {
            term: if term_ok { term } else { "xterm" }.to_string(),
            cols: clamp_size(cols, 80),
            rows: clamp_size(rows, 24),
        }
    }
}

/// Keep a terminal size between 1 and 1000.
pub(crate) fn clamp_size(value: u32, default: u16) -> u16 {
    if value == 0 {
        return default;
    }
    u16::try_from(value.min(1000)).unwrap_or(default)
}

/// One running shell on a PTY.
pub(crate) struct PtyShell {
    /// The master side of the terminal.
    pub(crate) master: File,
    /// The shell process.
    pub(crate) child: Child,
}

/// Open a PTY pair and start `/bin/sh -i` on it.
///
/// The environment has only `PATH`, `TERM`, `HOME`, and `ORBLX_SSH_USER`.
pub(crate) fn spawn_shell(spec: &PtySpec, user: &str) -> io::Result<PtyShell> {
    let (master, slave) = open_pair(spec.cols, spec.rows)?;
    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    let mut command = Command::new("/bin/sh");
    command
        .arg("-i")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", &spec.term)
        .env("HOME", "/")
        .env("ORBLX_SSH_USER", user)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(slave));
    // SAFETY: the closure runs in the child after fork and before exec.
    // It calls only async-signal-safe functions (setsid and ioctl).
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    Ok(PtyShell {
        master: File::from(master),
        child,
    })
}

fn open_pair(cols: u16, rows: u16) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let mut size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the pointers are valid for the call. The name buffer is not used.
    let status = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut size,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty returned two new open descriptors that this function owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    close_on_exec(&master)?;
    close_on_exec(&slave)?;
    Ok((master, slave))
}

fn close_on_exec(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: the descriptor is open for the call.
    let status = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Return true when the terminal echo is off.
///
/// A shell turns the echo off for a password prompt.
/// When the call fails, the function returns false.
pub(crate) fn echo_off(master: &File) -> bool {
    // SAFETY: termios is plain data. tcgetattr fills it.
    let mut modes: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and the pointer is valid.
    let status = unsafe { libc::tcgetattr(master.as_raw_fd(), &mut modes) };
    status == 0 && modes.c_lflag & libc::ECHO == 0
}

/// Set the terminal size.
pub(crate) fn resize(master: &File, cols: u16, rows: u16) -> io::Result<()> {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the descriptor is open and the pointer is valid.
    let status = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &size) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait up to `millis` for the master side to have data.
///
/// The function returns true when a read does not block.
pub(crate) fn readable(master: &File, millis: i32) -> bool {
    let mut poll = libc::pollfd {
        fd: master.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the pointer is valid for one pollfd.
    let status = unsafe { libc::poll(&mut poll, 1, millis) };
    status > 0
}

/// Stop the process group of a shell.
pub(crate) fn kill_group(pid: u32, signal: libc::c_int) {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    // SAFETY: kill has no memory effects. The group is the shell session.
    unsafe {
        libc::kill(-pid, signal);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    use super::{clamp_size, echo_off, readable, spawn_shell, PtySpec};

    #[test]
    fn a_bad_terminal_type_and_size_become_safe_values() {
        let spec = PtySpec::from_request("xterm;rm -rf /", 0, 5000);
        assert_eq!(spec.term, "xterm");
        assert_eq!(spec.cols, 80);
        assert_eq!(spec.rows, 1000);
        assert_eq!(clamp_size(132, 80), 132);
        assert_eq!(PtySpec::from_request("vt100", 100, 30).term, "vt100");
    }

    #[test]
    fn a_shell_on_the_pty_runs_input_and_echo_off_is_seen() {
        let spec = PtySpec::from_request("xterm", 80, 24);
        let mut shell = spawn_shell(&spec, "rec").unwrap();
        let mut writer = shell.master.try_clone().unwrap();
        writer
            .write_all(b"stty -echo; echo user-$ORBLX_SSH_USER; sleep 1; stty echo; exit\n")
            .unwrap();
        let mut seen = Vec::new();
        let mut saw_off = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut buf = [0u8; 1024];
        while Instant::now() < deadline {
            if readable(&shell.master, 50) {
                match shell.master.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(len) => seen.extend_from_slice(&buf[..len]),
                }
            }
            if String::from_utf8_lossy(&seen).contains("user-rec") && echo_off(&shell.master) {
                saw_off = true;
            }
            if shell.child.try_wait().unwrap().is_some() && !readable(&shell.master, 50) {
                break;
            }
        }
        let _ = shell.child.kill();
        let _ = shell.child.wait();
        assert!(String::from_utf8_lossy(&seen).contains("user-rec"));
        assert!(saw_off, "the echo-off state was not seen");
    }
}
