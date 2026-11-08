//! PTY shell for one SSH session.
//!
//! The server opens one pseudo-terminal pair for each shell session.
//! The shell is the session leader of a new session and owns the terminal.
//! The server keeps the master side and one slave descriptor. It does not
//! share them with other sessions. The slave descriptor is how the server
//! reads the echo flag.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

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
    /// The slave side. The echo flag is on this side, not on the master.
    pub(crate) slave: File,
    /// The shell process.
    pub(crate) child: Child,
}

/// Arguments for one interactive `/bin/sh`.
///
/// Bash line editing turns kernel echo off and draws the echo itself.
/// The recorder would then hide ordinary input.
/// `--noediting` leaves kernel echo on until a program turns it off.
pub(crate) fn interactive_shell_args(bash: bool) -> &'static [&'static str] {
    if bash {
        &["--noediting", "-i"]
    } else {
        &["-i"]
    }
}

/// `/bin/sh` is Bash when it sets `BASH_VERSION`.
///
/// macOS runs Bash for `/bin/sh`. Linux often runs another shell.
/// The probe result is kept for the process.
fn shell_is_bash() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let Ok(output) = Command::new("/bin/sh")
            .arg("-c")
            .arg("printf %s \"${BASH_VERSION-}\"")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
        else {
            return false;
        };
        output.status.success() && output.stdout.iter().any(|byte| !byte.is_ascii_whitespace())
    })
}

/// Open a PTY pair and start `/bin/sh -i` on it.
///
/// The environment has only `PATH`, `TERM`, `HOME`, and `ORBLX_SSH_USER`.
/// When `/bin/sh` is Bash, the arguments are `--noediting -i`.
pub(crate) fn spawn_shell(spec: &PtySpec, user: &str) -> io::Result<PtyShell> {
    spawn_program(
        "/bin/sh",
        interactive_shell_args(shell_is_bash()),
        spec,
        user,
    )
}

fn spawn_program(program: &str, args: &[&str], spec: &PtySpec, user: &str) -> io::Result<PtyShell> {
    let (master, slave) = open_pair(spec.cols, spec.rows)?;
    // Keep one slave descriptor. A later open of the slave path can fail,
    // and the master side does not show the echo flag.
    let echo_slave = slave.try_clone()?;
    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    let mut command = Command::new(program);
    command
        .args(args)
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
        slave: File::from(echo_slave),
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
/// `slave` is the slave side from `openpty`. On macOS the master side does
/// not carry the slave `ECHO` flag, so a master-only check hides every input.
/// A later open of the slave path can also fail, so this reads the descriptor
/// that `spawn_shell` kept. When the call fails, the function returns false.
pub(crate) fn echo_off(slave: &File) -> bool {
    // SAFETY: termios is plain data. tcgetattr fills it.
    let mut modes: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and the pointer is valid.
    let status = unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut modes) };
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

    use super::{
        clamp_size, echo_off, interactive_shell_args, readable, spawn_program, spawn_shell, PtySpec,
    };

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
            if String::from_utf8_lossy(&seen).contains("user-rec") && echo_off(&shell.slave) {
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

    fn bash_program() -> &'static str {
        if std::path::Path::new("/bin/bash").is_file() {
            "/bin/bash"
        } else if std::path::Path::new("/usr/bin/bash").is_file() {
            "/usr/bin/bash"
        } else {
            panic!("bash is not installed");
        }
    }

    /// Read until the shell writes, then sample kernel echo.
    fn prompt_has_echo_off(program: &str, args: &[&str]) -> bool {
        let spec = PtySpec::from_request("xterm", 80, 24);
        let mut shell = spawn_program(program, args, &spec, "rec").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 256];
        let mut saw = false;
        while Instant::now() < deadline {
            if readable(&shell.master, 50) {
                match shell.master.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        saw = true;
                        break;
                    }
                }
            }
        }
        let settle = Instant::now() + Duration::from_secs(1);
        let mut off = false;
        while Instant::now() < settle {
            if readable(&shell.master, 20) {
                let _ = shell.master.read(&mut buf);
            }
            off = echo_off(&shell.slave);
            std::thread::sleep(Duration::from_millis(20));
        }
        super::kill_group(shell.child.id(), libc::SIGKILL);
        let _ = shell.child.wait();
        assert!(saw, "the shell did not write a prompt");
        off
    }

    #[test]
    fn bash_line_editing_turns_kernel_echo_off() {
        // This is the macOS failure mode. Linux `/bin/sh` is not Bash.
        // The check uses Bash itself. It is not a macOS run.
        assert!(prompt_has_echo_off(bash_program(), &["-i"]));
    }

    #[test]
    fn the_server_bash_args_keep_kernel_echo_until_stty() {
        let spec = PtySpec::from_request("xterm", 80, 24);
        let args = interactive_shell_args(true);
        assert_eq!(args, ["--noediting", "-i"]);
        let mut shell = spawn_program(bash_program(), args, &spec, "rec").unwrap();
        let mut writer = shell.master.try_clone().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 256];
        let mut saw = false;
        while Instant::now() < deadline {
            if readable(&shell.master, 50) {
                match shell.master.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        saw = true;
                        break;
                    }
                }
            }
        }
        assert!(saw, "the shell did not write a prompt");
        let settle = Instant::now() + Duration::from_millis(300);
        while Instant::now() < settle {
            if readable(&shell.master, 20) {
                let _ = shell.master.read(&mut buf);
            }
            assert!(
                !echo_off(&shell.slave),
                "kernel echo is off at the bash prompt"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // `$((...))` makes the output differ from the echo of the input line.
        writer
            .write_all(b"stty -echo; echo hide-$((40+2)); sleep 1; stty echo; echo back-$((3+4))\n")
            .unwrap();
        let mut seen = Vec::new();
        let mut saw_off = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if readable(&shell.master, 50) {
                match shell.master.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(len) => seen.extend_from_slice(&buf[..len]),
                }
            }
            let text = String::from_utf8_lossy(&seen);
            if text.contains("hide-42") && echo_off(&shell.slave) {
                saw_off = true;
            }
            if text.contains("back-7") {
                break;
            }
        }
        let echo_after = echo_off(&shell.slave);
        let text = String::from_utf8_lossy(&seen);
        super::kill_group(shell.child.id(), libc::SIGKILL);
        let _ = shell.child.wait();
        assert!(
            text.contains("back-7"),
            "the shell did not restore echo. output={text:?}"
        );
        assert!(saw_off, "stty -echo did not clear kernel echo");
        assert!(!echo_after, "stty echo did not restore kernel echo");
    }
}
