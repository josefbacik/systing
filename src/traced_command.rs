//! Fork-pipe-exec support for tracing a command and its children.
//!
//! Provides [`TracedChild`] and [`spawn_traced_child`] which fork a child process
//! that waits for a readiness signal before calling exec. This allows the parent
//! to set up BPF tracing with the child's PID before the command starts.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};

/// A child process that has been forked but is waiting to exec.
///
/// The child blocks on a pipe until [`signal_exec`](TracedChild::signal_exec) is called,
/// at which point it calls `execv` with the resolved command. A second pipe with
/// `O_CLOEXEC` on the write end allows the parent to detect when exec completes.
///
/// On drop, if the child has not been waited on, it is killed with `SIGKILL` and reaped.
pub struct TracedChild {
    /// The child's PID (the TGID that will be used for BPF filtering).
    pub pid: u32,
    /// Write end of the "ready" pipe. Writing signals the child to exec.
    ready_write_fd: Option<i32>,
    /// Read end of the "exec" pipe. EOF means exec succeeded; data means failure.
    exec_read_fd: Option<i32>,
    /// Whether waitpid has already been called for this child.
    /// Shared with the background waitpid thread to prevent double-wait.
    /// Uses compare_exchange to ensure exactly one caller reaps the child.
    pub waited: Arc<AtomicBool>,
    /// The child's exit status (set by the waitpid thread or wait()).
    pub exit_status: Arc<std::sync::Mutex<Option<i32>>>,
}

impl Drop for TracedChild {
    fn drop(&mut self) {
        // Close any remaining pipe fds
        if let Some(fd) = self.ready_write_fd.take() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.exec_read_fd.take() {
            unsafe { libc::close(fd) };
        }

        // Atomically claim the right to reap the child.
        // If another thread already reaped it, this is a no-op.
        if self
            .waited
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            unsafe {
                libc::kill(self.pid as i32, libc::SIGKILL);
                let mut status: i32 = 0;
                libc::waitpid(self.pid as i32, &mut status, 0);
            }
        }
    }
}

impl TracedChild {
    /// Signal the child to call exec. This writes a byte to the ready pipe and closes it.
    pub fn signal_exec(&mut self) -> Result<()> {
        if let Some(fd) = self.ready_write_fd.take() {
            let buf: [u8; 1] = [1];
            let ret = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, 1) };
            // Capture errno before close() can clobber it
            let write_err = if ret < 0 {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            unsafe { libc::close(fd) };
            if let Some(err) = write_err {
                bail!("Failed to signal child to exec: {}", err);
            }
        }
        Ok(())
    }

    /// Wait for the child to complete exec. Returns Ok(()) on success.
    ///
    /// Reads from the CLOEXEC exec pipe. EOF means exec succeeded.
    /// If data is read, exec failed and the data contains the errno.
    pub fn wait_for_exec(&mut self) -> Result<()> {
        if let Some(fd) = self.exec_read_fd.take() {
            let mut buf = [0u8; 4];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 4) };
            // Capture errno before close() can clobber it
            let read_err = if n < 0 {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            unsafe { libc::close(fd) };

            if let Some(err) = read_err {
                bail!("Failed to read exec status pipe: {}", err);
            }
            if n > 0 {
                // Child wrote errno before _exit - exec failed
                let errno = if n >= 4 {
                    i32::from_ne_bytes(buf)
                } else {
                    buf[0] as i32
                };
                // Reap the child
                let mut status: i32 = 0;
                unsafe { libc::waitpid(self.pid as i32, &mut status, 0) };
                self.waited.store(true, Ordering::Release);
                bail!(
                    "Failed to exec command: {}",
                    std::io::Error::from_raw_os_error(errno)
                );
            }
            // n == 0: EOF, exec succeeded
        }
        Ok(())
    }

    /// Get the child's exit code, if it has been waited on.
    pub fn exit_code(&self) -> Option<i32> {
        *self.exit_status.lock().unwrap()
    }
}

/// Resolve a command name to its full path by searching PATH.
fn resolve_executable(name: &str) -> Result<PathBuf> {
    let path = Path::new(name);

    // If it contains a slash, treat as a direct path
    if name.contains('/') {
        if !path.exists() {
            bail!("Command not found: {}", name);
        }
        // Verify it's a file and executable
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Cannot stat '{}': {}", name, "permission denied"))?;
        if !metadata.is_file() {
            bail!("'{}' is not a regular file", name);
        }
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            bail!("'{}' is not executable", name);
        }
        return Ok(path.to_path_buf());
    }

    // Search PATH
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join(name);
            if candidate.exists() {
                if let Ok(metadata) = std::fs::metadata(&candidate) {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
                        return Ok(candidate);
                    }
                }
            }
        }
    }

    bail!(
        "Command '{}' not found in PATH. Specify the full path to the executable.",
        name
    );
}

/// Check if a command appears to be a Python interpreter.
pub fn is_python_command(command: &[String]) -> bool {
    if command.is_empty() {
        return false;
    }
    let cmd = &command[0];
    // Check the basename of the command
    let basename = Path::new(cmd)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd);
    // Match python, python3, python3.11, etc. but not bpython or cpython-build-tool
    basename.starts_with("python")
}

/// Fork a child process that waits to exec the given command.
///
/// The child blocks on a pipe until the parent calls [`TracedChild::signal_exec`].
/// This allows the parent to set up BPF tracing with the child's PID before
/// the command actually starts.
///
/// # Safety
///
/// This function calls `libc::fork()`. It must be called from a single-threaded
/// context (before spawning any threads). The child path uses only async-signal-safe
/// functions and **never returns** — it always calls `_exit()` or `execv()`.
pub fn spawn_traced_child(command: &[String]) -> Result<TracedChild> {
    if command.is_empty() {
        bail!("No command specified to run");
    }

    // Resolve the executable path before fork (involves Rust allocations)
    let resolved_path =
        resolve_executable(&command[0]).with_context(|| "Failed to resolve command")?;
    eprintln!(
        "Resolved command: {} -> {}",
        command[0],
        resolved_path.display()
    );

    // Prepare CStrings before fork (no allocations allowed in child after fork)
    let path_cstr = CString::new(resolved_path.as_os_str().as_bytes())
        .with_context(|| "Command path contains null byte")?;

    let arg_cstrings: Vec<CString> = command
        .iter()
        .map(|arg| {
            CString::new(arg.as_bytes())
                .with_context(|| format!("Argument contains null byte: {}", arg))
        })
        .collect::<Result<Vec<_>>>()?;

    // Build argv array: pointers to CStrings + null terminator
    let mut argv: Vec<*const libc::c_char> = arg_cstrings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    // Create ready_pipe: parent writes to signal child to exec
    let mut ready_fds = [0i32; 2];
    if unsafe { libc::pipe(ready_fds.as_mut_ptr()) } != 0 {
        bail!(
            "Failed to create ready pipe: {}",
            std::io::Error::last_os_error()
        );
    }
    let ready_read = ready_fds[0];
    let ready_write = ready_fds[1];

    // Create exec_pipe with O_CLOEXEC: EOF on exec success, data on failure
    let mut exec_fds = [0i32; 2];
    if unsafe { libc::pipe2(exec_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        unsafe {
            libc::close(ready_read);
            libc::close(ready_write);
        }
        bail!(
            "Failed to create exec pipe: {}",
            std::io::Error::last_os_error()
        );
    }
    let exec_read = exec_fds[0];
    let exec_write = exec_fds[1];

    // Save parent PID before fork for the PR_SET_PDEATHSIG race check
    let parent_pid = unsafe { libc::getpid() };

    // Fork
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            // Fork failed - clean up pipes
            unsafe {
                libc::close(ready_read);
                libc::close(ready_write);
                libc::close(exec_read);
                libc::close(exec_write);
            }
            bail!("fork() failed: {}", std::io::Error::last_os_error());
        }
        0 => {
            // ===== CHILD PROCESS =====
            // Only async-signal-safe libc calls from here.
            // NEVER return from this branch - always _exit() or exec.
            unsafe {
                // Close parent-side pipe ends
                libc::close(ready_write);
                libc::close(exec_read);

                // If parent dies before signaling, we get SIGTERM
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);

                // Check for the PR_SET_PDEATHSIG race: if the parent already
                // died between fork() and prctl(), we were reparented.
                if libc::getppid() != parent_pid {
                    libc::_exit(1);
                }

                // Block until parent signals readiness
                let mut buf = [0u8; 1];
                let n = libc::read(ready_read, buf.as_mut_ptr() as *mut libc::c_void, 1);
                libc::close(ready_read);

                if n <= 0 {
                    // EOF (parent died) or error - exit without exec
                    libc::_exit(1);
                }

                // exec the command (O_CLOEXEC closes exec_write on success)
                libc::execv(path_cstr.as_ptr(), argv.as_ptr());

                // If we get here, exec failed. Write errno to exec_pipe.
                let errno = *libc::__errno_location();
                let errno_bytes = errno.to_ne_bytes();
                libc::write(exec_write, errno_bytes.as_ptr() as *const libc::c_void, 4);
                libc::close(exec_write);
                libc::_exit(127);
            }
        }
        child_pid => {
            // ===== PARENT PROCESS =====
            // Close child-side pipe ends
            unsafe {
                libc::close(ready_read);
                libc::close(exec_write);
            }

            Ok(TracedChild {
                pid: child_pid as u32,
                ready_write_fd: Some(ready_write),
                exec_read_fd: Some(exec_read),
                waited: Arc::new(AtomicBool::new(false)),
                exit_status: Arc::new(std::sync::Mutex::new(None)),
            })
        }
    }
}
