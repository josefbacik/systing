//! Network namespace test utilities for integration testing.
//!
//! This module provides a test harness that creates isolated network namespaces
//! with veth pairs, ensuring network traffic goes through the real kernel network
//! stack (tc, netfilter, socket buffers) rather than the localhost shortcut.
//!
//! # External Dependencies
//!
//! This module requires the following tools to be installed:
//! - `ip` (iproute2) - for network namespace and veth management
//! - `socat` - for the TCP echo server
//! - `nc` (netcat) - for server readiness probing
//!
//! # Example
//!
//! ```ignore
//! let netns = NetnsTestEnv::new(NetworkTestConfig::default())?;
//! netns.generate_traffic(b"Hello")?;
//! // Traffic goes through veth pair, captured by BPF probes
//! ```

use anyhow::{Context, Result};
use arrow::array::{Int32Array, Int64Array, StringArray};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration;

/// Configuration for network namespace test environment
#[derive(Debug, Clone)]
pub struct NetworkTestConfig {
    /// Name prefix for the network namespace
    pub ns_name_prefix: String,
    /// IP address for the veth interface inside the namespace
    pub ns_ip: IpAddr,
    /// IP address for the veth interface on the host side
    pub host_ip: IpAddr,
    /// Subnet prefix length (e.g., 24 for /24)
    pub prefix_len: u8,
}

impl NetworkTestConfig {
    /// The network prefix used for test traffic (10.200.x.x).
    /// This prefix identifies traffic going through the veth pair
    /// rather than loopback.
    pub const TEST_NETWORK_PREFIX: &'static str = "10.200.";
}

impl Default for NetworkTestConfig {
    fn default() -> Self {
        Self {
            ns_name_prefix: "systing_test".to_string(),
            ns_ip: "10.200.1.2".parse().unwrap(),
            host_ip: "10.200.1.1".parse().unwrap(),
            prefix_len: 24,
        }
    }
}

/// Network namespace test environment
///
/// Creates an isolated network namespace with a veth pair for testing
/// network-related functionality. The namespace is automatically cleaned
/// up when this struct is dropped.
#[allow(dead_code)]
pub struct NetnsTestEnv {
    /// The name of the network namespace
    pub ns_name: String,
    /// Path to the network namespace file
    pub ns_path: PathBuf,
    /// Name of the veth interface inside the namespace
    pub ns_veth: String,
    /// Name of the veth interface on the host side
    pub host_veth: String,
    /// Configuration used to create this environment
    pub config: NetworkTestConfig,
    /// Port for the echo server
    pub server_port: u16,
    /// Child processes spawned in the namespace (for cleanup)
    children: Vec<Child>,
}

/// Run a command and return the output
fn run_cmd(cmd: &str, args: &[&str]) -> io::Result<Output> {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

/// Run a command inside a network namespace
fn run_cmd_in_ns(ns_name: &str, cmd: &str, args: &[&str]) -> io::Result<Output> {
    let mut full_args = vec!["netns", "exec", ns_name, cmd];
    full_args.extend(args);
    run_cmd("ip", &full_args)
}

/// Spawn a command inside a network namespace (non-blocking)
fn spawn_cmd_in_ns(ns_name: &str, cmd: &str, args: &[&str]) -> io::Result<Child> {
    let mut full_args = vec!["netns", "exec", ns_name, cmd];
    full_args.extend(args);
    Command::new("ip")
        .args(&full_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// Check if a command succeeded, returning an error with stderr if it failed
fn check_output(output: Output, context: &str) -> io::Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::other(format!("{context}: {}", stderr.trim())))
    }
}

#[allow(dead_code)]
impl NetnsTestEnv {
    /// Default port for the echo server
    const DEFAULT_SERVER_PORT: u16 = 8765;

    /// Maximum time to wait for server readiness (5 seconds total)
    const SERVER_READY_TIMEOUT_MS: u64 = 5000;

    /// Interval between readiness checks
    const SERVER_READY_POLL_MS: u64 = 100;

    /// Grace period after port is detected open (for socat to be fully ready)
    const SERVER_READY_GRACE_MS: u64 = 50;

    /// Create a new network namespace test environment
    pub fn new(config: NetworkTestConfig) -> io::Result<Self> {
        let pid = std::process::id();
        let ns_name = format!("{}_{}", config.ns_name_prefix, pid);
        let host_veth = format!("veth_h_{pid}");
        let ns_veth = format!("veth_n_{pid}");

        // Create the network namespace
        let output = run_cmd("ip", &["netns", "add", &ns_name])?;
        check_output(output, "Failed to create namespace")?;

        // From here on, we need to clean up on failure
        let cleanup_ns = || {
            let _ = run_cmd("ip", &["netns", "delete", &ns_name]);
        };

        // Create veth pair
        let output = run_cmd(
            "ip",
            &[
                "link", "add", &host_veth, "type", "veth", "peer", "name", &ns_veth,
            ],
        );
        if let Err(e) = output.and_then(|o| check_output(o, "Failed to create veth pair")) {
            cleanup_ns();
            return Err(e);
        }

        // Move ns_veth into the namespace
        let output = run_cmd("ip", &["link", "set", &ns_veth, "netns", &ns_name]);
        if let Err(e) = output.and_then(|o| check_output(o, "Failed to move veth to namespace")) {
            let _ = run_cmd("ip", &["link", "delete", &host_veth]);
            cleanup_ns();
            return Err(e);
        }

        // Configure host-side veth
        let host_ip_cidr = format!("{}/{}", config.host_ip, config.prefix_len);
        let output = run_cmd("ip", &["addr", "add", &host_ip_cidr, "dev", &host_veth]);
        if let Err(e) = output.and_then(|o| check_output(o, "Failed to configure host veth IP")) {
            let _ = run_cmd("ip", &["link", "delete", &host_veth]);
            cleanup_ns();
            return Err(e);
        }

        let output = run_cmd("ip", &["link", "set", &host_veth, "up"]);
        if let Err(e) = output.and_then(|o| check_output(o, "Failed to bring up host veth")) {
            let _ = run_cmd("ip", &["link", "delete", &host_veth]);
            cleanup_ns();
            return Err(e);
        }

        // Configure namespace-side veth
        let ns_ip_cidr = format!("{}/{}", config.ns_ip, config.prefix_len);
        let output = run_cmd_in_ns(
            &ns_name,
            "ip",
            &["addr", "add", &ns_ip_cidr, "dev", &ns_veth],
        );
        if let Err(e) = output.and_then(|o| check_output(o, "Failed to configure ns veth IP")) {
            let _ = run_cmd("ip", &["link", "delete", &host_veth]);
            cleanup_ns();
            return Err(e);
        }

        let output = run_cmd_in_ns(&ns_name, "ip", &["link", "set", &ns_veth, "up"]);
        if let Err(e) = output.and_then(|o| check_output(o, "Failed to bring up ns veth")) {
            let _ = run_cmd("ip", &["link", "delete", &host_veth]);
            cleanup_ns();
            return Err(e);
        }

        // Bring up loopback in namespace
        let output = run_cmd_in_ns(&ns_name, "ip", &["link", "set", "lo", "up"]);
        if let Err(e) = output.and_then(|o| check_output(o, "Failed to bring up loopback")) {
            let _ = run_cmd("ip", &["link", "delete", &host_veth]);
            cleanup_ns();
            return Err(e);
        }

        let ns_path = PathBuf::from(format!("/var/run/netns/{ns_name}"));

        let mut env = Self {
            ns_name,
            ns_path,
            ns_veth,
            host_veth,
            config,
            server_port: Self::DEFAULT_SERVER_PORT,
            children: Vec::new(),
        };

        // Start TCP echo server using socat
        env.start_echo_server()?;

        Ok(env)
    }

    /// Start a TCP echo server in the namespace using socat
    fn start_echo_server(&mut self) -> io::Result<()> {
        let listen_addr = format!("TCP-LISTEN:{},fork,reuseaddr", self.server_port);
        let child = spawn_cmd_in_ns(&self.ns_name, "socat", &[&listen_addr, "EXEC:cat"])?;
        self.children.push(child);

        // Wait for server to be ready by attempting to connect
        self.wait_for_server_ready()?;

        Ok(())
    }

    /// Wait for the echo server to be ready to accept connections
    fn wait_for_server_ready(&self) -> io::Result<()> {
        let max_attempts = Self::SERVER_READY_TIMEOUT_MS / Self::SERVER_READY_POLL_MS;
        let delay = Duration::from_millis(Self::SERVER_READY_POLL_MS);

        for _ in 0..max_attempts {
            // Try to connect using nc from outside the namespace
            let output = run_cmd(
                "nc",
                &[
                    "-z",
                    "-w",
                    "1",
                    &self.config.ns_ip.to_string(),
                    &self.server_port.to_string(),
                ],
            );
            if output.map(|o| o.status.success()).unwrap_or(false) {
                // Grace period for socat to be fully ready after port is open
                thread::sleep(Duration::from_millis(Self::SERVER_READY_GRACE_MS));
                return Ok(());
            }
            thread::sleep(delay);
        }

        Err(io::Error::new(
            ErrorKind::TimedOut,
            format!(
                "Echo server did not become ready within {}ms",
                Self::SERVER_READY_TIMEOUT_MS
            ),
        ))
    }

    /// Spawn a process inside the network namespace
    pub fn spawn_in_ns(&mut self, command: &str, args: &[&str]) -> io::Result<&Child> {
        let idx = self.children.len();
        let child = spawn_cmd_in_ns(&self.ns_name, command, args)?;
        self.children.push(child);
        // Safe: we just pushed to children at idx
        Ok(&self.children[idx])
    }

    /// Run a command inside the network namespace and wait for completion
    pub fn run_in_ns(&self, command: &str, args: &[&str]) -> io::Result<Output> {
        run_cmd_in_ns(&self.ns_name, command, args)
    }

    /// Returns the server address as "ip:port" for client connections
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.config.ns_ip, self.server_port)
    }

    /// Generate traffic by connecting to the server and exchanging data
    ///
    /// Connects to the echo server via TcpStream, writes the message,
    /// shuts down the write side, reads the response, and returns
    /// the total bytes exchanged (sent + received).
    pub fn generate_traffic(&self, message: &[u8]) -> Result<usize> {
        let addr = self.server_addr();
        let mut stream =
            TcpStream::connect(&addr).with_context(|| format!("Failed to connect to {addr}"))?;

        // Write the message
        stream
            .write_all(message)
            .context("Failed to write message to server")?;

        // Shutdown write side to signal end of message
        stream
            .shutdown(std::net::Shutdown::Write)
            .context("Failed to shutdown write side")?;

        // Read the echoed response
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .context("Failed to read response from server")?;

        // Return total bytes exchanged
        Ok(message.len() + response.len())
    }

    /// Generate traffic using explicit poll() syscall
    ///
    /// This method uses non-blocking I/O with explicit poll() calls to ensure
    /// poll/epoll events are captured by systing's BPF probes. It connects to
    /// the echo server, uses poll() to wait for writability, writes the message,
    /// uses poll() to wait for readability, and reads the response.
    ///
    /// Returns the total bytes exchanged (sent + received).
    pub fn generate_traffic_with_poll(&self, message: &[u8]) -> Result<usize> {
        use std::os::unix::io::AsRawFd;

        let addr = self.server_addr();

        // Create a non-blocking TCP connection
        let stream =
            TcpStream::connect(&addr).with_context(|| format!("Failed to connect to {addr}"))?;
        stream
            .set_nonblocking(true)
            .context("Failed to set non-blocking mode")?;

        let fd = stream.as_raw_fd();

        // Poll for write readiness (POLLOUT)
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };

        // SAFETY: pollfd is properly initialized with a valid fd from TcpStream,
        // nfds=1 matches the single pollfd, and timeout is a valid millisecond value.
        let ret = unsafe { libc::poll(&mut pollfd, 1, 5000) };
        if ret < 0 {
            anyhow::bail!("poll() for POLLOUT failed: {}", io::Error::last_os_error());
        }
        if ret == 0 {
            anyhow::bail!("poll() for POLLOUT timed out");
        }
        if pollfd.revents & libc::POLLOUT == 0 {
            anyhow::bail!(
                "poll() returned but POLLOUT not set, revents={}",
                pollfd.revents
            );
        }

        // Write the message (may need multiple writes for non-blocking)
        let mut total_written = 0;
        while total_written < message.len() {
            match (&stream).write(&message[total_written..]) {
                Ok(0) => anyhow::bail!("write() returned 0"),
                Ok(n) => total_written += n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    // Poll again for writability
                    pollfd.events = libc::POLLOUT;
                    pollfd.revents = 0;
                    // SAFETY: pollfd is valid, nfds=1, timeout is valid.
                    let ret = unsafe { libc::poll(&mut pollfd, 1, 5000) };
                    if ret < 0 {
                        anyhow::bail!(
                            "poll() for write continuation failed: {}",
                            io::Error::last_os_error()
                        );
                    }
                    if ret == 0 {
                        anyhow::bail!("poll() for write continuation timed out");
                    }
                }
                Err(e) => return Err(e).context("write() failed"),
            }
        }

        // Shutdown write side to signal end of message
        stream
            .shutdown(std::net::Shutdown::Write)
            .context("Failed to shutdown write side")?;

        // Poll for read readiness (POLLIN)
        pollfd.events = libc::POLLIN;
        pollfd.revents = 0;

        // SAFETY: pollfd is valid, nfds=1, timeout is valid.
        let ret = unsafe { libc::poll(&mut pollfd, 1, 5000) };
        if ret < 0 {
            anyhow::bail!("poll() for POLLIN failed: {}", io::Error::last_os_error());
        }
        if ret == 0 {
            anyhow::bail!("poll() for POLLIN timed out");
        }
        if pollfd.revents & libc::POLLIN == 0 {
            anyhow::bail!(
                "poll() returned but POLLIN not set, revents={}",
                pollfd.revents
            );
        }

        // Read the echoed response
        let mut response = Vec::new();
        loop {
            let mut buf = [0u8; 1024];
            match (&stream).read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    // Poll again for readability
                    pollfd.events = libc::POLLIN;
                    pollfd.revents = 0;
                    // SAFETY: pollfd is valid, nfds=1, timeout is valid.
                    let ret = unsafe { libc::poll(&mut pollfd, 1, 5000) };
                    if ret < 0 {
                        anyhow::bail!("poll() during read failed: {}", io::Error::last_os_error());
                    }
                    if ret == 0 {
                        // Timeout - no more data available, assume done
                        break;
                    }
                }
                Err(e) => return Err(e).context("read() failed"),
            }
        }

        // Return total bytes exchanged
        Ok(message.len() + response.len())
    }
}

impl Drop for NetnsTestEnv {
    fn drop(&mut self) {
        // Kill any spawned child processes
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Delete host veth (this also removes the peer in the namespace)
        let _ = run_cmd("ip", &["link", "delete", &self.host_veth]);

        // Delete the namespace
        let _ = run_cmd("ip", &["netns", "delete", &self.ns_name]);
    }
}

/// Result of validating network trace data
#[derive(Debug, Default)]
pub struct NetworkValidationResult {
    /// Number of socket records found
    pub socket_count: usize,
    /// Number of syscall records found
    pub syscall_count: usize,
    /// Number of packet records found
    pub packet_count: usize,
    /// Number of poll/epoll events found
    pub poll_count: usize,
    /// Errors encountered during validation
    pub errors: Vec<String>,
}

#[allow(dead_code)]
impl NetworkValidationResult {
    /// Returns true if the validation passed (no errors)
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate network trace Parquet files in a directory
///
/// Reads network_socket.parquet, network_syscall.parquet, and network_packet.parquet
/// and counts the records in each file.
pub fn validate_network_trace(output_dir: &Path) -> Result<NetworkValidationResult> {
    let mut result = NetworkValidationResult::default();

    // Read network_socket.parquet
    let socket_path = output_dir.join("network_socket.parquet");
    if socket_path.exists() {
        match count_parquet_records(&socket_path) {
            Ok(count) => result.socket_count = count,
            Err(e) => result
                .errors
                .push(format!("Failed to read network_socket.parquet: {e}")),
        }
    }

    // Read network_syscall.parquet
    let syscall_path = output_dir.join("network_syscall.parquet");
    if syscall_path.exists() {
        match count_parquet_records(&syscall_path) {
            Ok(count) => result.syscall_count = count,
            Err(e) => result
                .errors
                .push(format!("Failed to read network_syscall.parquet: {e}")),
        }
    }

    // Read network_packet.parquet
    let packet_path = output_dir.join("network_packet.parquet");
    if packet_path.exists() {
        match count_parquet_records(&packet_path) {
            Ok(count) => result.packet_count = count,
            Err(e) => result
                .errors
                .push(format!("Failed to read network_packet.parquet: {e}")),
        }
    }

    // Read network_poll.parquet
    let poll_path = output_dir.join("network_poll.parquet");
    if poll_path.exists() {
        match count_parquet_records(&poll_path) {
            Ok(count) => result.poll_count = count,
            Err(e) => result
                .errors
                .push(format!("Failed to read network_poll.parquet: {e}")),
        }
    }

    Ok(result)
}

/// Count records in a Parquet file
fn count_parquet_records(path: &Path) -> Result<usize> {
    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    let mut count = 0;
    for batch_result in reader {
        let batch = batch_result?;
        count += batch.num_rows();
    }

    Ok(count)
}

/// Assert that a socket with the given parameters was recorded
///
/// Searches network_socket.parquet for a socket matching the given
/// source IP, destination IP, and destination port. Returns the
/// socket_id if found, or an error if not found.
#[allow(dead_code)]
pub fn assert_socket_recorded(
    output_dir: &Path,
    src_ip: &str,
    dest_ip: &str,
    dest_port: u16,
) -> Result<i64> {
    let socket_path = output_dir.join("network_socket.parquet");
    if !socket_path.exists() {
        anyhow::bail!("network_socket.parquet not found in {:?}", output_dir);
    }

    let file = File::open(&socket_path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    for batch_result in reader {
        let batch = batch_result?;

        // Get the columns we need
        let socket_ids = batch
            .column_by_name("socket_id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("Missing socket_id column in network_socket")?;

        let src_ips = batch
            .column_by_name("src_ip")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .context("Missing src_ip column in network_socket")?;

        let dest_ips = batch
            .column_by_name("dest_ip")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .context("Missing dest_ip column in network_socket")?;

        let dest_ports = batch
            .column_by_name("dest_port")
            .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
            .context("Missing dest_port column in network_socket")?;

        // Search for matching socket
        for i in 0..batch.num_rows() {
            let row_src_ip = src_ips.value(i);
            let row_dest_ip = dest_ips.value(i);
            let row_dest_port = dest_ports.value(i) as u16;

            if row_src_ip == src_ip && row_dest_ip == dest_ip && row_dest_port == dest_port {
                return Ok(socket_ids.value(i));
            }
        }
    }

    anyhow::bail!(
        "No socket found matching src_ip={}, dest_ip={}, dest_port={}",
        src_ip,
        dest_ip,
        dest_port
    )
}

/// Count poll events for a specific socket ID
///
/// Searches network_poll.parquet for poll events matching the given socket_id.
/// Returns the count of matching poll events.
#[allow(dead_code)]
pub fn count_poll_events_for_socket(output_dir: &Path, socket_id: i64) -> Result<usize> {
    let poll_path = output_dir.join("network_poll.parquet");
    if !poll_path.exists() {
        return Ok(0);
    }

    let file = File::open(&poll_path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    let mut count = 0;
    for batch_result in reader {
        let batch = batch_result?;

        let socket_ids = batch
            .column_by_name("socket_id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("Missing socket_id column in network_poll")?;

        for i in 0..batch.num_rows() {
            if socket_ids.value(i) == socket_id {
                count += 1;
            }
        }
    }

    Ok(count)
}

/// Assert that poll events were recorded for a socket
///
/// Searches network_poll.parquet for poll events matching any of the
/// sockets with dest_ip in the test network (10.200.x.x). Returns the
/// count of poll events found, or an error if none were found.
#[allow(dead_code)]
pub fn assert_poll_events_recorded(output_dir: &Path, test_network_prefix: &str) -> Result<usize> {
    // First, find all socket IDs with dest_ip matching the test network
    let socket_path = output_dir.join("network_socket.parquet");
    if !socket_path.exists() {
        anyhow::bail!("network_socket.parquet not found in {:?}", output_dir);
    }

    let file = File::open(&socket_path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    let mut test_socket_ids = std::collections::HashSet::new();

    for batch_result in reader {
        let batch = batch_result?;

        let socket_ids = batch
            .column_by_name("socket_id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("Missing socket_id column in network_socket")?;

        let dest_ips = batch
            .column_by_name("dest_ip")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .context("Missing dest_ip column in network_socket")?;

        let src_ips = batch
            .column_by_name("src_ip")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .context("Missing src_ip column in network_socket")?;

        for i in 0..batch.num_rows() {
            let dest_ip = dest_ips.value(i);
            let src_ip = src_ips.value(i);
            if dest_ip.starts_with(test_network_prefix) || src_ip.starts_with(test_network_prefix) {
                test_socket_ids.insert(socket_ids.value(i));
            }
        }
    }

    if test_socket_ids.is_empty() {
        anyhow::bail!(
            "No sockets found with IPs matching network prefix {}",
            test_network_prefix
        );
    }

    // Now count poll events for these sockets
    let poll_path = output_dir.join("network_poll.parquet");
    if !poll_path.exists() {
        anyhow::bail!(
            "network_poll.parquet not found in {:?}, but expected poll events",
            output_dir
        );
    }

    let file = File::open(&poll_path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    let mut poll_count = 0;
    for batch_result in reader {
        let batch = batch_result?;

        let socket_ids = batch
            .column_by_name("socket_id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("Missing socket_id column in network_poll")?;

        for i in 0..batch.num_rows() {
            if test_socket_ids.contains(&socket_ids.value(i)) {
                poll_count += 1;
            }
        }
    }

    if poll_count == 0 {
        anyhow::bail!(
            "No poll events found for {} test sockets in network {}",
            test_socket_ids.len(),
            test_network_prefix
        );
    }

    Ok(poll_count)
}
