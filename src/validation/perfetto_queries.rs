//! Perfetto-specific validation query implementation.
//!
//! This module implements `ValidationQueries` for Perfetto protobuf traces.
//! Unlike Parquet and DuckDB, Perfetto uses streaming - all data is parsed
//! in a single pass and cached for queries.
//!
//! Note: Perfetto validation also has format-specific checks (track UUIDs,
//! compact_sched, clock snapshots, network syscalls) that are NOT part of
//! the unified trait and are implemented as separate methods.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::config::ValidationConfig;
use super::perfetto_reader::{open_trace_reader, TracePacketIterator};
use super::queries::{
    CmdlineStats, FieldCheck, OrphanCheck, SchemaResult, StackViolation, ValidationQueries,
};
use super::result::{ValidationError, ValidationResult, ValidationWarning};
use super::runner::run_common_validations;

/// Perfetto-specific validation query implementation.
///
/// All data is parsed in a single pass and cached internally.
/// Query methods return cached results.
pub struct PerfettoQueries {
    /// Parsed trace context - populated on creation.
    context: PerfettoContext,
    /// Whether parsing succeeded.
    parse_error: Option<String>,
}

/// Internal context for Perfetto trace validation.
/// Accumulated during single-pass streaming.
#[derive(Default)]
pub struct PerfettoContext {
    // === Track/Process/Thread Data ===
    /// All defined track UUIDs
    pub defined_tracks: HashSet<u64>,
    /// Track UUIDs referenced by events (track_uuid -> first timestamp seen)
    pub referenced_tracks: HashMap<u64, u64>,
    /// Parent UUID references (child_uuid -> parent_uuid)
    pub parent_refs: HashMap<u64, u64>,
    /// Track UUIDs that have ThreadDescriptor or ProcessDescriptor
    pub thread_process_tracks: HashSet<u64>,
    /// Track names (track_uuid -> name)
    pub track_names: HashMap<u64, String>,

    // === Process/Thread Name Validation ===
    /// Count of processes with empty names (excluding pid=0)
    pub empty_process_names: i64,
    /// Total user-space processes
    pub total_processes: i64,
    /// Sample pids with empty names
    pub sample_empty_process_pids: Vec<i64>,

    /// Count of threads with empty names (excluding tid=0)
    pub empty_thread_names: i64,
    /// Total threads
    pub total_threads: i64,
    /// Sample tids with empty names
    pub sample_empty_thread_tids: Vec<i64>,

    // === Cmdline Validation ===
    /// Count of user-space processes with empty cmdline
    pub empty_cmdline_count: i64,
    /// Count of user-space processes with non-empty cmdline
    pub has_cmdline_count: i64,

    // === Network Event Validation ===
    /// Network syscall events that need to be on per-thread tracks
    pub network_syscall_events: HashMap<(u64, String), u64>,
    /// UUID of the "Network Packets" root track, if present
    pub network_packets_root_uuid: Option<u64>,

    // === Clock/System Info ===
    /// Whether we've seen a clock snapshot
    pub has_clock_snapshot: bool,
    /// Whether we've seen valid SystemInfo with utsname
    pub has_valid_system_info: bool,

    // === Sched Event Validation ===
    /// Counts of prev_state values from compact_sched
    pub prev_state_counts: HashMap<i64, u64>,
    /// Track which CPUs we've seen first switch events for
    pub cpus_seen_first_switch: HashSet<u32>,
    /// Comm strings seen for pid=0 (swapper/idle) in sched events
    pub pid_zero_comms: HashMap<String, u64>,

    // === Errors/Warnings accumulated during parsing ===
    /// Errors found during streaming parse
    pub errors: Vec<ValidationError>,
    /// Warnings found during streaming parse
    pub warnings: Vec<ValidationWarning>,
}

impl PerfettoQueries {
    /// Create a new PerfettoQueries by parsing the trace file.
    ///
    /// The entire trace is parsed in this constructor. Query methods
    /// return cached results.
    pub fn new(path: &Path) -> Result<Self> {
        let mut context = PerfettoContext::default();

        // Parse the trace file
        match parse_perfetto_trace(path, &mut context) {
            Ok(()) => Ok(Self {
                context,
                parse_error: None,
            }),
            Err(e) => Ok(Self {
                context,
                parse_error: Some(e.to_string()),
            }),
        }
    }

    /// Get the accumulated errors from parsing.
    pub fn get_errors(&self) -> &[ValidationError] {
        &self.context.errors
    }

    /// Get the accumulated warnings from parsing.
    pub fn get_warnings(&self) -> &[ValidationWarning] {
        &self.context.warnings
    }

    /// Get the parse error if any.
    pub fn parse_error(&self) -> Option<&str> {
        self.parse_error.as_deref()
    }

    /// Get the parsed context for format-specific validation.
    pub fn context(&self) -> &PerfettoContext {
        &self.context
    }

    // === Perfetto-specific validation methods ===

    /// Validate that all referenced track UUIDs have been defined.
    pub fn validate_track_uuid_refs(&self, result: &mut ValidationResult) {
        for track_uuid in self.context.referenced_tracks.keys() {
            if !self.context.defined_tracks.contains(track_uuid) {
                result.add_error(ValidationError::PerfettoError {
                    message: format!("TrackEvent references undefined track_uuid {track_uuid}"),
                });
                return; // Only report first error
            }
        }
    }

    /// Validate that parent_uuid references form a valid tree.
    pub fn validate_parent_uuid_hierarchy(&self, result: &mut ValidationResult) {
        // Check for undefined parent references
        for (child_uuid, parent_uuid) in &self.context.parent_refs {
            if !self.context.defined_tracks.contains(parent_uuid) {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "TrackDescriptor {child_uuid} has parent_uuid {parent_uuid} \
                         which is not defined"
                    ),
                });
                return;
            }
        }

        // Check for cycles
        for start_uuid in self.context.parent_refs.keys() {
            let mut visited = HashSet::new();
            let mut current = *start_uuid;

            while let Some(&parent) = self.context.parent_refs.get(&current) {
                if !visited.insert(current) {
                    result.add_error(ValidationError::PerfettoError {
                        message: format!(
                            "Cycle detected in track parent hierarchy involving track {current}"
                        ),
                    });
                    return;
                }
                current = parent;
            }
        }
    }

    /// Validate that at least one ClockSnapshot exists.
    pub fn validate_clock_snapshot_exists(&self, result: &mut ValidationResult) {
        if !self.context.has_clock_snapshot {
            result.add_error(ValidationError::PerfettoError {
                message: "No ClockSnapshot packet found in trace".to_string(),
            });
        }
    }

    /// Validate that SystemInfo with valid utsname exists.
    pub fn validate_system_info_exists(&self, result: &mut ValidationResult) {
        if !self.context.has_valid_system_info {
            result.add_error(ValidationError::PerfettoError {
                message: "No SystemInfo packet with valid utsname found in trace".to_string(),
            });
        }
    }

    /// Validate that network syscall events are on proper network tracks.
    pub fn validate_network_syscalls_on_network_tracks(&self, result: &mut ValidationResult) {
        for ((track_uuid, event_name), ts) in &self.context.network_syscall_events {
            let track_name = match self.context.track_names.get(track_uuid) {
                Some(name) => name,
                None => {
                    result.add_error(ValidationError::PerfettoError {
                        message: format!(
                            "Network syscall event '{event_name}' (track_uuid={track_uuid}, ts={ts}) \
                             is on a track without a name."
                        ),
                    });
                    continue;
                }
            };

            let is_valid_network_track =
                track_name == "Network" || track_name.starts_with("Network (tid ");
            if !is_valid_network_track {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "Network syscall event '{event_name}' (track_uuid={track_uuid}, ts={ts}) \
                         is on track '{track_name}'. Expected 'Network' or 'Network (tid N)'."
                    ),
                });
                continue;
            }

            // Check parent is thread/process track
            if let Some(&parent_uuid) = self.context.parent_refs.get(track_uuid) {
                if !self.context.thread_process_tracks.contains(&parent_uuid) {
                    result.add_error(ValidationError::PerfettoError {
                        message: format!(
                            "Network syscall event '{event_name}' (track_uuid={track_uuid}, ts={ts}) \
                             is on track '{track_name}' which is not parented to a thread/process track."
                        ),
                    });
                }
            } else {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "Network syscall event '{event_name}' (track_uuid={track_uuid}, ts={ts}) \
                         is on track '{track_name}' which has no parent."
                    ),
                });
            }
        }
    }

    /// Validate that socket tracks have socket_id in their name.
    pub fn validate_socket_tracks_have_socket_id(&self, result: &mut ValidationResult) {
        let Some(network_packets_uuid) = self.context.network_packets_root_uuid else {
            return;
        };

        for (track_uuid, parent_uuid) in &self.context.parent_refs {
            if *parent_uuid != network_packets_uuid {
                continue;
            }

            let Some(track_name) = self.context.track_names.get(track_uuid) else {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "Socket track (track_uuid={track_uuid}) under 'Network Packets' has no name"
                    ),
                });
                continue;
            };

            if !track_name.starts_with("Socket ") {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "Socket track '{track_name}' under 'Network Packets' must start with \
                         'Socket N:...' where N is the socket_id (track_uuid={track_uuid})"
                    ),
                });
            }
        }
    }

    /// Validate swapper/idle thread names.
    pub fn validate_swapper_thread_names(
        &self,
        min_sched_events: u64,
        result: &mut ValidationResult,
    ) {
        let total_sched_events: u64 = self.context.prev_state_counts.values().sum();

        if self.context.pid_zero_comms.is_empty() {
            if total_sched_events > min_sched_events {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "No sched events with next_pid=0 (swapper/idle) found, but trace has \
                         {total_sched_events} total sched events."
                    ),
                });
            }
            return;
        }

        let mut invalid_comms: Vec<(String, u64)> = Vec::new();
        let mut total_pid_zero_events: u64 = 0;

        for (comm, count) in &self.context.pid_zero_comms {
            total_pid_zero_events += count;

            let is_valid = comm.is_empty()
                || comm == "swapper"
                || comm.starts_with("swapper/")
                || comm == "<idle>";

            if !is_valid {
                invalid_comms.push((comm.clone(), *count));
            }
        }

        if !invalid_comms.is_empty() {
            invalid_comms.sort_by(|a, b| b.1.cmp(&a.1));
            let invalid_count: u64 = invalid_comms.iter().map(|(_, c)| c).sum();
            let invalid_percent = if total_pid_zero_events > 0 {
                (invalid_count as f64 / total_pid_zero_events as f64) * 100.0
            } else {
                0.0
            };

            let top_offenders: Vec<String> = invalid_comms
                .iter()
                .take(5)
                .map(|(comm, count)| format!("'{comm}' ({count} events)"))
                .collect();

            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "Idle thread (pid=0) has incorrect comm strings in {invalid_count}/{total_pid_zero_events} \
                     sched events ({invalid_percent:.1}%). Expected 'swapper' or 'swapper/N', \
                     but found: {}.",
                    top_offenders.join(", ")
                ),
            });
        }
    }

    /// Add all accumulated errors and warnings to the result.
    pub fn add_accumulated_to_result(&self, result: &mut ValidationResult) {
        if let Some(ref err) = self.parse_error {
            result.add_error(ValidationError::PerfettoError {
                message: format!("Failed to open trace file: {err}"),
            });
        }

        for error in &self.context.errors {
            result.errors.push(error.clone());
        }
        for warning in &self.context.warnings {
            result.warnings.push(warning.clone());
        }
    }
}

impl ValidationQueries for PerfettoQueries {
    fn format_name(&self) -> &'static str {
        "perfetto"
    }

    fn count_orphan_thread_upids(&mut self) -> Result<OrphanCheck> {
        // Perfetto doesn't have the same table structure as Parquet/DuckDB.
        // Thread/process relationships are through track hierarchy, not upid references.
        // Return OK - hierarchy validation is done through validate_parent_uuid_hierarchy.
        Ok(OrphanCheck::ok(0))
    }

    fn count_orphan_sched_utids(&mut self) -> Result<OrphanCheck> {
        // Perfetto compact_sched uses pids directly, not utids.
        // Return OK - this check doesn't apply to Perfetto.
        Ok(OrphanCheck::ok(0))
    }

    fn count_empty_process_names(&mut self) -> Result<FieldCheck> {
        Ok(FieldCheck {
            empty_count: self.context.empty_process_names,
            total_count: self.context.total_processes,
            sample_ids: self.context.sample_empty_process_pids.clone(),
        })
    }

    fn count_empty_thread_names(&mut self) -> Result<FieldCheck> {
        Ok(FieldCheck {
            empty_count: self.context.empty_thread_names,
            total_count: self.context.total_threads,
            sample_ids: self.context.sample_empty_thread_tids.clone(),
        })
    }

    fn get_cmdline_stats(&mut self) -> Result<CmdlineStats> {
        let total = self.context.empty_cmdline_count + self.context.has_cmdline_count;
        Ok(CmdlineStats {
            has_column: true, // Perfetto always has cmdline support
            empty_count: self.context.empty_cmdline_count,
            total_count: total,
        })
    }

    fn check_end_state_schema(&mut self) -> Result<SchemaResult> {
        // Perfetto uses prev_state in compact_sched, not end_state.
        // Return valid - schema check doesn't apply to Perfetto in the same way.
        Ok(SchemaResult::valid("compact_sched.prev_state"))
    }

    fn get_counter_unit_values(&mut self) -> Result<Vec<Option<String>>> {
        // Perfetto counter tracks are validated through CounterDescriptor.
        // Return empty - not applicable in the same way as Parquet/DuckDB.
        Ok(Vec::new())
    }

    fn find_stack_timing_violations(&mut self, _tolerance_ns: i64) -> Result<Vec<StackViolation>> {
        // Stack timing validation doesn't apply to Perfetto in the same way.
        // Perfetto PerfSamples are validated separately.
        Ok(Vec::new())
    }
}

/// Parse a Perfetto trace file and populate the context.
fn parse_perfetto_trace(path: &Path, context: &mut PerfettoContext) -> Result<()> {
    let reader = open_trace_reader(path)?;

    for packet_result in TracePacketIterator::new(reader) {
        match packet_result {
            Ok(packet) => {
                process_packet(&packet, context);
            }
            Err(e) => {
                context.errors.push(ValidationError::PerfettoError {
                    message: format!("Failed to parse packet: {e}"),
                });
            }
        }
    }

    Ok(())
}

/// Process a single TracePacket and update context.
fn process_packet(
    packet: &perfetto_protos::trace_packet::TracePacket,
    context: &mut PerfettoContext,
) {
    // Clock snapshot
    if packet.has_clock_snapshot() {
        context.has_clock_snapshot = true;
    }

    // Track descriptors
    if packet.has_track_descriptor() {
        let desc = packet.track_descriptor();
        let uuid = desc.uuid();

        context.defined_tracks.insert(uuid);

        if desc.has_name() {
            let name = desc.name().to_string();
            if name == "Network Packets" {
                context.network_packets_root_uuid = Some(uuid);
            }
            context.track_names.insert(uuid, name);
        }

        if desc.has_parent_uuid() {
            context.parent_refs.insert(uuid, desc.parent_uuid());
        }

        // ThreadDescriptor
        if let Some(thread) = desc.thread.as_ref() {
            context.thread_process_tracks.insert(uuid);
            context.total_threads += 1;

            // Check for empty thread_name (excluding tid=0)
            let tid = thread.tid();
            if tid != 0 && (!thread.has_thread_name() || thread.thread_name().is_empty()) {
                context.empty_thread_names += 1;
                if context.sample_empty_thread_tids.len() < 10 {
                    context.sample_empty_thread_tids.push(tid as i64);
                }
                context.errors.push(ValidationError::PerfettoError {
                    message: format!(
                        "ThreadDescriptor (track_uuid={}, tid={}) has empty or missing thread_name",
                        uuid, tid
                    ),
                });
            }

            // Check pid == tid error
            if thread.has_pid() && thread.has_tid() && thread.pid() == thread.tid() {
                context.errors.push(ValidationError::PerfettoError {
                    message: format!(
                        "ThreadDescriptor (track_uuid={}) has pid == tid ({}), main threads \
                         should use ProcessDescriptor instead",
                        uuid,
                        thread.pid()
                    ),
                });
            }
        }

        // ProcessDescriptor
        if let Some(process) = desc.process.as_ref() {
            context.thread_process_tracks.insert(uuid);
            let pid = process.pid();

            if pid != 0 {
                context.total_processes += 1;

                // Check process_name
                if !process.has_process_name() || process.process_name().is_empty() {
                    context.empty_process_names += 1;
                    if context.sample_empty_process_pids.len() < 10 {
                        context.sample_empty_process_pids.push(pid as i64);
                    }
                    context.errors.push(ValidationError::PerfettoError {
                        message: format!(
                            "ProcessDescriptor (track_uuid={}, pid={}) has empty or missing process_name",
                            uuid, pid
                        ),
                    });
                }

                // Check cmdline
                if process.cmdline.is_empty() {
                    context.empty_cmdline_count += 1;
                } else {
                    context.has_cmdline_count += 1;
                }
            }
        }
    }

    // Track events
    if packet.has_track_event() {
        let event = packet.track_event();
        if event.has_track_uuid() {
            let track_uuid = event.track_uuid();
            let ts = packet.timestamp();
            context.referenced_tracks.entry(track_uuid).or_insert(ts);

            // Network syscall events
            let is_network_syscall = event.categories.iter().any(|c| c == "network")
                && event.has_name()
                && matches!(event.name(), "sendmsg" | "recvmsg" | "poll");

            if is_network_syscall {
                context
                    .network_syscall_events
                    .entry((track_uuid, event.name().to_string()))
                    .or_insert(ts);
            }
        }
    }

    // Ftrace events with CompactSched
    if packet.has_ftrace_events() {
        let events = packet.ftrace_events();
        if let Some(compact) = events.compact_sched.as_ref() {
            let cpu = events.cpu();
            process_compact_sched(compact, cpu, context);
        }
    }

    // PerfSample validation
    if packet.has_perf_sample() {
        let sample = packet.perf_sample();
        if sample.has_pid() && sample.has_tid() && sample.pid() == 0 && sample.tid() == 0 {
            context.errors.push(ValidationError::PerfettoError {
                message: format!(
                    "PerfSample has both pid and tid set to 0 (timestamp={})",
                    packet.timestamp()
                ),
            });
        }
    }

    // SystemInfo
    if packet.has_system_info() && !context.has_valid_system_info {
        let system_info = packet.system_info();
        if let Some(utsname) = system_info.utsname.as_ref() {
            let mut missing_fields = Vec::new();

            if !utsname.has_sysname() || utsname.sysname().is_empty() {
                missing_fields.push("sysname");
            }
            if !utsname.has_release() || utsname.release().is_empty() {
                missing_fields.push("release");
            }
            if !utsname.has_version() || utsname.version().is_empty() {
                missing_fields.push("version");
            }
            if !utsname.has_machine() || utsname.machine().is_empty() {
                missing_fields.push("machine");
            }

            if missing_fields.is_empty() {
                context.has_valid_system_info = true;
            } else {
                context.errors.push(ValidationError::PerfettoError {
                    message: format!(
                        "SystemInfo.utsname is missing required fields: {}",
                        missing_fields.join(", ")
                    ),
                });
            }
        } else {
            context.errors.push(ValidationError::PerfettoError {
                message: "SystemInfo.utsname is not set".to_string(),
            });
        }
    }
}

/// Process CompactSched events.
fn process_compact_sched(
    compact: &perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched,
    cpu: u32,
    context: &mut PerfettoContext,
) {
    let intern_len = compact.intern_table.len();

    // Validate intern table bounds
    for (i, &comm_index) in compact.switch_next_comm_index.iter().enumerate() {
        if intern_len == 0 || (comm_index as usize) >= intern_len {
            context.errors.push(ValidationError::PerfettoError {
                message: format!(
                    "CompactSched: switch_next_comm_index[{i}] = {comm_index} \
                     is out of bounds (intern_table.len = {intern_len})"
                ),
            });
            return;
        }
    }

    for (i, &comm_index) in compact.waking_comm_index.iter().enumerate() {
        if intern_len == 0 || (comm_index as usize) >= intern_len {
            context.errors.push(ValidationError::PerfettoError {
                message: format!(
                    "CompactSched: waking_comm_index[{i}] = {comm_index} \
                     is out of bounds (intern_table.len = {intern_len})"
                ),
            });
            return;
        }
    }

    // Validate first switch per CPU
    if !compact.switch_prev_state.is_empty() && !context.cpus_seen_first_switch.contains(&cpu) {
        context.cpus_seen_first_switch.insert(cpu);
        let first_prev_state = compact.switch_prev_state[0];
        if first_prev_state != 0 {
            context.errors.push(ValidationError::PerfettoError {
                message: format!(
                    "CompactSched CPU {cpu}: first switch has prev_state={first_prev_state}, \
                     expected 0 (at trace start, previous task state is unknown)."
                ),
            });
        }
    }

    // Collect prev_state distribution
    for &prev_state in &compact.switch_prev_state {
        *context.prev_state_counts.entry(prev_state).or_insert(0) += 1;
    }

    // Collect pid=0 comm strings
    for (i, &next_pid) in compact.switch_next_pid.iter().enumerate() {
        if next_pid == 0 {
            let comm_idx = compact.switch_next_comm_index.get(i).copied().unwrap_or(0) as usize;
            let comm = compact
                .intern_table
                .get(comm_idx)
                .map(String::as_str)
                .unwrap_or("");
            *context.pid_zero_comms.entry(comm.to_string()).or_insert(0) += 1;
        }
    }
}

// ============================================================================
// Entry Point
// ============================================================================

/// Validate a Perfetto trace file (.pb or .pb.gz).
///
/// Checks:
/// - All TracePackets parse correctly
/// - Track UUIDs are defined before being referenced
/// - Parent UUIDs form a valid tree
/// - CompactSched intern table bounds
/// - At least one ClockSnapshot exists
pub fn validate_perfetto_trace(path: &Path) -> ValidationResult {
    let mut result = ValidationResult::default();

    // Use the unified validation framework
    let mut queries = match PerfettoQueries::new(path) {
        Ok(q) => q,
        Err(e) => {
            result.add_error(ValidationError::PerfettoError {
                message: format!("Failed to parse trace file: {e}"),
            });
            return result;
        }
    };

    // Run common validations (names, cmdline, etc.)
    let config = ValidationConfig::default();
    run_common_validations(&mut queries, &config, &mut result);

    // Add accumulated errors and warnings from parsing
    queries.add_accumulated_to_result(&mut result);

    // Run Perfetto-specific validations
    queries.validate_track_uuid_refs(&mut result);
    queries.validate_parent_uuid_hierarchy(&mut result);
    queries.validate_clock_snapshot_exists(&mut result);
    queries.validate_system_info_exists(&mut result);
    queries.validate_network_syscalls_on_network_tracks(&mut result);
    queries.validate_socket_tracks_have_socket_id(&mut result);
    queries
        .validate_swapper_thread_names(config.min_sched_events_for_swapper_validation, &mut result);

    result
}
