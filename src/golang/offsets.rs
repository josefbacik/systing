//! Go version-specific layouts of the runtime's structs.
//!
//! The numbers are generated from the runtime's own DWARF
//! (`scripts/generate_go_bindings.py` writes [`super::bindings`]). Unlike
//! Python's, an unknown version has no fallback: the runtime's private
//! structs change between minor releases (Go 1.27's heap record is half the
//! size of 1.26's), and a wrong layout would read wrong numbers, not fail.
//! A new version is a new bindings file and a line in [`for_version`].

use super::bindings;

/// Where the readers find what they read, in one Go version.
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    /// `runtime.bucket`: its fixed part, which the stack and then the
    /// record follow, and the fields read in it.
    pub bucket_size: usize,
    pub bucket_allnext: usize,
    pub bucket_typ: usize,
    pub bucket_nstk: usize,
    /// `runtime.memRecord`: an active cycle, then `future_cycles` more.
    pub mem_record_size: usize,
    pub mem_record_active: usize,
    pub mem_record_future: usize,
    pub mem_record_future_cycles: usize,
    /// `runtime.memRecordCycle`.
    pub cycle_size: usize,
    pub cycle_allocs: usize,
    pub cycle_frees: usize,
    pub cycle_alloc_bytes: usize,
    pub cycle_free_bytes: usize,
    /// `runtime.blockRecord`.
    pub block_record_size: usize,
    pub block_record_count: usize,
    pub block_record_cycles: usize,
    /// `runtime.ticksType`.
    pub ticks_start_ticks: usize,
    pub ticks_start_time: usize,
    pub ticks_val: usize,
    /// `runtime.g`.
    pub g_stack_hi: usize,
    pub g_sched_pc: usize,
    pub g_sched_bp: usize,
    pub g_syscallpc: usize,
    pub g_syscallbp: usize,
    pub g_atomicstatus: usize,
    pub g_goid: usize,
    pub g_waitsince: usize,
    pub g_waitreason: usize,
    pub g_startpc: usize,
    /// `runtime.g.labels`: the goroutine's profiler labels, a
    /// `*runtime/pprof.labelMap` (nil without labels).
    pub g_labels: usize,
    /// Where a `labelMap`'s slice of labels is, and a label's size and
    /// fields (two strings).
    pub label_map_list: usize,
    pub label_size: usize,
    pub label_key: usize,
    pub label_value: usize,
    /// `runtime/trace`'s multiplexer, recorder and flight recorder.
    pub trace_mux_flight_recorder: usize,
    pub trace_recorder_r: usize,
    pub flight_recorder_header: usize,
    pub flight_recorder_ring: usize,
    pub raw_generation_size: usize,
    pub raw_generation_gen: usize,
    pub raw_generation_batches: usize,
    /// `bucketType` values.
    pub mem_profile: u64,
    pub block_profile: u64,
    pub mutex_profile: u64,
    /// Goroutine states, and the scan bit over them.
    pub g_running: u32,
    pub g_syscall: u32,
    pub g_dead: u32,
    pub g_deadextra: u32,
    pub g_scan: u32,
    /// The trace format's batch events.
    pub ev_event_batch: u8,
    pub ev_experimental_batch: u8,
    pub ev_end_of_generation: u8,
    /// `gStatusStrings`, by goroutine state.
    pub status_names: &'static [&'static str],
    /// `waitReasonStrings`, by `waitReason`.
    pub wait_reasons: &'static [&'static str],
}

impl Layout {
    /// How much of a `runtime.g` the goroutine reader needs: up to the end of
    /// the last field it reads.
    pub fn g_read_len(&self) -> usize {
        [
            self.g_stack_hi,
            self.g_sched_pc,
            self.g_sched_bp,
            self.g_syscallpc,
            self.g_syscallbp,
            self.g_atomicstatus,
            self.g_goid,
            self.g_waitsince,
            self.g_waitreason,
            self.g_startpc,
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
            + 8
    }
}

/// The layout for Go 1.`minor`, if this reader has its bindings.
pub fn for_version(major: u32, minor: u32) -> Option<Layout> {
    match (major, minor) {
        (1, 26) => Some(go1_26()),
        _ => None,
    }
}

pub fn go1_26() -> Layout {
    use bindings::v1_26::*;
    Layout {
        bucket_size: BUCKET_SIZE,
        bucket_allnext: BUCKET_ALLNEXT,
        bucket_typ: BUCKET_TYP,
        bucket_nstk: BUCKET_NSTK,
        mem_record_size: MEM_RECORD_SIZE,
        mem_record_active: MEM_RECORD_ACTIVE,
        mem_record_future: MEM_RECORD_FUTURE,
        mem_record_future_cycles: MEM_RECORD_FUTURE_CYCLES,
        cycle_size: MEM_RECORD_CYCLE_SIZE,
        cycle_allocs: MEM_RECORD_CYCLE_ALLOCS,
        cycle_frees: MEM_RECORD_CYCLE_FREES,
        cycle_alloc_bytes: MEM_RECORD_CYCLE_ALLOC_BYTES,
        cycle_free_bytes: MEM_RECORD_CYCLE_FREE_BYTES,
        block_record_size: BLOCK_RECORD_SIZE,
        block_record_count: BLOCK_RECORD_COUNT,
        block_record_cycles: BLOCK_RECORD_CYCLES,
        ticks_start_ticks: TICKS_START_TICKS,
        ticks_start_time: TICKS_START_TIME,
        ticks_val: TICKS_VAL,
        g_stack_hi: G_STACK_HI,
        g_sched_pc: G_SCHED_PC,
        g_sched_bp: G_SCHED_BP,
        g_syscallpc: G_SYSCALLPC,
        g_syscallbp: G_SYSCALLBP,
        g_atomicstatus: G_ATOMICSTATUS,
        g_goid: G_GOID,
        g_waitsince: G_WAITSINCE,
        g_waitreason: G_WAITREASON,
        g_startpc: G_STARTPC,
        g_labels: G_LABELS,
        label_map_list: LABEL_MAP_LIST,
        label_size: LABEL_SIZE,
        label_key: LABEL_KEY,
        label_value: LABEL_VALUE,
        trace_mux_flight_recorder: TRACE_MUX_FLIGHT_RECORDER,
        trace_recorder_r: TRACE_RECORDER_R,
        flight_recorder_header: FLIGHT_RECORDER_HEADER,
        flight_recorder_ring: FLIGHT_RECORDER_RING,
        raw_generation_size: RAW_GENERATION_SIZE,
        raw_generation_gen: RAW_GENERATION_GEN,
        raw_generation_batches: RAW_GENERATION_BATCHES,
        mem_profile: MEM_PROFILE,
        block_profile: BLOCK_PROFILE,
        mutex_profile: MUTEX_PROFILE,
        g_running: G_RUNNING,
        g_syscall: G_SYSCALL,
        g_dead: G_DEAD,
        g_deadextra: G_DEADEXTRA,
        g_scan: G_SCAN,
        ev_event_batch: EV_EVENT_BATCH,
        ev_experimental_batch: EV_EXPERIMENTAL_BATCH,
        ev_end_of_generation: EV_END_OF_GENERATION,
        status_names: &G_STATUS_NAMES,
        wait_reasons: &WAIT_REASONS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_versions_with_bindings() {
        assert!(for_version(1, 26).is_some());
        assert!(for_version(1, 25).is_none());
        assert!(for_version(1, 27).is_none());
        assert!(for_version(2, 26).is_none());
    }

    #[test]
    fn records_fit_their_reads() {
        let l = go1_26();
        // A memRecord is its active cycle and its future ones.
        assert_eq!(
            l.mem_record_future + l.mem_record_future_cycles * l.cycle_size,
            l.mem_record_size
        );
        assert!(l.g_read_len() <= bindings::v1_26::G_SIZE);
        assert!(l.wait_reasons[0].is_empty());
    }
}
