//! Validation configuration.

/// Configuration for validation checks.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Tolerance for stack timing validation in nanoseconds.
    /// Stack samples may be slightly offset from slice boundaries due to timing jitter.
    pub stack_timing_tolerance_ns: i64,

    /// Maximum number of validation errors to report per category.
    pub max_errors_per_category: usize,

    /// Minimum number of sched events required before validating swapper/idle presence.
    /// Traces with fewer events may legitimately have no idle time if the system was busy.
    pub min_sched_events_for_swapper_validation: u64,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            // 100 microseconds in nanoseconds
            stack_timing_tolerance_ns: 100_000,
            max_errors_per_category: 10,
            min_sched_events_for_swapper_validation: 1000,
        }
    }
}
