//! Workload-lifetime helpers shared by the integration tests.
//!
//! A test workload must overlap the whole trace window, and the window's
//! edges move with machine speed: BPF skeleton load alone takes tens of
//! seconds on slow or emulated machines (e.g. QEMU TCG, ~10-20x slower than
//! native), and interpreter warm-up scales the same way. Tests have
//! repeatedly grown hardcoded "should be enough" budgets (30s here, 5s
//! there, 1s elsewhere) that pass on fast hardware and race everything
//! else. The rules these helpers encode:
//!
//! - A workload runs until the test STOPS it (`stoppable_workload`), never
//!   for a fixed iteration count or duration that has to outguess attach
//!   latency.
//! - A wait polls the actual postcondition with one shared, generous
//!   deadline (`wait_until`, `SLOW_MACHINE_BUDGET`). Deadlines are backstops
//!   against hangs, not estimates of expected latency: on a fast machine the
//!   poll exits early and the budget costs nothing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// One budget for every readiness deadline and completion backstop. Sized
/// for the slowest supported environment (QEMU TCG with a cold interpreter
/// warm-up), not for the expected case.
pub const SLOW_MACHINE_BUDGET: Duration = Duration::from_secs(300);

/// A background workload thread that runs until stopped, plus the guarantee
/// that it IS stopped and joined when the guard goes away — including on the
/// test's own panic path, so a leaked busy loop can't slow every later test
/// in the binary.
pub struct WorkloadGuard {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl WorkloadGuard {
    /// Stop the workload and join it. Equivalent to dropping the guard, but
    /// explicit at call sites where shutdown ordering matters.
    pub fn stop(self) {}
}

impl Drop for WorkloadGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let result = handle.join();
            // Surface a workload panic unless the test is already panicking
            // (a double panic would abort the whole test binary).
            if !std::thread::panicking() {
                result.expect("workload thread panicked");
            }
        }
    }
}

/// Spawn `f` on a background thread with a stop flag. `f` owns its whole
/// lifecycle — setup, loop while the flag is clear, teardown:
///
/// ```ignore
/// let workload = stoppable_workload(|stop| {
///     while !stop.load(Ordering::Relaxed) {
///         one_round_of_traffic();
///         thread::sleep(Duration::from_millis(50));
///     }
/// });
/// systing(config, None).expect("recording failed");
/// workload.stop();
/// ```
pub fn stoppable_workload<F>(f: F) -> WorkloadGuard
where
    F: FnOnce(&AtomicBool) + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let handle = std::thread::spawn(move || f(&thread_stop));
    WorkloadGuard {
        stop,
        handle: Some(handle),
    }
}

/// Poll `cond` until it returns true, panicking with `what` after
/// [`SLOW_MACHINE_BUDGET`]. `cond` may itself panic to fail fast with a more
/// specific diagnosis (e.g. "the workload exited before becoming ready").
pub fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + SLOW_MACHINE_BUDGET;
    while !cond() {
        assert!(
            Instant::now() < deadline,
            "timed out after {SLOW_MACHINE_BUDGET:?} waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
