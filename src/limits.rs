//! Limits that a capture reached: counted where the tracer gives up, reported
//! when it writes the trace.
//!
//! To add one, declare it beside the code that gives up, and hit it there:
//!
//! ```ignore
//! static LINES_CUT: Limit = Limit::new("lines cut short");
//! LINES_CUT.hit();
//! ```
//!
//! Any ordinary thread may hit it, but no signal handler and no forked child: a
//! first hit takes a lock and may allocate. Code that runs for every event
//! counts by itself and calls [`Limit::add`] once.
//!
//! Only the `systing` binary reports, once for each capture, in
//! `SessionRecorder::generate_parquet_trace`, after symbolization. A hit later
//! than that, in a capture that ends before that, or in another program that
//! links this library is counted and never reported. Another program that wants
//! a report makes it itself and prints it on stderr: the stdout of the other
//! programs is parsed, and `systing-analyze` and the MCP server print nothing.
//!
//! A name and a number are all that is reported of a limit, and the name is a
//! constant in the source.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

/// A limit of the tracer's, and how often it was reached.
pub struct Limit {
    name: &'static str,
    /// Since the process began.
    count: AtomicU64,
    /// The part of `count` that [`take_reached`] has already reported.
    taken: AtomicU64,
    /// Whether it is in [`REACHED`], or about to be.
    listed: AtomicBool,
}

/// The limits reached since [`take_reached`] last ran.
static REACHED: Mutex<Vec<&'static Limit>> = Mutex::new(Vec::new());

impl Limit {
    /// A limit called `name`, which says what was left out or cut, so that
    /// "lines cut short: 3" reads well. Use it in a static: there, a name that is
    /// empty, not printable ASCII, or holds one of `: ' " % \` does not compile.
    pub const fn new(name: &'static str) -> Self {
        let bytes = name.as_bytes();
        assert!(!bytes.is_empty(), "a limit needs a name");
        let mut i = 0;
        while i < bytes.len() {
            assert!(
                bytes[i] >= b' ' && bytes[i] <= b'~',
                "a limit's name must be printable ASCII"
            );
            // The report's line uses colons as separators, and a name must be
            // safe to quote.
            assert!(
                !matches!(bytes[i], b':' | b'\'' | b'"' | b'%' | b'\\'),
                "a limit's name must not hold a colon, a quote, a percent sign or a backslash"
            );
            i += 1;
        }
        Self {
            name,
            count: AtomicU64::new(0),
            taken: AtomicU64::new(0),
            listed: AtomicBool::new(false),
        }
    }

    /// The limit was reached once more.
    pub fn hit(&'static self) {
        self.add(1);
    }

    /// The limit was reached `n` more times. `n` counts things that were left
    /// out.
    pub fn add(&'static self, n: u64) {
        if n == 0 {
            return;
        }
        // This adds to `count`, then reads `listed`; take_reached() clears
        // `listed`, then reads `count`. All four are SeqCst, so the report sees
        // this hit, or this call sees `listed` cleared and lists the limit again.
        self.count.fetch_add(n, Ordering::SeqCst);
        if !self.listed.load(Ordering::SeqCst) && !self.listed.swap(true, Ordering::SeqCst) {
            REACHED.lock().unwrap().push(self);
        }
    }

    /// How often it was reached since the process began. Tests of one binary
    /// run side by side in one process: compare two readings, and expect no
    /// exact value.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
}

/// The limits reached since the last call, in the order of their names, and how
/// often each was; statics of one name are one limit. Empty if none was reached.
/// The tracer calls it once, when it writes the trace: any other call, from a
/// test too, takes its hits out of that report.
pub fn take_reached() -> Vec<(&'static str, u64)> {
    // Held to the end, so that two calls at once do not hand out one hit twice.
    let mut listed = REACHED.lock().unwrap();
    let mut reached: Vec<_> = listed
        .drain(..)
        .map(|limit| {
            limit.listed.store(false, Ordering::SeqCst);
            let count = limit.count.load(Ordering::SeqCst);
            // The count wraps, like the atomic that holds it.
            let times = count.wrapping_sub(limit.taken.swap(count, Ordering::SeqCst));
            (limit.name, times)
        })
        .filter(|(_, times)| *times > 0)
        .collect();
    reached.sort_unstable();
    reached.dedup_by(|next, kept| {
        let same = next.0 == kept.0;
        if same {
            kept.1 = kept.1.saturating_add(next.1);
        }
        same
    });
    reached
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What take_reached() gives for `limit`; other tests' limits may be in the
    /// same answer.
    fn taken(limit: &Limit) -> u64 {
        take_reached()
            .into_iter()
            .filter(|(name, _)| *name == limit.name)
            .map(|(_, times)| times)
            .sum()
    }

    // take_reached() empties one list for the whole process, so the tests that
    // look at what it returns take turns.
    static TURN: Mutex<()> = Mutex::new(());

    /// A turn, also after a test that failed in its own.
    fn turn() -> std::sync::MutexGuard<'static, ()> {
        TURN.lock().unwrap_or_else(|failed| failed.into_inner())
    }

    #[test]
    fn a_limit_that_was_not_reached_is_not_reported() {
        static QUIET: Limit = Limit::new("limits test, never reached");
        let _turn = turn();
        QUIET.add(0);
        assert_eq!(QUIET.count(), 0);
        assert_eq!(taken(&QUIET), 0);
    }

    #[test]
    fn hits_are_reported_once() {
        static LIMIT: Limit = Limit::new("limits test, reported once");
        let _turn = turn();
        LIMIT.hit();
        LIMIT.add(4);
        assert_eq!(LIMIT.count(), 5);
        assert_eq!(taken(&LIMIT), 5);
        assert_eq!(taken(&LIMIT), 0);
        // The next capture's hits are its own; the count goes on.
        LIMIT.hit();
        assert_eq!(LIMIT.count(), 6);
        assert_eq!(taken(&LIMIT), 1);
    }

    #[test]
    fn the_report_is_in_the_order_of_the_names() {
        static B: Limit = Limit::new("limits test, order b");
        static A: Limit = Limit::new("limits test, order a");
        let _turn = turn();
        B.hit();
        A.add(2);
        let ours: Vec<_> = take_reached()
            .into_iter()
            .filter(|(name, _)| name.starts_with("limits test, order"))
            .collect();
        assert_eq!(
            ours,
            [("limits test, order a", 2), ("limits test, order b", 1)]
        );
    }

    #[test]
    fn a_name_that_would_garble_the_report_is_refused() {
        // In a static these do not compile; called at run time, they panic.
        for name in [
            "",
            "caf\u{e9}",
            "a\nb",
            "a: b",
            "it's",
            "\"a\"",
            "100%",
            "a\\b",
        ] {
            assert!(
                std::panic::catch_unwind(|| Limit::new(name)).is_err(),
                "{name:?}"
            );
        }
        Limit::new("lines (of text), cut-short at 4 KiB");
    }

    #[test]
    fn statics_of_one_name_are_one_limit() {
        static HERE: Limit = Limit::new("limits test, one name");
        static THERE: Limit = Limit::new("limits test, one name");
        let _turn = turn();
        HERE.add(2);
        THERE.hit();
        let ours: Vec<_> = take_reached()
            .into_iter()
            .filter(|(name, _)| *name == "limits test, one name")
            .collect();
        assert_eq!(ours, [("limits test, one name", 3)]);
    }

    #[test]
    fn a_count_that_wraps_does_not_stop_the_report() {
        static LIMIT: Limit = Limit::new("limits test, a count that wraps");
        let _turn = turn();
        LIMIT.add(5);
        assert_eq!(taken(&LIMIT), 5);
        LIMIT.add(u64::MAX - 1);
        assert_eq!(LIMIT.count(), 3);
        assert_eq!(taken(&LIMIT), u64::MAX - 1);
    }

    #[test]
    fn no_hit_is_lost_or_reported_twice_between_threads() {
        static LIMIT: Limit = Limit::new("limits test, many threads");
        const THREADS: u64 = 8;
        const HITS: u64 = 20_000;
        let _turn = turn();
        let mut seen = 0;
        std::thread::scope(|scope| {
            let hitters: Vec<_> = (0..THREADS)
                .map(|_| scope.spawn(|| (0..HITS).for_each(|_| LIMIT.hit())))
                .collect();
            // Reports are taken while the hits come in.
            while hitters.iter().any(|hitter| !hitter.is_finished()) {
                seen += taken(&LIMIT);
            }
        });
        seen += taken(&LIMIT);
        assert_eq!(seen, THREADS * HITS);
        assert_eq!(LIMIT.count(), THREADS * HITS);
    }
}
