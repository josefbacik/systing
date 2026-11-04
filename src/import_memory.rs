//! Reports how much memory this process takes while it builds a DuckDB database.

use std::io::{self, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::stack_recorder::current_anon_rss_bytes;

const SAMPLE_PERIOD: Duration = Duration::from_millis(100);

/// What the looks at this process's anonymous RSS have shown. A sample is a look that worked.
#[derive(Default)]
struct Seen {
    /// The highest, in bytes.
    peak: u64,
    samples: u64,
}

impl Seen {
    fn add(&mut self, look: Option<u64>) {
        if let Some(bytes) = look {
            self.peak = self.peak.max(bytes);
            self.samples += 1;
        }
    }
}

/// Writes two notes on this process's memory: one when the watch starts and one when the watch is
/// dropped.
///
/// ```text
/// Note: DuckDB import start: anon RSS 120 MiB (peak RSS so far 310 MiB)
/// Note: DuckDB import peak: anon RSS 532 MiB (43 samples in 4.13s)
/// ```
///
/// The peak is the highest of the look at the start, one look every [`SAMPLE_PERIOD`] from a
/// thread of its own, and one at the drop. On a host that leaves that thread little CPU time it
/// can read low, and the note then shows far fewer than ten samples a second. "Peak RSS so far"
/// is `ru_maxrss`: a parent that finds a higher one when it waits for this process knows that the
/// highest came later.
///
/// Programs read these notes, so their words must not change, and each is one write, so that
/// nothing cuts it or lands inside it. The watch never fails or panics: what it cannot measure or
/// write, it leaves out.
pub(crate) struct ImportMemoryWatch<W: Write> {
    notes: W,
    started: Instant,
    stop: Option<mpsc::Sender<()>>,
    sampler: Option<JoinHandle<Seen>>,
}

impl ImportMemoryWatch<io::Stderr> {
    pub(crate) fn start() -> Self {
        Self::start_with(io::stderr(), current_anon_rss_bytes, peak_rss_bytes())
    }
}

impl<W: Write> ImportMemoryWatch<W> {
    fn start_with(
        mut notes: W,
        mut anon_rss: impl FnMut() -> Option<u64> + Send + 'static,
        peak_rss: Option<u64>,
    ) -> Self {
        let started = Instant::now();
        let mut seen = Seen::default();
        seen.add(anon_rss());
        if seen.samples > 0 {
            let _ = notes.write_all(start_note(seen.peak, peak_rss).as_bytes());
        }

        let (stop, stopped) = mpsc::channel();
        let sampler = thread::Builder::new()
            .name("duckdb_memory".to_string())
            .spawn(move || {
                // Nothing is sent: the wait ends early when the watch drops `stop`.
                while stopped.recv_timeout(SAMPLE_PERIOD) == Err(RecvTimeoutError::Timeout) {
                    seen.add(anon_rss());
                }
                seen.add(anon_rss());
                seen
            });
        Self {
            notes,
            started,
            stop: Some(stop),
            sampler: sampler.ok(),
        }
    }
}

impl<W: Write> Drop for ImportMemoryWatch<W> {
    fn drop(&mut self) {
        drop(self.stop.take());
        let Some(Ok(seen)) = self.sampler.take().map(JoinHandle::join) else {
            return;
        };
        if seen.samples > 0 {
            let note = peak_note(&seen, self.started.elapsed());
            let _ = self.notes.write_all(note.as_bytes());
        }
    }
}

fn start_note(anon_rss: u64, peak_rss: Option<u64>) -> String {
    let so_far = peak_rss
        .map(|bytes| format!(" (peak RSS so far {} MiB)", bytes >> 20))
        .unwrap_or_default();
    format!(
        "Note: DuckDB import start: anon RSS {} MiB{so_far}\n",
        anon_rss >> 20
    )
}

fn peak_note(seen: &Seen, took: Duration) -> String {
    format!(
        "Note: DuckDB import peak: anon RSS {} MiB ({} samples in {:.2}s)\n",
        seen.peak >> 20,
        seen.samples,
        took.as_secs_f64()
    )
}

/// The most memory that this process has held resident so far, in bytes.
fn peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: the pointer is to writable memory of the type that the kernel fills.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: it was zeroed, which is a valid value of the type.
    let kib = unsafe { usage.assume_init() }.ru_maxrss;
    Some(u64::try_from(kib).ok()? << 10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};

    const MIB: u64 = 1 << 20;

    /// Keeps each write of a watch apart, so that a test can read them while the watch is alive.
    #[derive(Clone, Default)]
    struct Notes(Arc<Mutex<Vec<String>>>);

    impl Notes {
        /// The writes, with `_` for the peak note's seconds, which no test can foretell.
        fn writes(&self) -> Vec<String> {
            let writes = self.0.lock().unwrap();
            let masked = writes.iter().map(|write| {
                let Some((head, tail)) = write.split_once(" samples in ") else {
                    return write.clone();
                };
                let (seconds, rest) = tail.split_once('s').unwrap();
                let (_, decimals) = seconds.split_once('.').unwrap();
                assert_eq!(decimals.len(), 2, "{write}");
                format!("{head} samples in _s{rest}")
            });
            masked.collect()
        }

        fn seconds(&self) -> f64 {
            let writes = self.0.lock().unwrap();
            let (_, tail) = writes.last().unwrap().split_once(" samples in ").unwrap();
            tail.split_once('s').unwrap().0.parse().unwrap()
        }
    }

    impl Write for Notes {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let write = String::from_utf8(bytes.to_vec()).unwrap();
            self.0.lock().unwrap().push(write);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Gives the looks of `script` in turn. After them it fails every look and sends on `spent`
    /// each time.
    fn scripted(
        script: &[Option<u64>],
        spent: mpsc::Sender<()>,
    ) -> impl FnMut() -> Option<u64> + Send + 'static {
        let mut script = Vec::from(script).into_iter();
        move || {
            script.next().unwrap_or_else(|| {
                let _ = spent.send(());
                None
            })
        }
    }

    #[test]
    fn the_start_note_is_written_at_the_start() {
        let notes = Notes::default();
        let _watch =
            ImportMemoryWatch::start_with(notes.clone(), || Some(120 * MIB), Some(310 * MIB));
        assert_eq!(
            notes.writes(),
            ["Note: DuckDB import start: anon RSS 120 MiB (peak RSS so far 310 MiB)\n"]
        );
    }

    #[test]
    fn the_start_note_has_no_bracket_without_a_peak_rss() {
        let notes = Notes::default();
        let _watch = ImportMemoryWatch::start_with(notes.clone(), || Some(120 * MIB), None);
        assert_eq!(
            notes.writes(),
            ["Note: DuckDB import start: anon RSS 120 MiB\n"]
        );
    }

    #[test]
    fn the_peak_note_has_the_highest_look_and_counts_the_looks_that_worked() {
        let notes = Notes::default();
        let (spent, all_looks_taken) = mpsc::channel();
        let looks = [
            Some(120 * MIB),
            Some(200 * MIB),
            None,
            Some(532 * MIB + MIB - 1),
            Some(300 * MIB),
        ];
        let watch = ImportMemoryWatch::start_with(notes.clone(), scripted(&looks, spent), None);
        all_looks_taken
            .recv_timeout(Duration::from_secs(30))
            .expect("the sampler takes no looks");
        drop(watch);
        assert_eq!(
            notes.writes(),
            [
                "Note: DuckDB import start: anon RSS 120 MiB\n",
                "Note: DuckDB import peak: anon RSS 532 MiB (4 samples in _s)\n"
            ]
        );
    }

    #[test]
    fn an_import_shorter_than_the_period_gets_a_look_at_each_end() {
        let notes = Notes::default();
        let (spent, _) = mpsc::channel();
        let looks = [Some(10 * MIB), Some(30 * MIB)];
        drop(ImportMemoryWatch::start_with(
            notes.clone(),
            scripted(&looks, spent),
            None,
        ));
        assert_eq!(
            notes.writes(),
            [
                "Note: DuckDB import start: anon RSS 10 MiB\n",
                "Note: DuckDB import peak: anon RSS 30 MiB (2 samples in _s)\n"
            ]
        );
    }

    #[test]
    fn the_peak_is_never_below_the_start() {
        let notes = Notes::default();
        let (spent, _) = mpsc::channel();
        let looks = [Some(30 * MIB), Some(10 * MIB)];
        drop(ImportMemoryWatch::start_with(
            notes.clone(),
            scripted(&looks, spent),
            None,
        ));
        assert_eq!(
            notes.writes(),
            [
                "Note: DuckDB import start: anon RSS 30 MiB\n",
                "Note: DuckDB import peak: anon RSS 30 MiB (2 samples in _s)\n"
            ]
        );
    }

    #[test]
    fn the_peak_note_gives_the_seconds_with_two_decimals() {
        let seen = Seen {
            peak: 532 * MIB,
            samples: 43,
        };
        assert_eq!(
            peak_note(&seen, Duration::from_millis(4_126)),
            "Note: DuckDB import peak: anon RSS 532 MiB (43 samples in 4.13s)\n"
        );
    }

    #[test]
    fn the_seconds_run_from_the_start_to_the_drop() {
        let notes = Notes::default();
        let watch = ImportMemoryWatch::start_with(notes.clone(), || Some(10 * MIB), None);
        thread::sleep(Duration::from_millis(250));
        drop(watch);
        assert!(notes.seconds() >= 0.25, "{:?}", notes.writes());
    }

    #[test]
    fn one_look_is_still_counted_in_the_plural() {
        let notes = Notes::default();
        let (spent, _) = mpsc::channel();
        drop(ImportMemoryWatch::start_with(
            notes.clone(),
            scripted(&[Some(10 * MIB)], spent),
            None,
        ));
        assert_eq!(
            notes.writes(),
            [
                "Note: DuckDB import start: anon RSS 10 MiB\n",
                "Note: DuckDB import peak: anon RSS 10 MiB (1 samples in _s)\n"
            ]
        );
    }

    #[test]
    fn no_look_that_works_means_no_note() {
        let notes = Notes::default();
        drop(ImportMemoryWatch::start_with(
            notes.clone(),
            || None,
            Some(310 * MIB),
        ));
        assert!(notes.writes().is_empty(), "{:?}", notes.writes());
    }

    #[test]
    fn a_drop_ends_the_sampler() {
        let held_by_the_sampler = Arc::new(());
        let held = held_by_the_sampler.clone();
        let watch = ImportMemoryWatch::start_with(
            Notes::default(),
            move || Some(Arc::strong_count(&held) as u64),
            None,
        );
        assert_eq!(Arc::strong_count(&held_by_the_sampler), 2);
        drop(watch);
        assert_eq!(Arc::strong_count(&held_by_the_sampler), 1);
    }

    #[test]
    fn a_panic_in_the_import_ends_the_sampler_and_leaves_both_notes() {
        let notes = Notes::default();
        let held_by_the_sampler = Arc::new(());
        let held = held_by_the_sampler.clone();
        let import = catch_unwind(AssertUnwindSafe(|| {
            let _watch = ImportMemoryWatch::start_with(
                notes.clone(),
                move || Some(Arc::strong_count(&held) as u64 * MIB),
                None,
            );
            panic!("the import panics");
        }));
        assert!(import.is_err());
        assert_eq!(Arc::strong_count(&held_by_the_sampler), 1);
        assert_eq!(notes.writes().len(), 2, "{:?}", notes.writes());
    }

    #[test]
    fn a_panic_in_the_sampler_costs_the_peak_note_alone() {
        let notes = Notes::default();
        let mut looks = 0;
        drop(ImportMemoryWatch::start_with(
            notes.clone(),
            move || {
                looks += 1;
                assert_eq!(looks, 1, "the sampler panics at its first look");
                Some(10 * MIB)
            },
            None,
        ));
        assert_eq!(
            notes.writes(),
            ["Note: DuckDB import start: anon RSS 10 MiB\n"]
        );
    }

    #[test]
    fn notes_that_cannot_be_written_are_dropped() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        drop(ImportMemoryWatch::start_with(
            Closed,
            || Some(10 * MIB),
            None,
        ));
    }

    #[test]
    fn this_process_has_a_peak_rss_at_or_above_what_it_holds_now() {
        // Touched, so that it is resident. The black box keeps an optimised build from dropping it.
        let held = std::hint::black_box(vec![1u8; 64 << 20]);
        let peak = peak_rss_bytes().unwrap();
        assert!(peak >= held.len() as u64, "{peak}");
    }
}
