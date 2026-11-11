//! Joining worker threads when a capture stops.

use crate::limits::Limit;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How long the stop sequence waits for a worker thread, where nothing calls
/// for another limit. A thread whose input has closed ends once it has worked
/// through what is queued; one that has not ended by then is left running, and
/// the stop goes on without it.
pub const STOP_JOIN_LIMIT: Duration = Duration::from_secs(10);

static THREADS_LEFT_BEHIND: Limit =
    Limit::new("worker threads still running when the capture stopped");
static THREADS_PANICKED: Limit = Limit::new("worker threads that panicked");

/// Joins `thread`, waiting at most `limit`, and returns what it returned.
///
/// `None`, after a warning, if it panicked or has not ended by then. A thread
/// that has not ended goes on running: it must hold no lock that the caller
/// still takes for longer than a moment, and use no descriptor by its number that
/// the caller still closes.
pub fn join_at_stop<T>(name: &'static str, thread: JoinHandle<T>, limit: Duration) -> Option<T> {
    let asked = Instant::now();
    while !thread.is_finished() {
        if asked.elapsed() >= limit {
            eprintln!(
                "Warning: the {name} thread has not ended after {} s; going on without it",
                limit.as_secs()
            );
            THREADS_LEFT_BEHIND.hit();
            return None;
        }
        thread::sleep(Duration::from_millis(1));
    }
    match thread.join() {
        Ok(value) => Some(value),
        Err(_) => {
            eprintln!("Warning: the {name} thread panicked; going on without it");
            THREADS_PANICKED.hit();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    #[test]
    fn test_join_returns_what_the_thread_returned() {
        let thread = thread::spawn(|| 7);
        assert_eq!(join_at_stop("test", thread, STOP_JOIN_LIMIT), Some(7));
    }

    #[test]
    fn test_join_waits_for_a_thread_that_ends_in_time() {
        let thread = thread::spawn(|| {
            thread::sleep(Duration::from_millis(20));
            7
        });
        assert_eq!(join_at_stop("test", thread, STOP_JOIN_LIMIT), Some(7));
    }

    #[test]
    fn test_join_survives_a_panic() {
        let panicked = THREADS_PANICKED.count();
        let thread = thread::spawn(|| panic!("a worker's panic, made for this test"));
        assert_eq!(join_at_stop("test", thread, STOP_JOIN_LIMIT), None);
        assert!(THREADS_PANICKED.count() > panicked);
    }

    #[test]
    fn test_join_gives_up_at_the_limit() {
        let left_behind = THREADS_LEFT_BEHIND.count();
        let (release, released) = channel::<()>();
        let thread = thread::spawn(move || released.recv().is_ok());
        let started = Instant::now();
        assert_eq!(
            join_at_stop("test", thread, Duration::from_millis(20)),
            None
        );
        assert!(started.elapsed() < STOP_JOIN_LIMIT);
        assert!(THREADS_LEFT_BEHIND.count() > left_behind);
        drop(release);
    }
}
