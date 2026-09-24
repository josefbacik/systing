//! What a thread meets when the block region is full.
//!
//! The region holds a fixed number of blocks, one per thread that has set a
//! value. The thread that finds none left is refused (`NoBlock`) and the
//! refusal is counted in the per-process record; the threads that have a block
//! are not affected, and a block another thread gives back can be taken again.
//! This takes every block of the process, so it is a test binary of its own:
//! next to other tests it would starve them.

use std::sync::{Arc, Barrier};
use std::thread;

use task_context::{info, set_u64, Error};

#[test]
fn a_thread_past_the_regions_room_is_refused_and_counted_and_room_comes_back() {
    let record = info();
    let room = (record.region_size / u64::from(record.block_size)) as usize;
    let past = 3;
    // Every thread holds its block until every thread has tried.
    let all_tried = Arc::new(Barrier::new(room + past));
    let threads: Vec<_> = (0..room + past)
        .map(|_| {
            let all_tried = Arc::clone(&all_tried);
            thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(move || {
                    let result = set_u64("n", 1);
                    all_tried.wait();
                    result
                })
                .expect("this test needs thousands of threads: raise the limit on them")
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let given = results.iter().filter(|result| result.is_ok()).count();
    let refused = results
        .iter()
        .filter(|result| **result == Err(Error::NoBlock))
        .count();
    assert_eq!((given, refused), (room, past));
    assert_eq!(info().region_full_count, past as u64);

    // Every thread has ended and given its block back.
    thread::spawn(|| set_u64("again", 1))
        .join()
        .unwrap()
        .expect("a block is free again");
}
