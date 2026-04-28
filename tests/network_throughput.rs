//! Throughput benchmark for the network recorder hot path under lock contention.
//!
//! Reproduces the scenario where the network/packet/epoll consumer threads all
//! contend on the single `Mutex<NetworkRecorder>`: compares locking once per
//! event against locking once per batch of events. Run with:
//!
//!     cargo test --release --test network_throughput -- --ignored --nocapture

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use systing::network_recorder::NetworkRecorder;
use systing::record::InMemoryCollector;
use systing::systing_core::types::{
    network_address_family, network_protocol, packet_event, packet_event_type,
};
use systing::utid::UtidGenerator;

#[allow(clippy::field_reassign_with_default)]
fn make_event(i: u64) -> packet_event {
    let mut ev = packet_event::default();
    ev.ts = 1_000_000_000 + i;
    ev.protocol = network_protocol::NETWORK_TCP;
    ev.af = network_address_family::NETWORK_AF_INET;
    ev.src_addr[0] = 10;
    ev.src_port = 12345;
    ev.dest_addr[0] = 10;
    ev.dest_addr[3] = 1;
    ev.dest_port = 443;
    ev.seq = i as u32;
    ev.length = 1448;
    ev.event_type = packet_event_type::PACKET_ENQUEUE;
    // Cycle through a small set of socket ids so the seen_sockets set stays tiny.
    ev.socket_id = 1 + (i % 16);
    ev.sndbuf_used = 4096;
    ev.sndbuf_limit = 65536;
    ev
}

fn new_recorder() -> Arc<Mutex<NetworkRecorder>> {
    let utid = Arc::new(UtidGenerator::new());
    let mut rec = NetworkRecorder::new(utid, false);
    rec.set_streaming_collector(Box::new(InMemoryCollector::new()));
    Arc::new(Mutex::new(rec))
}

const THREADS: usize = 3;
const EVENTS_PER_THREAD: u64 = 500_000;

fn run_per_event() -> f64 {
    let rec = new_recorder();
    let start = Instant::now();
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let rec = rec.clone();
            thread::spawn(move || {
                for i in 0..EVENTS_PER_THREAD {
                    let ev = make_event(t as u64 * EVENTS_PER_THREAD + i);
                    rec.lock().unwrap().handle_packet_event(ev);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let elapsed = start.elapsed().as_secs_f64();
    (THREADS as u64 * EVENTS_PER_THREAD) as f64 / elapsed
}

fn run_batched(batch: usize) -> f64 {
    let rec = new_recorder();
    let start = Instant::now();
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let rec = rec.clone();
            thread::spawn(move || {
                let mut buf = Vec::with_capacity(batch);
                for i in 0..EVENTS_PER_THREAD {
                    buf.push(make_event(t as u64 * EVENTS_PER_THREAD + i));
                    if buf.len() == batch {
                        let mut r = rec.lock().unwrap();
                        for ev in buf.drain(..) {
                            r.handle_packet_event(ev);
                        }
                    }
                }
                if !buf.is_empty() {
                    let mut r = rec.lock().unwrap();
                    for ev in buf.drain(..) {
                        r.handle_packet_event(ev);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let elapsed = start.elapsed().as_secs_f64();
    (THREADS as u64 * EVENTS_PER_THREAD) as f64 / elapsed
}

#[test]
#[ignore = "throughput benchmark, run manually with --release --nocapture"]
fn network_recorder_lock_contention_throughput() {
    let per_event = run_per_event();
    let batched = run_batched(4096);
    println!(
        "handle_packet_event throughput under {}-way contention:",
        THREADS
    );
    println!("  per-event lock: {:>10.0} events/s", per_event);
    println!("  batched (4096): {:>10.0} events/s", batched);
    println!("  speedup:        {:>10.1}x", batched / per_event);
    assert!(
        batched > per_event * 1.5,
        "batched locking should be meaningfully faster than per-event"
    );
}
