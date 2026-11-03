//! From the probes' events to slices: one per run of a Python frame.
//!
//! Each thread's events arrive in the order they happened (a thread emits an
//! event and only then runs on), so a stack of the frames open on the thread
//! is enough to pair them. The frame's address is the identity: an exit names
//! the frame it ends, so a lost event or a frame that was already running
//! when the trace began usually costs one slice its exact end. A frame an
//! exception unwound has no exit event and is closed later; after an
//! exception that C code swallowed, or a cancelled await chain, slices can
//! also get a wrong parent (see the doc).

use super::sites::Kind;
use std::collections::HashMap;

/// What the recorder keeps of one event of the probes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Event {
    pub ts: u64,
    pub frame: u64,
    pub symbol_id: u64,
    pub tgid: u32,
    pub tid: u32,
    pub first_line: u32,
    pub kind: u8,
}

/// How a slice ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The function returned.
    Return,
    /// A generator or coroutine suspended; a later slice continues it.
    Yield,
    /// No exit event: usually an exception took the frame, or an event was
    /// lost. The end is when that was noticed (the handler that caught it,
    /// or a later event on the same address or below it).
    Unwound,
    /// Still running when the trace ended.
    Open,
}

impl End {
    pub fn as_str(self) -> &'static str {
        match self {
            End::Return => "return",
            End::Yield => "yield",
            End::Unwound => "unwound",
            End::Open => "open",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slice {
    pub tgid: u32,
    pub tid: u32,
    pub start: u64,
    pub end: u64,
    pub symbol_id: u64,
    pub first_line: u32,
    /// How many traced frames were open on the thread below this one.
    pub depth: u32,
    pub end_kind: End,
}

struct OpenFrame {
    frame: u64,
    symbol_id: u64,
    first_line: u32,
    start: u64,
}

#[derive(Default)]
struct Thread {
    tgid: u32,
    stack: Vec<OpenFrame>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub events: u64,
    pub enters: u64,
    pub exits: u64,
    pub yields: u64,
    pub syncs: u64,
    /// An exit for a frame that is not open: it began before the trace did,
    /// or its entry was lost.
    pub unmatched_exits: u64,
    /// Frames closed without an exit event.
    pub unwound: u64,
    /// Frames first seen in an exception handler.
    pub first_seen_in_handler: u64,
    pub open_at_end: u64,
}

impl Counters {
    pub fn add(&mut self, other: &Counters) {
        self.events += other.events;
        self.enters += other.enters;
        self.exits += other.exits;
        self.yields += other.yields;
        self.syncs += other.syncs;
        self.unmatched_exits += other.unmatched_exits;
        self.unwound += other.unwound;
        self.first_seen_in_handler += other.first_seen_in_handler;
        self.open_at_end += other.open_at_end;
    }
}

#[derive(Default)]
pub struct Pairer {
    threads: HashMap<u32, Thread>,
    pub slices: Vec<Slice>,
    pub counters: Counters,
}

impl Pairer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, e: &Event) {
        let Some(kind) = Kind::from_u8(e.kind) else {
            return;
        };
        self.counters.events += 1;
        let at = {
            let thread = self.threads.entry(e.tid).or_default();
            thread.tgid = e.tgid;
            thread.stack.iter().rposition(|f| f.frame == e.frame)
        };
        match kind {
            Kind::Enter => {
                self.counters.enters += 1;
                if let Some(i) = at {
                    // The frame's address is in use again, so the frame that
                    // had it is gone, with everything above it: it left
                    // without an exit event (an exception that C code caught,
                    // as when a module's `__getattr__` raises AttributeError).
                    // Two entries in a row on one address are read this way
                    // too: the interpreter can dispatch one RESUME twice
                    // (when instrumentation changes under it), and that shows
                    // as a sub-microsecond "unwound" slice ahead of the real
                    // one, which costs less than merging two calls into one.
                    self.close_down_to(e.tid, i, e.ts, End::Unwound);
                }
                self.open(e);
            }
            Kind::Exit | Kind::Yield => {
                let end = if kind == Kind::Exit {
                    self.counters.exits += 1;
                    End::Return
                } else {
                    self.counters.yields += 1;
                    End::Yield
                };
                match at {
                    Some(i) => {
                        self.close_down_to(e.tid, i + 1, e.ts, End::Unwound);
                        self.close_top(e.tid, e.ts, end);
                    }
                    None => self.counters.unmatched_exits += 1,
                }
            }
            Kind::Sync => {
                self.counters.syncs += 1;
                match at {
                    Some(i) => self.close_down_to(e.tid, i + 1, e.ts, End::Unwound),
                    None => {
                        // Resumed by an exception thrown into it (no RESUME
                        // runs then), or running since before the trace.
                        self.counters.first_seen_in_handler += 1;
                        self.open(e);
                    }
                }
            }
        }
    }

    /// Ends every frame still open as gone, at `ts`: the process exec'd.
    pub fn close_all(&mut self, ts: u64) {
        let tids: Vec<u32> = self.threads.keys().copied().collect();
        for tid in tids {
            self.close_down_to(tid, 0, ts, End::Unwound);
        }
    }

    /// Ends every frame still open, at `end_ts`.
    pub fn finish(&mut self, end_ts: u64) {
        let tids: Vec<u32> = self.threads.keys().copied().collect();
        for tid in tids {
            while self.threads.get(&tid).is_some_and(|t| !t.stack.is_empty()) {
                self.counters.open_at_end += 1;
                self.close_top(tid, end_ts, End::Open);
            }
        }
    }

    fn open(&mut self, e: &Event) {
        let thread = self.threads.entry(e.tid).or_default();
        thread.stack.push(OpenFrame {
            frame: e.frame,
            symbol_id: e.symbol_id,
            first_line: e.first_line,
            start: e.ts,
        });
    }

    /// Closes frames from the top until `len` are left.
    fn close_down_to(&mut self, tid: u32, len: usize, ts: u64, end: End) {
        while self.threads.get(&tid).is_some_and(|t| t.stack.len() > len) {
            if end == End::Unwound {
                self.counters.unwound += 1;
            }
            self.close_top(tid, ts, end);
        }
    }

    fn close_top(&mut self, tid: u32, ts: u64, end_kind: End) {
        let Some(thread) = self.threads.get_mut(&tid) else {
            return;
        };
        let Some(frame) = thread.stack.pop() else {
            return;
        };
        let end = ts.max(frame.start);
        self.slices.push(Slice {
            tgid: thread.tgid,
            tid,
            start: frame.start,
            end,
            symbol_id: frame.symbol_id,
            first_line: frame.first_line,
            depth: thread.stack.len() as u32,
            end_kind,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u64 = 0x1000;
    const B: u64 = 0x2000;
    const C: u64 = 0x3000;

    fn ev(kind: Kind, frame: u64, ts: u64) -> Event {
        Event {
            ts,
            frame,
            symbol_id: frame,
            tgid: 1,
            tid: 1,
            kind: kind as u8,
            ..Default::default()
        }
    }

    /// (symbol, start, end, depth, how it ended), in the order slices closed.
    fn shape(p: &Pairer) -> Vec<(u64, u64, u64, u32, End)> {
        p.slices
            .iter()
            .map(|s| (s.symbol_id, s.start, s.end, s.depth, s.end_kind))
            .collect()
    }

    fn run(events: &[Event]) -> Pairer {
        let mut p = Pairer::new();
        for e in events {
            p.push(e);
        }
        p
    }

    #[test]
    fn calls_nest() {
        let p = run(&[
            ev(Kind::Enter, A, 10),
            ev(Kind::Enter, B, 20),
            ev(Kind::Exit, B, 50),
            ev(Kind::Exit, A, 100),
        ]);
        assert_eq!(
            shape(&p),
            [(B, 20, 50, 1, End::Return), (A, 10, 100, 0, End::Return)]
        );
    }

    #[test]
    fn a_generator_is_a_slice_per_resumption() {
        let p = run(&[
            ev(Kind::Enter, A, 0),
            ev(Kind::Enter, B, 10),
            ev(Kind::Yield, B, 20),
            ev(Kind::Enter, B, 30),
            ev(Kind::Exit, B, 45),
            ev(Kind::Exit, A, 50),
        ]);
        assert_eq!(
            shape(&p),
            [
                (B, 10, 20, 1, End::Yield),
                (B, 30, 45, 1, End::Return),
                (A, 0, 50, 0, End::Return)
            ]
        );
    }

    #[test]
    fn an_exception_closes_the_frames_it_unwound_at_the_handler() {
        // C raises, B does not catch, A's handler starts at 40.
        let p = run(&[
            ev(Kind::Enter, A, 0),
            ev(Kind::Enter, B, 10),
            ev(Kind::Enter, C, 20),
            ev(Kind::Sync, A, 40),
            ev(Kind::Exit, A, 60),
        ]);
        assert_eq!(
            shape(&p),
            [
                (C, 20, 40, 2, End::Unwound),
                (B, 10, 40, 1, End::Unwound),
                (A, 0, 60, 0, End::Return)
            ]
        );
        assert_eq!(p.counters.unwound, 2);
    }

    #[test]
    fn without_a_handler_event_the_next_event_closes_what_was_unwound() {
        // B raised and C code swallowed it; A returns.
        let p = run(&[
            ev(Kind::Enter, A, 0),
            ev(Kind::Enter, B, 10),
            ev(Kind::Exit, A, 30),
        ]);
        assert_eq!(
            shape(&p),
            [(B, 10, 30, 1, End::Unwound), (A, 0, 30, 0, End::Return)]
        );
        // Or A calls again and the new frame takes the address B's had.
        let p = run(&[
            ev(Kind::Enter, A, 0),
            ev(Kind::Enter, B, 10),
            ev(Kind::Enter, B, 25),
            ev(Kind::Exit, B, 28),
            ev(Kind::Exit, A, 30),
        ]);
        assert_eq!(
            shape(&p),
            [
                (B, 10, 25, 1, End::Unwound),
                (B, 25, 28, 1, End::Return),
                (A, 0, 30, 0, End::Return)
            ]
        );
    }

    #[test]
    fn an_exit_of_a_frame_from_before_the_trace_is_counted_and_dropped() {
        let p = run(&[
            ev(Kind::Exit, B, 5),
            ev(Kind::Enter, A, 10),
            ev(Kind::Exit, A, 20),
        ]);
        assert_eq!(shape(&p), [(A, 10, 20, 0, End::Return)]);
        assert_eq!(p.counters.unmatched_exits, 1);
    }

    #[test]
    fn an_entry_on_the_top_frames_address_ends_the_frame_that_had_it() {
        // B raised, C code swallowed it, and A's next call got B's address:
        // two entries in a row on one frame are two frames.
        let p = run(&[
            ev(Kind::Enter, A, 0),
            ev(Kind::Enter, B, 10),
            Event {
                symbol_id: C,
                ..ev(Kind::Enter, B, 20)
            },
            ev(Kind::Exit, B, 30),
            ev(Kind::Exit, A, 40),
        ]);
        assert_eq!(
            shape(&p),
            [
                (B, 10, 20, 1, End::Unwound),
                (C, 20, 30, 1, End::Return),
                (A, 0, 40, 0, End::Return)
            ]
        );
    }

    #[test]
    fn a_frame_first_seen_in_its_handler_is_opened_there() {
        // A coroutine resumed by an exception thrown into it runs no RESUME.
        let p = run(&[
            ev(Kind::Enter, A, 0),
            ev(Kind::Sync, B, 10),
            ev(Kind::Yield, B, 20),
            ev(Kind::Exit, A, 30),
        ]);
        assert_eq!(
            shape(&p),
            [(B, 10, 20, 1, End::Yield), (A, 0, 30, 0, End::Return)]
        );
        assert_eq!(p.counters.first_seen_in_handler, 1);
    }

    #[test]
    fn frames_open_at_the_end_are_closed_there_and_threads_do_not_mix() {
        let mut p = Pairer::new();
        p.push(&ev(Kind::Enter, A, 0));
        p.push(&Event {
            tid: 2,
            ..ev(Kind::Enter, A, 5)
        });
        p.push(&Event {
            tid: 2,
            ..ev(Kind::Exit, A, 9)
        });
        p.finish(100);
        assert_eq!(
            shape(&p),
            [(A, 5, 9, 0, End::Return), (A, 0, 100, 0, End::Open)]
        );
        assert_eq!(p.slices[0].tid, 2);
        assert_eq!(p.counters.open_at_end, 1);
    }

    #[test]
    fn an_exec_ends_every_frame_as_gone() {
        let mut p = Pairer::new();
        p.push(&ev(Kind::Enter, A, 0));
        p.push(&ev(Kind::Enter, B, 5));
        p.close_all(10);
        p.push(&ev(Kind::Enter, A, 20));
        p.push(&ev(Kind::Exit, A, 30));
        assert_eq!(
            shape(&p),
            [
                (B, 5, 10, 1, End::Unwound),
                (A, 0, 10, 0, End::Unwound),
                (A, 20, 30, 0, End::Return)
            ]
        );
    }
}
