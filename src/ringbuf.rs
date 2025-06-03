use crate::SystingEventTS;
use std::collections::VecDeque;

#[derive(Default)]
pub struct RingBuffer<T> {
    buffer: VecDeque<VecDeque<T>>,
    start_set: bool,
    start_ts: u64,
    max_duration: u64,
}

impl<T> RingBuffer<T> {
    fn rotate(&mut self) {
        if self.max_duration == 0 {
            return;
        }

        if self.buffer.len() == 2 {
            self.buffer.pop_back();
        }
        self.buffer.push_front(VecDeque::new());
    }

    pub fn push_front(&mut self, item: T)
    where
        T: SystingEventTS,
    {
        if self.max_duration == 0 {
            return;
        }

        let cur_ts = item.ts();

        // Since the ringbuf gets events from all CPUs we can have some CPUs that get their events
        // in at a different time, so just reset our ts if our start_ts is less than the current
        // ts.
        //
        // This works out ok for the recorders because they are either recording per-cpu, so the TS
        // is always in sync, or they're recording per process, so if the process switches CPU's
        // the TS will still be ahead of its previous CPU's TS. (This isn't actually guaranteed but
        // we don't want to have to think about this right now so fuck it, let it ride until we hit
        // a machine where this ends up not being true and then we can do things like TS adjustment
        // when we bounc CPUs.)
        if !self.start_set || cur_ts < self.start_ts {
            self.start_set = true;
            self.start_ts = cur_ts;
        }
        let cur_duration = cur_ts - self.start_ts;
        if cur_duration >= self.max_duration {
            self.rotate();
            self.start_ts = cur_ts;
        }
        let first_vec = self.buffer.front_mut().unwrap();
        first_vec.push_front(item);
    }

    pub fn pop_back(&mut self) -> Option<T> {
        if self.max_duration == 0 {
            return None;
        }

        if let Some(last_vec) = self.buffer.back_mut() {
            if let Some(item) = last_vec.pop_back() {
                if last_vec.is_empty() {
                    self.buffer.pop_back();
                }
                return Some(item);
            }
        }
        None
    }

    pub fn set_max_duration(&mut self, max_duration: u64) {
        self.max_duration = max_duration;
        if self.max_duration == 0 {
            self.buffer.clear();
            self.start_ts = 0;
        } else if self.buffer.is_empty() {
            self.buffer.push_front(VecDeque::new());
        }
    }

    pub fn max_duration(&self) -> u64 {
        self.max_duration
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
            || (self.buffer.len() == 1 && self.buffer.front().unwrap().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestEvent {
        ts: u64,
    }

    impl SystingEventTS for TestEvent {
        fn ts(&self) -> u64 {
            self.ts
        }
    }

    impl TestEvent {
        fn new(ts: u64) -> Self {
            Self { ts }
        }
    }

    #[test]
    fn test_ringbuf() {
        let mut rb = RingBuffer::<TestEvent>::default();
        rb.set_max_duration(500);

        for i in 0..20 {
            rb.push_front(TestEvent::new(i * 100));
        }

        for i in 10..20 {
            assert_eq!(rb.pop_back().unwrap().ts(), i * 100);
        }
        assert!(rb.is_empty());
    }
}
