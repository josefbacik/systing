use crate::SystingEventTS;

#[derive(Default)]
pub struct RingBuffer<T> {
    buffer: Vec<Vec<T>>,
    start_ts: u64,
    max_duration: u64,
}

impl<T> RingBuffer<T> {
    pub fn rotate(&mut self) {
        if self.max_duration == 0 {
            return;
        }

        if self.buffer.len() == 2 {
            self.buffer.pop();
        }
        self.buffer.push(Vec::new());
    }

    pub fn push(&mut self, item: T)
    where
        T: SystingEventTS,
    {
        if self.max_duration == 0 {
            return;
        }

        let cur_ts = item.ts();
        if self.start_ts == 0 {
            self.start_ts = cur_ts;
        }
        let cur_duration = cur_ts - self.start_ts;
        if cur_duration > self.max_duration {
            self.rotate();
            self.start_ts = cur_ts;
        }
        let first_vec = self.buffer.first_mut().unwrap();
        first_vec.push(item);
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.max_duration == 0 {
            return None;
        }

        if let Some(last_vec) = self.buffer.last_mut() {
            if let Some(item) = last_vec.pop() {
                return Some(item);
            }
        }
        None
    }

    pub fn set_max_duration(&mut self, max_duration: u64) {
        self.max_duration = max_duration;
    }

    pub fn max_duration(&self) -> u64 {
        self.max_duration
    }
}
