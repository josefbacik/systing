use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::pystacks::stack_walker::StackWalkerRun;
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::stack_recorder::Stack;
use crate::systing_core::types::{
    memory_alloc_op, memory_event, memory_event_type, memory_rss_member,
};
use crate::systing_core::SystingRecordEvent;
use crate::trace::{MemoryAllocRecord, MemoryFaultRecord, MemoryMapRecord, MemoryRssRecord};

/// stack_id offset for stacks interned by the memory recorder, to keep them
/// disjoint from `StackRecorder`'s own ids prior to the end-of-trace merge.
const MEMORY_STACK_ID_OFFSET: i64 = 1_000_000_000;

/// Synthetic `member` values for periodic mm_struct samples (distinguish from
/// the kernel rss_stat member indices 0..=3).
pub const MEMORY_MEMBER_HIWATER_RSS: i8 = -1;
pub const MEMORY_MEMBER_TOTAL_VM: i8 = -2;

pub struct MemoryRecorder {
    pub(crate) ringbuf: RingBuffer<memory_event>,
    pub(crate) psr: Arc<StackWalkerRun>,
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    unique_stacks: HashMap<(Stack, i32), i64>,
    next_stack_id: i64,
    next_map_id: i64,
    next_alloc_id: i64,
    write_error_reported: bool,
}

impl Default for MemoryRecorder {
    fn default() -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            psr: Arc::new(StackWalkerRun::default()),
            streaming_collector: None,
            unique_stacks: HashMap::new(),
            next_stack_id: MEMORY_STACK_ID_OFFSET,
            next_map_id: 1,
            next_alloc_id: 1,
            write_error_reported: false,
        }
    }
}

fn alloc_op_name(op: u32) -> &'static str {
    match memory_alloc_op(op) {
        memory_alloc_op::MEMORY_OP_MALLOC => "malloc",
        memory_alloc_op::MEMORY_OP_CALLOC => "calloc",
        memory_alloc_op::MEMORY_OP_REALLOC => "realloc",
        memory_alloc_op::MEMORY_OP_POSIX_MEMALIGN => "posix_memalign",
        memory_alloc_op::MEMORY_OP_ALIGNED_ALLOC => "aligned_alloc",
        memory_alloc_op::MEMORY_OP_FREE => "free",
        _ => "unknown",
    }
}

impl MemoryRecorder {
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    pub fn set_pystacks_run(&mut self, psr: Arc<StackWalkerRun>) {
        self.psr = psr;
    }

    /// Drain the deduplicated stacks for hand-off to `StackRecorder` so they are
    /// symbolized in the shared `stack` table during finish.
    pub fn take_unique_stacks(&mut self) -> HashMap<(Stack, i32), i64> {
        std::mem::take(&mut self.unique_stacks)
    }

    pub fn finish(
        &mut self,
        collector: Box<dyn RecordCollector + Send>,
    ) -> Result<Box<dyn RecordCollector + Send>> {
        if let Some(mut own) = self.streaming_collector.take() {
            own.flush()?;
            own.finish_boxed()?;
        }
        Ok(collector)
    }

    fn report_write_error(&mut self, r: Result<()>) {
        if let Err(e) = r {
            if !self.write_error_reported {
                self.write_error_reported = true;
                eprintln!("memory_recorder: write error (further errors suppressed): {e}");
            }
        }
    }

    fn intern_stack(&mut self, event: &memory_event, tgid: i32) -> Option<i64> {
        let klen = (event.hdr.kernel_stack_length as usize).min(event.kernel_stack.len());
        let ulen = (event.hdr.user_stack_length as usize).min(event.user_stack.len());
        let kstack = &event.kernel_stack[..klen];
        let ustack = &event.user_stack[..ulen];
        let py_stack = self
            .psr
            .get_pystack_from_buffer(&event.py_msg_buffer, tgid as u64);
        if kstack.is_empty() && ustack.is_empty() && py_stack.is_empty() {
            return None;
        }
        let stack = Stack::new(kstack, ustack, &py_stack);
        let id = *self.unique_stacks.entry((stack, tgid)).or_insert_with(|| {
            let id = self.next_stack_id;
            self.next_stack_id += 1;
            id
        });
        Some(id)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_map(
        &mut self,
        collector: &mut (dyn RecordCollector + Send),
        event: &memory_event,
        tgid: i32,
        tid: i32,
        event_type: &'static str,
        prot: Option<i32>,
        flags: Option<i32>,
    ) {
        let stack_id = self.intern_stack(event, tgid);
        let id = self.next_map_id;
        self.next_map_id += 1;
        let r = collector.add_memory_map(MemoryMapRecord {
            id,
            ts: event.hdr.ts as i64,
            tid,
            pid: tgid,
            event_type: event_type.to_string(),
            addr: event.hdr.addr as i64,
            size: event.hdr.size as i64,
            prot,
            flags,
            stack_id,
        });
        self.report_write_error(r);
    }
}

impl SystingRecordEvent<memory_event> for MemoryRecorder {
    fn ringbuf(&self) -> &RingBuffer<memory_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<memory_event> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: memory_event) {
        let Some(mut collector) = self.streaming_collector.take() else {
            return;
        };
        let hdr = &event.hdr;
        let tgid = (hdr.task.tgidpid >> 32) as i32;
        let tid = (hdr.task.tgidpid & 0xFFFF_FFFF) as i32;

        match hdr.r#type {
            memory_event_type::MEMORY_RSS_STAT => {
                let r = collector.add_memory_rss(MemoryRssRecord {
                    ts: hdr.ts as i64,
                    tid,
                    pid: tgid,
                    member: hdr.member.min(i8::MAX as u32) as i8,
                    size: hdr.size as i64,
                });
                self.report_write_error(r);
            }
            memory_event_type::MEMORY_MMAP => {
                self.emit_map(
                    collector.as_mut(),
                    &event,
                    tgid,
                    tid,
                    "mmap",
                    Some(hdr.member as i32),
                    Some(hdr.flags as i32),
                );
            }
            memory_event_type::MEMORY_MUNMAP => {
                self.emit_map(collector.as_mut(), &event, tgid, tid, "munmap", None, None);
            }
            memory_event_type::MEMORY_BRK => {
                self.emit_map(collector.as_mut(), &event, tgid, tid, "brk", None, None);
            }
            memory_event_type::MEMORY_PAGE_FAULT => {
                let stack_id = self.intern_stack(&event, tgid);
                let r = collector.add_memory_fault(MemoryFaultRecord {
                    ts: hdr.ts as i64,
                    tid,
                    pid: tgid,
                    addr: hdr.addr as i64,
                    error_code: hdr.flags as i32,
                    stack_id,
                });
                self.report_write_error(r);
            }
            memory_event_type::MEMORY_ALLOC | memory_event_type::MEMORY_FREE => {
                let stack_id = self.intern_stack(&event, tgid);
                let id = self.next_alloc_id;
                self.next_alloc_id += 1;
                let is_realloc = memory_alloc_op(hdr.member) == memory_alloc_op::MEMORY_OP_REALLOC;
                let r = collector.add_memory_alloc(MemoryAllocRecord {
                    id,
                    ts: hdr.ts as i64,
                    tid,
                    pid: tgid,
                    op: alloc_op_name(hdr.member).to_string(),
                    addr: hdr.addr as i64,
                    size: hdr.size as i64,
                    old_addr: if is_realloc {
                        Some(hdr.old_addr as i64)
                    } else {
                        None
                    },
                    stack_id,
                });
                self.report_write_error(r);
            }
            memory_event_type::MEMORY_MM_SAMPLE => {
                let r = collector.add_memory_rss(MemoryRssRecord {
                    ts: hdr.ts as i64,
                    tid,
                    pid: tgid,
                    member: MEMORY_MEMBER_HIWATER_RSS,
                    size: hdr.addr as i64,
                });
                self.report_write_error(r);
                let r = collector.add_memory_rss(MemoryRssRecord {
                    ts: hdr.ts as i64,
                    tid,
                    pid: tgid,
                    member: MEMORY_MEMBER_TOTAL_VM,
                    size: hdr.size as i64,
                });
                self.report_write_error(r);
            }
            _ => {}
        }

        self.streaming_collector = Some(collector);
    }
}

/// Human-readable label for the `memory_rss.member` column.
pub fn memory_rss_member_name(member: i8) -> &'static str {
    match member {
        MEMORY_MEMBER_HIWATER_RSS => "hiwater_rss",
        MEMORY_MEMBER_TOTAL_VM => "total_vm",
        m if m >= 0 => match memory_rss_member(m as u32) {
            memory_rss_member::MEMORY_MM_FILEPAGES => "file",
            memory_rss_member::MEMORY_MM_ANONPAGES => "anon",
            memory_rss_member::MEMORY_MM_SWAPENTS => "swap",
            memory_rss_member::MEMORY_MM_SHMEMPAGES => "shmem",
            _ => "unknown",
        },
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_member_name() {
        assert_eq!(memory_rss_member_name(1), "anon");
        assert_eq!(memory_rss_member_name(-1), "hiwater_rss");
        assert_eq!(memory_rss_member_name(-2), "total_vm");
        assert_eq!(memory_rss_member_name(99), "unknown");
    }
}
