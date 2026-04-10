use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::pystacks::stack_walker::StackWalkerRun;
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::stack_recorder::Stack;
use crate::systing_core::types::{memory_alloc_op, memory_event, memory_event_type};
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

    fn intern_stack(&mut self, event: &memory_event, tgid: i32) -> Option<i64> {
        let klen = (event.kernel_stack_length as usize).min(event.kernel_stack.len());
        let ulen = (event.user_stack_length as usize).min(event.user_stack.len());
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
        let _ = collector.add_memory_map(MemoryMapRecord {
            id,
            ts: event.ts as i64,
            tid,
            pid: tgid,
            event_type: event_type.to_string(),
            addr: event.addr as i64,
            size: event.size as i64,
            prot,
            flags,
            stack_id,
        });
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
        let tgid = (event.task.tgidpid >> 32) as i32;
        let tid = (event.task.tgidpid & 0xFFFF_FFFF) as i32;

        match event.r#type {
            memory_event_type::MEMORY_RSS_STAT => {
                let _ = collector.add_memory_rss(MemoryRssRecord {
                    ts: event.ts as i64,
                    tid,
                    pid: tgid,
                    member: event.member.min(i8::MAX as u32) as i8,
                    size: event.size as i64,
                });
            }
            memory_event_type::MEMORY_MMAP => {
                self.emit_map(
                    collector.as_mut(),
                    &event,
                    tgid,
                    tid,
                    "mmap",
                    Some(event.member as i32),
                    Some(event.flags as i32),
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
                let _ = collector.add_memory_fault(MemoryFaultRecord {
                    ts: event.ts as i64,
                    tid,
                    pid: tgid,
                    addr: event.addr as i64,
                    error_code: event.flags as i32,
                    stack_id,
                });
            }
            memory_event_type::MEMORY_ALLOC | memory_event_type::MEMORY_FREE => {
                let stack_id = self.intern_stack(&event, tgid);
                let id = self.next_alloc_id;
                self.next_alloc_id += 1;
                let is_realloc =
                    memory_alloc_op(event.member) == memory_alloc_op::MEMORY_OP_REALLOC;
                let _ = collector.add_memory_alloc(MemoryAllocRecord {
                    id,
                    ts: event.ts as i64,
                    tid,
                    pid: tgid,
                    op: alloc_op_name(event.member).to_string(),
                    addr: event.addr as i64,
                    size: event.size as i64,
                    old_addr: if is_realloc {
                        Some(event.old_addr as i64)
                    } else {
                        None
                    },
                    stack_id,
                });
            }
            memory_event_type::MEMORY_MM_SAMPLE => {
                let _ = collector.add_memory_rss(MemoryRssRecord {
                    ts: event.ts as i64,
                    tid,
                    pid: tgid,
                    member: MEMORY_MEMBER_HIWATER_RSS,
                    size: event.addr as i64,
                });
                let _ = collector.add_memory_rss(MemoryRssRecord {
                    ts: event.ts as i64,
                    tid,
                    pid: tgid,
                    member: MEMORY_MEMBER_TOTAL_VM,
                    size: event.size as i64,
                });
            }
            _ => {}
        }

        self.streaming_collector = Some(collector);
    }
}

/// Human-readable label for the `memory_rss.member` column.
pub fn memory_rss_member_name(member: i8) -> &'static str {
    match member {
        0 => "file",
        1 => "anon",
        2 => "swap",
        3 => "shmem",
        MEMORY_MEMBER_HIWATER_RSS => "hiwater_rss",
        MEMORY_MEMBER_TOTAL_VM => "total_vm",
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
