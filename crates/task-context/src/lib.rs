//! Attach a few named values to the calling thread so that a tracer can read
//! them from outside the process.
//!
//! A thread sets a name — `request_id`, `iteration_id` — to a string of up to
//! [`VALUE_MAX`] bytes or to a 64-bit number. A tracer started with
//! `--include-task-context` finds those values by a recipe the library
//! publishes in the process, and stores them beside each sample it takes of
//! that thread. Nothing here talks to a tracer: setting a value is a few
//! stores into memory the thread owns.
//!
//! ```
//! task_context::set_str("request_id", "abc-123").unwrap();
//! task_context::set_u64("iteration_id", 42).unwrap();
//! assert_ne!(task_context::current_id(), 0);
//! task_context::clear("request_id").unwrap();
//! ```
//!
//! The library itself is one C file (`src/task_context.c`), because it needs
//! a thread-local with a fixed TLS model and a load-time constructor; this
//! crate compiles it and wraps its five functions. The contract between the
//! library and a reader — the two records, how they are written, how they
//! must be read — is `include/task_context.h`, and that file is the
//! reference for everything below.
//!
//! **Trust.** Any process can set any name to any value. A consumer may join
//! on a context value; it must never authorise, bill or attribute ownership
//! by one. Values are copied into traces: do not put a secret in one.

use core::ffi::{c_char, c_int, c_void};
use core::fmt;

/// Longest string value, in bytes. A longer one is refused, never truncated.
pub const VALUE_MAX: usize = 256;
/// Size of the name buffer; a name is 1 to `NAME_MAX - 1` bytes.
pub const NAME_MAX: usize = 32;
/// How many names one thread can have set at once.
pub const SLOTS: usize = 8;
/// Distance between two threads' blocks inside the region.
pub const BLOCK_STRIDE: usize = 2560;
/// Size of the one region every block lives in.
pub const REGION_SIZE: usize = 16 * 1024 * 1024;
/// `magic` of the per-process record.
pub const INFO_MAGIC: u32 = 0x3158_4354;
/// `magic` of a thread's block.
pub const BLOCK_MAGIC: u32 = 0x4258_4354;
/// The one recipe version 1 publishes: slot = thread pointer + `tp_offset`.
pub const RECIPE_TP_OFFSET: u32 = 1;

/// Why a call was refused. Nothing is ever truncated or partly applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The name is empty, 32 bytes or longer, or has a byte outside
    /// `[A-Za-z0-9_.:-]`.
    InvalidName,
    /// The value cannot be passed on (it contains a NUL byte).
    InvalidValue,
    /// The string is longer than [`VALUE_MAX`] bytes.
    TooLong,
    /// [`SLOTS`] names are already set on this thread.
    NoSlot,
    /// The call interrupted this thread's own update (a signal handler).
    Busy,
    /// More threads hold a block than the region has room for.
    NoBlock,
    /// The region could not be reserved.
    NoMemory,
    /// The library's thread-local is not in static TLS in this process.
    Unsupported,
    /// A code this binding does not know.
    Other(i32),
}

impl Error {
    fn from_code(code: c_int) -> Error {
        match code {
            -1 => Error::InvalidName,
            -2 => Error::InvalidValue,
            -3 => Error::TooLong,
            -4 => Error::NoSlot,
            -5 => Error::Busy,
            -6 => Error::NoBlock,
            -7 => Error::NoMemory,
            -8 => Error::Unsupported,
            other => Error::Other(other),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidName => write!(
                f,
                "invalid name: 1 to {} bytes of [A-Za-z0-9_.:-]",
                NAME_MAX - 1
            ),
            Error::InvalidValue => write!(f, "invalid value: it contains a NUL byte"),
            Error::TooLong => write!(f, "value longer than {VALUE_MAX} bytes"),
            Error::NoSlot => write!(f, "{SLOTS} names are already set on this thread"),
            Error::Busy => write!(f, "the call interrupted this thread's own update"),
            Error::NoBlock => write!(f, "the block region is full"),
            Error::NoMemory => write!(f, "the block region could not be reserved"),
            Error::Unsupported => write!(f, "the thread-local is not in static TLS"),
            Error::Other(code) => write!(f, "task_context error {code}"),
        }
    }
}

impl std::error::Error for Error {}

/// The per-process record a reader looks for, field for field as
/// `struct task_context_info_v1` lays it out.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfoV1 {
    pub magic: u32,
    pub version: u16,
    pub info_size: u16,
    pub recipe_tag: u32,
    pub recipe_generation: u32,
    pub tp_offset: i64,
    pub dtv_modid: u64,
    pub dtv_block_offset: u64,
    pub pthread_key: u32,
    pub flags: u32,
    pub self_address: u64,
    pub region_base: u64,
    pub region_size: u64,
    pub block_size: u32,
    pub block_hdr_size: u16,
    pub slot_size: u16,
    pub nslots: u16,
    pub name_max: u16,
    pub value_max: u32,
    pub region_full_count: u64,
    pub busy_refused_count: u64,
}

const _: () = assert!(core::mem::size_of::<InfoV1>() == 104);

/// What the calling thread looks like to a reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfDescription {
    /// The thread pointer as the architecture defines it.
    pub thread_pointer: usize,
    /// Address of the library's thread-local in this thread.
    pub slot_address: usize,
    /// `slot_address - thread_pointer`: one constant for the whole process.
    pub tp_offset: i64,
    /// Address of this thread's block, 0 before its first set.
    pub block: usize,
    /// The thread's current context id, 0 before its first set.
    pub id: u64,
}

#[repr(C)]
struct RawSelf {
    thread_pointer: *const c_void,
    slot_address: *const c_void,
    tp_offset: i64,
    block: *const c_void,
    id: u64,
}

extern "C" {
    #[link_name = "task_context_info_v1"]
    static TASK_CONTEXT_INFO_V1: InfoV1;

    fn set_task_context_str(name: *const c_char, value: *const c_char) -> c_int;
    fn set_task_context_u64(name: *const c_char, value: u64) -> c_int;
    fn clear_task_context(name: *const c_char) -> c_int;
    fn task_context_current_id() -> u64;
    fn task_context_describe_self(out: *mut RawSelf) -> c_int;
}

fn check(code: c_int) -> Result<(), Error> {
    match code {
        0 => Ok(()),
        refused => Err(Error::from_code(refused)),
    }
}

/// A NUL-terminated copy of the name on the stack. The library checks the
/// character class; this only makes sure the name can be passed at all.
fn c_name(name: &str) -> Result<[u8; NAME_MAX], Error> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= NAME_MAX || bytes.contains(&0) {
        return Err(Error::InvalidName);
    }
    let mut buf = [0u8; NAME_MAX];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(buf)
}

/// Set `name` to a string on the calling thread.
///
/// No system call, no lock and no allocation after the thread's first call.
pub fn set_str(name: &str, value: &str) -> Result<(), Error> {
    let name = c_name(name)?;
    let bytes = value.as_bytes();
    if bytes.contains(&0) {
        return Err(Error::InvalidValue);
    }
    if bytes.len() > VALUE_MAX {
        return Err(Error::TooLong);
    }
    let mut buf = [0u8; VALUE_MAX + 1];
    buf[..bytes.len()].copy_from_slice(bytes);
    // SAFETY: both buffers are NUL-terminated and outlive the call; the
    // library copies what it keeps.
    check(unsafe { set_task_context_str(name.as_ptr().cast(), buf.as_ptr().cast()) })
}

/// Set `name` to a 64-bit number on the calling thread.
pub fn set_u64(name: &str, value: u64) -> Result<(), Error> {
    let name = c_name(name)?;
    // SAFETY: the name is NUL-terminated and outlives the call.
    check(unsafe { set_task_context_u64(name.as_ptr().cast(), value) })
}

/// Forget `name` on the calling thread and free its slot. Clearing a name
/// that is not set succeeds and changes nothing.
pub fn clear(name: &str) -> Result<(), Error> {
    let name = c_name(name)?;
    // SAFETY: the name is NUL-terminated and outlives the call.
    check(unsafe { clear_task_context(name.as_ptr().cast()) })
}

/// The calling thread's current context id, or 0 when it never set a value.
///
/// The id changes at every completed set or clear; equal ids of one thread
/// mean equal values.
pub fn current_id() -> u64 {
    // SAFETY: the function takes no argument and only reads.
    unsafe { task_context_current_id() }
}

/// Describe the calling thread the way a reader would find it. Never takes a
/// block and never publishes.
pub fn describe_self() -> SelfDescription {
    let mut raw = RawSelf {
        thread_pointer: core::ptr::null(),
        slot_address: core::ptr::null(),
        tp_offset: 0,
        block: core::ptr::null(),
        id: 0,
    };
    // SAFETY: `raw` is a valid, writable `struct task_context_self`.
    let code = unsafe { task_context_describe_self(&mut raw) };
    debug_assert_eq!(code, 0);
    SelfDescription {
        thread_pointer: raw.thread_pointer as usize,
        slot_address: raw.slot_address as usize,
        tp_offset: raw.tp_offset,
        block: raw.block as usize,
        id: raw.id,
    }
}

/// A copy of the per-process record as it stands now.
pub fn info() -> InfoV1 {
    // SAFETY: the record is a static the library defines; its fields are
    // plain integers, and a concurrent update of a counter cannot make the
    // copy invalid.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TASK_CONTEXT_INFO_V1)) }
}

/// Address of the per-process record in this process.
pub fn info_address() -> usize {
    core::ptr::addr_of!(TASK_CONTEXT_INFO_V1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    // The block's layout, from task_context.h.
    const BLOCK_MAGIC_AT: usize = 0;
    const BLOCK_SEQ_AT: usize = 8;
    const BLOCK_MASK_AT: usize = 16;
    const BLOCK_SLOTS_AT: usize = 32;
    const SLOT_SIZE: usize = 296;
    const SLOT_TYPE_AT: usize = 0;
    const SLOT_NAME_LEN_AT: usize = 1;
    const SLOT_VALUE_LEN_AT: usize = 2;
    const SLOT_NAME_AT: usize = 8;
    const SLOT_VALUE_AT: usize = 40;

    const COUNT_MASK: u64 = 0x0000_00ff_ffff_fffe;
    const INDEX_SHIFT: u32 = 40;

    /// Every test body runs on a thread of its own, so no test sees the
    /// context another left behind, however the test runner schedules them.
    fn on_a_fresh_thread<F>(body: F)
    where
        F: FnOnce() + Send + 'static,
    {
        thread::spawn(body)
            .join()
            .expect("the test thread panicked");
    }

    fn read<T: Copy>(address: usize) -> T {
        // SAFETY: the tests only pass addresses inside a block of the one
        // region, which is mapped for the life of the process.
        unsafe { core::ptr::read_volatile(address as *const T) }
    }

    fn slot_address(block: usize, index: usize) -> usize {
        block + BLOCK_SLOTS_AT + index * SLOT_SIZE
    }

    fn slot_of(block: usize, name: &str) -> Option<usize> {
        let mask: u32 = read(block + BLOCK_MASK_AT);
        (0..SLOTS).find(|&index| {
            if (mask >> index) & 1 == 0 {
                return false;
            }
            let slot = slot_address(block, index);
            let len = read::<u8>(slot + SLOT_NAME_LEN_AT) as usize;
            (0..len).all(|at| {
                name.as_bytes().get(at).copied() == Some(read::<u8>(slot + SLOT_NAME_AT + at))
            }) && len == name.len()
        })
    }

    fn index_of(id: u64) -> u64 {
        id >> INDEX_SHIFT
    }

    #[test]
    fn the_recipe_is_published_before_any_set() {
        on_a_fresh_thread(|| {
            let info = info();
            assert_eq!(info.magic, INFO_MAGIC);
            assert_eq!(info.version, 1);
            assert_eq!(info.info_size, 104);
            assert_eq!(info.recipe_tag, RECIPE_TP_OFFSET);
            assert!(info.recipe_generation >= 1);
            assert_eq!(info.self_address, info_address() as u64);
            assert_eq!(info.region_size, REGION_SIZE as u64);
            assert_ne!(info.region_base, 0);
            assert_eq!(info.region_base % 4096, 0);
            assert_eq!(info.block_size, BLOCK_STRIDE as u32);
            assert_eq!(info.block_hdr_size, BLOCK_SLOTS_AT as u16);
            assert_eq!(info.slot_size, SLOT_SIZE as u16);
            assert_eq!(info.nslots, SLOTS as u16);
            assert_eq!(info.name_max, NAME_MAX as u16);
            assert_eq!(info.value_max, VALUE_MAX as u32);
            // Static TLS lies below the thread pointer on x86-64 and above
            // it on aarch64.
            if cfg!(target_arch = "x86_64") {
                assert!(info.tp_offset < 0, "tp_offset {}", info.tp_offset);
            } else {
                assert!(info.tp_offset > 0, "tp_offset {}", info.tp_offset);
            }
            assert_eq!(describe_self().tp_offset, info.tp_offset);
        });
    }

    #[test]
    fn a_thread_that_never_set_has_no_block() {
        on_a_fresh_thread(|| {
            let before = describe_self();
            assert_eq!(before.block, 0);
            assert_eq!(before.id, 0);
            assert_eq!(current_id(), 0);
            // Clearing takes no block either.
            clear("never_set").unwrap();
            assert_eq!(describe_self().block, 0);
        });
    }

    #[test]
    fn set_and_clear_move_the_id_and_the_recipe_finds_the_block() {
        on_a_fresh_thread(|| {
            set_u64("a", 1).unwrap();
            let first = current_id();
            assert_ne!(first, 0);
            assert_eq!(first & 1, 0, "an id is an even word");
            assert_ne!(index_of(first), 0, "a thread index is never 0");
            assert_eq!(first & COUNT_MASK, 4, "one update after the first word");

            set_u64("a", 2).unwrap();
            let second = current_id();
            assert_eq!(second & COUNT_MASK, 6);
            assert_eq!(index_of(second), index_of(first));

            clear("a").unwrap();
            let third = current_id();
            assert_eq!(third & COUNT_MASK, 8);

            // Nothing to clear: the id stays.
            clear("a").unwrap();
            assert_eq!(current_id(), third);

            // What a reader does: thread pointer + the published offset
            // holds the block's address, inside the published region.
            let info = info();
            let me = describe_self();
            assert_eq!(me.id, third);
            assert_eq!(
                me.slot_address as i64 - me.thread_pointer as i64,
                info.tp_offset
            );
            let slot = (me.thread_pointer as i64 + info.tp_offset) as usize;
            assert_eq!(read::<usize>(slot), me.block);
            let base = info.region_base as usize;
            assert!(me.block >= base && me.block < base + REGION_SIZE);
            assert_eq!((me.block - base) % BLOCK_STRIDE, 0);
            assert_eq!(read::<u32>(me.block + BLOCK_MAGIC_AT), BLOCK_MAGIC);
            assert_eq!(read::<u64>(me.block + BLOCK_SEQ_AT), third);
            assert_eq!(read::<u32>(me.block + BLOCK_MASK_AT), 0);
        });
    }

    #[test]
    fn names_are_checked() {
        on_a_fresh_thread(|| {
            assert_eq!(set_u64("", 1), Err(Error::InvalidName));
            assert_eq!(set_u64(&"n".repeat(NAME_MAX), 1), Err(Error::InvalidName));
            assert_eq!(set_u64("two words", 1), Err(Error::InvalidName));
            assert_eq!(set_u64("slash/", 1), Err(Error::InvalidName));
            assert_eq!(set_u64("nul\0inside", 1), Err(Error::InvalidName));
            assert_eq!(clear("two words"), Err(Error::InvalidName));
            // None of the refusals took a block.
            assert_eq!(describe_self().block, 0);

            set_u64(&"n".repeat(NAME_MAX - 1), 1).unwrap();
            set_u64("ok_.:-9", 1).unwrap();
        });
    }

    #[test]
    fn a_value_is_kept_whole_or_refused() {
        on_a_fresh_thread(|| {
            let longest = "v".repeat(VALUE_MAX);
            set_str("longest", &longest).unwrap();
            assert_eq!(
                set_str("longest", &"v".repeat(VALUE_MAX + 1)),
                Err(Error::TooLong)
            );
            assert_eq!(set_str("longest", "nul\0inside"), Err(Error::InvalidValue));

            // The refusals left the full-length value in place.
            let block = describe_self().block;
            let slot = slot_address(block, slot_of(block, "longest").unwrap());
            assert_eq!(read::<u8>(slot + SLOT_TYPE_AT), 2);
            assert_eq!(read::<u16>(slot + SLOT_VALUE_LEN_AT) as usize, VALUE_MAX);
            assert!((0..VALUE_MAX).all(|at| read::<u8>(slot + SLOT_VALUE_AT + at) == b'v'));
        });
    }

    #[test]
    fn a_number_leaves_nothing_of_the_string_it_replaces() {
        on_a_fresh_thread(|| {
            set_str("k", "a string of some length").unwrap();
            set_u64("k", 7).unwrap();
            let block = describe_self().block;
            let slot = slot_address(block, slot_of(block, "k").unwrap());
            assert_eq!(read::<u8>(slot + SLOT_TYPE_AT), 1);
            assert_eq!(read::<u16>(slot + SLOT_VALUE_LEN_AT), 8);
            assert_eq!(read::<u64>(slot + SLOT_VALUE_AT), 7);
            assert!((8..VALUE_MAX).all(|at| read::<u8>(slot + SLOT_VALUE_AT + at) == 0));
        });
    }

    #[test]
    fn a_ninth_name_is_refused_until_one_is_cleared() {
        on_a_fresh_thread(|| {
            for n in 0..SLOTS {
                set_u64(&format!("n{n}"), n as u64).unwrap();
            }
            let full = current_id();
            assert_eq!(set_u64("one_more", 9), Err(Error::NoSlot));
            assert_eq!(current_id(), full, "a refused set leaves the id alone");

            clear("n3").unwrap();
            set_u64("one_more", 9).unwrap();
            let block = describe_self().block;
            assert!(slot_of(block, "n3").is_none());
            assert!(slot_of(block, "one_more").is_some());
        });
    }

    #[test]
    fn every_thread_has_the_same_offset_and_its_own_block() {
        const THREADS: usize = 4;
        let all_hold_a_block = Arc::new(Barrier::new(THREADS));
        let workers: Vec<_> = (0..THREADS)
            .map(|n| {
                let all_hold_a_block = Arc::clone(&all_hold_a_block);
                thread::spawn(move || {
                    set_u64("who", n as u64).unwrap();
                    let me = describe_self();
                    // Nobody exits, and so returns its block, before
                    // everybody has one.
                    all_hold_a_block.wait();
                    me
                })
            })
            .collect();
        let seen: Vec<SelfDescription> = workers.into_iter().map(|w| w.join().unwrap()).collect();

        let offset = info().tp_offset;
        for me in &seen {
            assert_eq!(me.tp_offset, offset);
            assert_ne!(me.block, 0);
        }
        for a in 0..THREADS {
            for b in a + 1..THREADS {
                assert_ne!(seen[a].block, seen[b].block);
                assert_ne!(index_of(seen[a].id), index_of(seen[b].id));
            }
        }
    }

    #[test]
    fn a_returned_block_comes_back_empty_under_a_new_index() {
        let first = thread::spawn(|| {
            set_str("left_behind", "by the first owner").unwrap();
            describe_self()
        })
        .join()
        .unwrap();
        let second = thread::spawn(|| {
            set_u64("fresh", 1).unwrap();
            let me = describe_self();
            let mask: u32 = read(me.block + BLOCK_MASK_AT);
            (me, mask, slot_of(me.block, "left_behind"))
        })
        .join()
        .unwrap();

        let (me, mask, stale) = second;
        assert_ne!(index_of(me.id), index_of(first.id));
        assert_eq!(mask.count_ones(), 1);
        assert!(stale.is_none());
    }

    /// One thread rewrites ONE value over and over: a string wider than any
    /// single store, every 8-byte word of it carrying the round. The other
    /// reads word, value, word. Under a stable even word every word of the
    /// value must agree. A tear of one update (new bytes seen under the old
    /// id, which is what a missing writer fence would allow on weakly ordered
    /// hardware) shows as words that differ; two values set by two updates
    /// could not show it, because every state such a tear produces is a state
    /// the writer passes through anyway. On x86-64 stores are not reordered
    /// with stores and this cannot fail; it is here to be run on weakly
    /// ordered hardware.
    #[test]
    fn a_reader_on_another_thread_never_keeps_a_torn_value() {
        const ROUNDS: u64 = 200_000;
        const WORDS: usize = 8;
        let block_address = Arc::new(AtomicU64::new(0));
        let writer_done = Arc::new(AtomicBool::new(false));

        let writer = {
            let block_address = Arc::clone(&block_address);
            let writer_done = Arc::clone(&writer_done);
            thread::spawn(move || {
                // Eight hex digits are one 8-byte word; the value is WORDS
                // copies of it, written by one update.
                let value_of = |round: u64| format!("{round:08x}").repeat(WORDS);
                set_str("round", &value_of(0)).unwrap();
                block_address.store(describe_self().block as u64, Ordering::Release);
                for round in 1..=ROUNDS {
                    set_str("round", &value_of(round)).unwrap();
                }
                writer_done.store(true, Ordering::Release);
            })
        };

        let mut block = 0usize;
        while block == 0 {
            block = block_address.load(Ordering::Acquire) as usize;
            thread::yield_now();
        }
        let value = slot_address(block, slot_of(block, "round").unwrap()) + SLOT_VALUE_AT;
        // The words race with the writer by design, so every one of them is
        // read as an atomic.
        fn atomic_at(address: usize) -> &'static AtomicU64 {
            // SAFETY: every address passed is 8-byte aligned inside a block
            // of the region, which stays mapped for the life of the process.
            unsafe { AtomicU64::from_ptr(address as *mut u64) }
        }
        let word = atomic_at(block + BLOCK_SEQ_AT);

        let mut kept = 0u64;
        while !writer_done.load(Ordering::Acquire) {
            let before = word.load(Ordering::Acquire);
            if before & 1 == 1 {
                continue;
            }
            let mut words = [0u64; WORDS];
            for (at, slot) in words.iter_mut().enumerate() {
                *slot = atomic_at(value + 8 * at).load(Ordering::Relaxed);
            }
            fence(Ordering::Acquire);
            if word.load(Ordering::Relaxed) != before {
                continue;
            }
            kept += 1;
            assert!(
                words.iter().all(|&each| each == words[0]),
                "a torn value under id {before:#x}: {words:x?}"
            );
        }
        writer.join().unwrap();
        // Not a claim about how many: only that the loop looked at all.
        let _ = kept;
    }
}
