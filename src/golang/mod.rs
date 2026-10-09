//! Go programs, read from outside: the profiles the Go runtime keeps of
//! itself (heap, block, mutex), its goroutines, and its flight recorder,
//! copied out of the program's memory. Nothing is asked of the program: no
//! pprof port, no signal, no code of ours runs in it, and it is not stopped.
//!
//! The pieces, as `pystacks` has them for Python:
//!
//! - [`discovery`] opens a Go program: its Go version, where the runtime's
//!   globals are (from `.symtab`, or in a stripped binary from the code of the
//!   functions that use them), and the layout to read them with;
//! - [`offsets`] is that layout per Go version, from the generated
//!   [`bindings`] (`scripts/generate_go_bindings.py`, from the runtime's own
//!   DWARF). A version without bindings is refused, never guessed at;
//! - [`profiles`], [`goroutines`] and [`flight`] read what their names say;
//! - [`symbols`] names a program counter by the program's own function table;
//! - [`pprof`] reads Go's profile files, the form the program itself writes,
//!   and writes them.
//!
//! Every read goes through `/proc/<pid>/mem`, with the reader the Python
//! walker uses ([`crate::pystacks::process`]). The program runs on while it is
//! read, so a record can change under the read: records that cannot be right
//! are skipped and counted, never trusted.
//!
//! x86-64 only: the stripped-binary rules find globals by instruction
//! encoding, and the bindings are generated for linux/amd64.

pub mod bindings;
pub mod discovery;
pub mod flight;
pub mod goroutines;
pub mod offsets;
pub mod pprof;
pub mod profiles;
pub mod symbols;

pub use discovery::{is_go, FoundBy, GoProcess};

/// What a read cost and what it skipped.
#[derive(Debug, Default, Clone)]
pub struct ReadStats {
    /// Records read: buckets, goroutines or trace batches.
    pub records: u64,
    /// Records left out because they could not be read or could not be right.
    pub skipped: u64,
    /// Reads of the process's memory, and the bytes they read.
    pub reads: u64,
    pub bytes: u64,
    pub micros: u128,
}

/// The unsigned varint Go's formats use (`encoding/binary.Uvarint`): the
/// value and the bytes it took.
pub(crate) fn uvarint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, &byte) in b.iter().enumerate().take(10) {
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}
