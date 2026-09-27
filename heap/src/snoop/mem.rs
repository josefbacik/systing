//! Reading another process's memory.
//!
//! Every read is made by the kernel on `/proc/<pid>/mem`, so an address the
//! target has freed or unmapped since we learned it is an error here, never a
//! fault in either process. Nothing is written and the target is not stopped:
//! what is read may change under the reader, and the walk is written for that.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, Ordering};

/// What the walk needs from a process's memory. A trait so the walk can be
/// tested against memory made up in a test.
pub trait Memory {
    /// Read up to `buf.len()` bytes at `addr`; fewer when the range runs into
    /// memory that cannot be read. Fails when not even the first byte can.
    fn read_some(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Fill `buf`, or fail.
    fn read_exact(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            let n = self.read_some(addr.wrapping_add(done as u64), &mut buf[done..])?;
            done += n;
        }
        Ok(())
    }

    /// `len` bytes at `addr`.
    fn bytes(&self, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut v = vec![0u8; len];
        self.read_exact(addr, &mut v)?;
        Ok(v)
    }

    fn u64_at(&self, addr: u64) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }
}

/// A live process's memory, through `/proc/<pid>/mem`.
pub struct ProcMem {
    file: File,
    reads: AtomicU64,
    bytes: AtomicU64,
}

impl ProcMem {
    /// Open a process's `mem` file. The kernel decides who may: the caller
    /// needs ptrace access to the process (the same user, unless it is root or
    /// has CAP_SYS_PTRACE, and subject to `kernel.yama.ptrace_scope`).
    pub fn open(mem_path: &std::path::Path) -> io::Result<ProcMem> {
        Ok(ProcMem {
            file: File::open(mem_path)?,
            reads: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        })
    }

    /// (reads made, bytes read) so far.
    pub fn traffic(&self) -> (u64, u64) {
        (
            self.reads.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }
}

impl Memory for ProcMem {
    fn read_some(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // pread takes a signed offset: an address in the upper half of the
        // address space is not user memory.
        if i64::try_from(addr).is_err() {
            return Err(io::Error::from_raw_os_error(libc::EFAULT));
        }
        self.reads.fetch_add(1, Ordering::Relaxed);
        loop {
            match self.file.read_at(buf, addr) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => {
                    self.bytes.fetch_add(n as u64, Ordering::Relaxed);
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
pub mod fake {
    //! Memory made up in a test: a set of byte ranges at chosen addresses.

    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct FakeMem {
        ranges: BTreeMap<u64, Vec<u8>>,
    }

    impl FakeMem {
        pub fn put(&mut self, addr: u64, bytes: Vec<u8>) {
            self.ranges.insert(addr, bytes);
        }

        /// Overwrite bytes inside an existing range.
        pub fn poke(&mut self, addr: u64, bytes: &[u8]) {
            let (&start, range) = self.ranges.range_mut(..=addr).next_back().unwrap();
            let at = (addr - start) as usize;
            range[at..at + bytes.len()].copy_from_slice(bytes);
        }

        pub fn poke_u64(&mut self, addr: u64, v: u64) {
            self.poke(addr, &v.to_le_bytes());
        }
    }

    impl Memory for FakeMem {
        fn read_some(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            let Some((&start, range)) = self.ranges.range(..=addr).next_back() else {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            };
            let at = (addr - start) as usize;
            if at >= range.len() {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let n = buf.len().min(range.len() - at);
            buf[..n].copy_from_slice(&range[at..at + n]);
            Ok(n)
        }
    }
}
