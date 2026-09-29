//! Resolving paths beneath a directory that stands for another root, such as
//! a container's seen from outside it.
//!
//! A dump names the files its process had mapped by the paths that process
//! saw. Read from outside the process's container, joining those paths onto
//! the container's root is not enough: the kernel resolves an absolute
//! symlink on the way (`/lib -> /usr/lib`, or one planted to point at
//! `/etc/shadow`) and a `..` at the top against the caller's root, so the
//! walk can leave the container. [`Root`] holds a handle on the directory and
//! opens every path with `openat2(2)` and `RESOLVE_IN_ROOT`: the kernel then
//! resolves absolute paths, absolute symlinks and `..` as it would for a
//! process whose root that directory is, and nothing resolves outside it.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// How often an open is tried again when the kernel answers `EAGAIN`.
const RETRIES: u32 = 16;

/// A directory that every path is resolved beneath.
#[derive(Debug)]
pub struct Root {
    dir: OwnedFd,
}

impl Root {
    /// The root at `dir`. `dir` is the caller's own path and is followed like
    /// any other, so it may be a process's `/proc/<pid>/root`.
    pub fn open(dir: &Path) -> io::Result<Root> {
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(dir)?;
        Root::from_dir(handle)
    }

    /// The root at an open directory descriptor inherited from the caller.
    /// The descriptor is duplicated, so the caller's stays as it was.
    pub fn from_fd(fd: RawFd) -> io::Result<Root> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a file descriptor",
            ));
        }
        // SAFETY: the descriptor is borrowed only for the duplication, and a
        // number that is not open makes the duplication fail with EBADF.
        let owned = unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?;
        Root::from_dir(File::from(owned))
    }

    /// The root at an open directory. It fails where the kernel cannot resolve
    /// beneath a root, so that is known before any path is looked up.
    pub fn from_dir(dir: File) -> io::Result<Root> {
        if !dir.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a directory",
            ));
        }
        let root = Root {
            dir: OwnedFd::from(dir),
        };
        root.open_at(Path::new("."), libc::O_PATH | libc::O_DIRECTORY)?;
        Ok(root)
    }

    /// Open `path` beneath the root. An absolute path, an absolute symlink
    /// met on the way and a `..` at the top all resolve against the root, and
    /// a procfs-style magic link is refused (`ELOOP`). Mounts beneath the
    /// root are crossed. `flags` are open(2)'s, with `O_CLOEXEC` added.
    ///
    /// There is no fallback to a plain open: where the kernel has no
    /// `openat2` (before Linux 5.6) this is an error.
    pub fn open_at(&self, path: &Path, flags: libc::c_int) -> io::Result<File> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
        // SAFETY: open_how is three integers, for which all zeroes is a valid
        // value; libc marks it non-exhaustive, so it cannot be built by name.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (flags | libc::O_CLOEXEC) as u64;
        how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
        // While it steps over a `..` the kernel answers EAGAIN, rather than
        // risk an escape, if anything on the system was renamed or mounted
        // meanwhile, and asks to be called again.
        let mut tries = 0;
        loop {
            // SAFETY: an open directory descriptor, a NUL-terminated path, and
            // an open_how passed with its size; the kernel only reads them.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    self.dir.as_raw_fd(),
                    c_path.as_ptr(),
                    &how as *const libc::open_how,
                    std::mem::size_of::<libc::open_how>(),
                )
            };
            if fd >= 0 {
                // SAFETY: the kernel just returned this descriptor, and
                // nothing else owns it.
                return Ok(unsafe { File::from_raw_fd(fd as RawFd) });
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) if tries < RETRIES => tries += 1,
                Some(libc::ENOSYS) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "resolving paths beneath a root needs openat2(2), Linux 5.6 or later",
                    ))
                }
                _ => return Err(err),
            }
        }
    }
}

/// Whether `file` is on a filesystem whose files live somewhere else: FUSE, or
/// a network filesystem. Beneath a root the paths opened are chosen by whoever
/// wrote the dumps; a read from such a mount would be made with the reader's
/// authority on storage the container only mounts (a bucket, a file server),
/// and it can stall without end. A file there is left unread. This is a deny
/// list of the known types: a filesystem that is not on it reads as local.
pub fn on_remote_fs(file: &File) -> bool {
    // SAFETY: statfs is plain integers, for which all zeroes is a valid value.
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid fd and a writable statfs.
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut sfs) } != 0 {
        return true;
    }
    // f_type is a long on some targets and an int on others; the magic
    // numbers are 32 bits either way.
    is_remote_fs_type(sfs.f_type as u32)
}

fn is_remote_fs_type(f_type: u32) -> bool {
    // Magic numbers from linux/magic.h and the filesystems' own headers, as
    // coreutils' stat lists them.
    const REMOTE: [u32; 13] = [
        0x6573_5546, // fuse, fuseblk, virtiofs
        0x6969,      // nfs
        0x517b,      // smb
        0xff53_4d42, // cifs
        0xfe53_4d42, // smb2
        0x00c3_6400, // ceph
        0x0102_1997, // 9p
        0x5346_414f, // afs
        0x6b41_4653, // kafs
        0x7375_7245, // coda
        0x0bd0_0bd0, // lustre
        0x4750_4653, // gpfs
        0x1983_0326, // beegfs
    ];
    REMOTE.contains(&f_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    fn read_at(root: &Root, path: &str) -> io::Result<String> {
        let mut text = String::new();
        root.open_at(Path::new(path), libc::O_RDONLY)?
            .read_to_string(&mut text)?;
        Ok(text)
    }

    /// A directory outside any root under test, holding a file that must
    /// never be read through one.
    fn outside() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret"), "outside").unwrap();
        dir
    }

    #[test]
    fn an_absolute_symlink_resolves_beneath_the_root() {
        let outside = outside();
        let secret = outside.path().join("secret");
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("lib")).unwrap();
        symlink(&secret, dir.path().join("lib/x")).unwrap();
        let root = Root::open(dir.path()).unwrap();

        // The link's target does not exist beneath the root.
        assert_eq!(
            read_at(&root, "/lib/x").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        // Once it does, that file is the one read, not the one outside.
        let inside = dir.path().join(secret.strip_prefix("/").unwrap());
        std::fs::create_dir_all(inside.parent().unwrap()).unwrap();
        std::fs::write(&inside, "inside").unwrap();
        assert_eq!(read_at(&root, "/lib/x").unwrap(), "inside");
    }

    #[test]
    fn dot_dot_does_not_climb_out_of_the_root() {
        let outside = outside();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        let climb = format!(
            "../../../../../../../../../../../..{}/secret",
            outside.path().display()
        );
        symlink(&climb, dir.path().join("a/up")).unwrap();
        let root = Root::open(dir.path()).unwrap();

        for path in [format!("/{climb}"), climb, "/a/up".to_string()] {
            assert_eq!(
                read_at(&root, &path).unwrap_err().kind(),
                io::ErrorKind::NotFound,
                "{path}"
            );
        }
    }

    #[test]
    fn links_that_stay_beneath_the_root_resolve() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        std::fs::create_dir(dir.path().join("b")).unwrap();
        std::fs::write(dir.path().join("b/z"), "z").unwrap();
        symlink("../b/z", dir.path().join("a/y")).unwrap();
        symlink("/b", dir.path().join("lib")).unwrap();
        let root = Root::open(dir.path()).unwrap();

        assert_eq!(read_at(&root, "/a/y").unwrap(), "z");
        assert_eq!(read_at(&root, "/lib/z").unwrap(), "z");
        // A relative path starts at the root.
        assert_eq!(read_at(&root, "a/y").unwrap(), "z");
    }

    #[test]
    fn a_magic_link_is_refused() {
        let root = Root::open(Path::new("/")).unwrap();
        let err = root
            .open_at(Path::new("/proc/self/exe"), libc::O_RDONLY)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn fuse_and_network_filesystems_are_remote_and_disk_ones_are_not() {
        assert!(is_remote_fs_type(0x6573_5546), "fuse");
        assert!(is_remote_fs_type(0x6969), "nfs");
        // ext4, tmpfs, overlayfs, xfs, btrfs.
        for local in [
            0xef53_u32,
            0x0102_1994,
            0x794c_7630,
            0x5846_5342,
            0x9123_683e,
        ] {
            assert!(!is_remote_fs_type(local), "{local:#x}");
        }
    }

    #[test]
    fn only_a_directory_can_be_a_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f"), "f").unwrap();
        assert!(Root::open(&dir.path().join("f")).is_err());

        let file = File::open(dir.path().join("f")).unwrap();
        assert_eq!(
            Root::from_fd(file.as_raw_fd()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            Root::from_fd(-1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let handle = File::open(dir.path()).unwrap();
        let root = Root::from_fd(handle.as_raw_fd()).unwrap();
        assert_eq!(read_at(&root, "/f").unwrap(), "f");
    }
}
