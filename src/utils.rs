/// Utility functions for working with combined tgidpid values.
///
/// In the Linux kernel, `bpf_get_current_pid_tgid()` returns a u64 where:
/// - Lower 32 bits: TID (Thread ID)
/// - Upper 32 bits: TGID (Thread Group ID, which is the Process ID)
///
///   Extract TID (Thread ID) from combined tgidpid value.
///
/// The lower 32 bits contain the TID.
///
/// # Examples
///
/// ```
/// let tgidpid: u64 = 0x0000_1234_0000_5678;
/// let tid = tid_from_tgidpid(tgidpid);
/// assert_eq!(tid, 0x5678);
/// ```
#[inline(always)]
pub const fn tid_from_tgidpid(tgidpid: u64) -> i32 {
    (tgidpid & 0xFFFFFFFF) as i32
}

/// Extract PID (Process ID / TGID) from combined tgidpid value.
///
/// The upper 32 bits contain the PID (TGID - Thread Group ID).
///
/// # Examples
///
/// ```
/// let tgidpid: u64 = 0x0000_1234_0000_5678;
/// let pid = pid_from_tgidpid(tgidpid);
/// assert_eq!(pid, 0x1234);
/// ```
#[inline(always)]
pub const fn pid_from_tgidpid(tgidpid: u64) -> i32 {
    (tgidpid >> 32) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tid_extraction() {
        let tgidpid: u64 = 0x0000_1234_0000_5678;
        assert_eq!(tid_from_tgidpid(tgidpid), 0x5678);
    }

    #[test]
    fn test_pid_extraction() {
        let tgidpid: u64 = 0x0000_1234_0000_5678;
        assert_eq!(pid_from_tgidpid(tgidpid), 0x1234);
    }

    #[test]
    fn test_same_tid_pid() {
        // Main thread has same TID and PID
        let tgidpid: u64 = 0x0000_1000_0000_1000;
        assert_eq!(tid_from_tgidpid(tgidpid), 0x1000);
        assert_eq!(pid_from_tgidpid(tgidpid), 0x1000);
    }

    #[test]
    fn test_max_values() {
        let tgidpid: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        assert_eq!(tid_from_tgidpid(tgidpid), -1);
        assert_eq!(pid_from_tgidpid(tgidpid), -1);
    }
}
