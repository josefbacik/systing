// Integration tests for privilege separation functionality
//
// These tests verify that privilege separation via systemd-run works correctly.
// They require systemd and polkit to be available, so they are marked as ignored
// by default.

#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    #[ignore] // Requires systemd, polkit interaction, and user authentication
    fn test_privilege_separation_creates_user_owned_file() {
        // Test that unprivileged systing can create trace.pb owned by the user
        let output = Command::new(env!("CARGO_BIN_EXE_systing"))
            .args(["--duration", "1"])
            .output()
            .expect("Failed to run systing");

        assert!(
            output.status.success(),
            "systing should complete successfully"
        );
        assert!(
            std::path::Path::new("trace.pb").exists(),
            "trace.pb should be created"
        );

        // Verify file is owned by current user, not root
        let metadata = std::fs::metadata("trace.pb").expect("Failed to get trace.pb metadata");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let file_uid = metadata.uid();
            let current_uid = unsafe { libc::getuid() };
            assert_eq!(
                file_uid, current_uid,
                "trace.pb should be owned by current user ({}), not root (got {})",
                current_uid, file_uid
            );
        }

        // Cleanup
        std::fs::remove_file("trace.pb").ok();
    }

    #[test]
    #[ignore] // Requires systemd-run to NOT be available
    fn test_error_message_without_systemd_run() {
        // This test should be run on a system without systemd-run
        // to verify the helpful error message is displayed

        // Note: This is more of a documentation test - actual testing
        // would require mocking or a non-systemd environment
    }

    #[test]
    #[ignore] // Requires CAP_BPF capability to be set on binary
    fn test_with_capabilities_no_privilege_separation() {
        // Test that if systing has CAP_BPF capability, it doesn't use
        // privilege separation (just runs directly)

        // Prerequisites:
        // sudo setcap cap_bpf,cap_perfmon,cap_sys_resource=ep path/to/systing

        // Note: This would require capability setup in CI environment
    }

    #[test]
    fn test_no_privilege_separation_flag() {
        // Test that --no-privilege-separation flag is parsed correctly
        let output = Command::new(env!("CARGO_BIN_EXE_systing"))
            .args(["--no-privilege-separation", "--help"])
            .output()
            .expect("Failed to run systing --help");

        assert!(output.status.success());
    }

    #[test]
    fn test_privileged_mode_flag_is_hidden() {
        // Verify that --privileged-mode flag is hidden from help output
        let output = Command::new(env!("CARGO_BIN_EXE_systing"))
            .arg("--help")
            .output()
            .expect("Failed to run systing --help");

        let help_text = String::from_utf8_lossy(&output.stdout);
        assert!(
            !help_text.contains("--privileged-mode"),
            "privileged-mode flag should be hidden from help output"
        );
    }
}
