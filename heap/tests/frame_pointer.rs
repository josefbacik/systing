//! The "frame-pointer" backtrace's walk by frame pointers, given frame pointers
//! of every kind on stacks of every kind (`frame_pointer_target.c`). The
//! register holds whatever code built without frame pointers left in it, and
//! the walk runs inside malloc: it may end early, and it may not fault. That
//! it names Python's functions is in `hooks.rs`.

#![cfg(target_arch = "x86_64")]

mod common;

use std::path::Path;
use std::process::Command;

use common::HOOKS;

const TARGET_C: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/frame_pointer_target.c");

fn run(scenario: &str) {
    let dir = tempfile::tempdir().unwrap();
    if !common::make_hooks(Path::new(HOOKS), dir.path()) {
        return;
    }
    let target = dir.path().join("frame_pointer_target");
    let built = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-O1", "-g", "-Wall", "-Wextra", "-Werror"])
        // The target's own functions are what the walk goes through.
        .arg("-fno-omit-frame-pointer")
        .arg("-o")
        .arg(&target)
        .arg(TARGET_C)
        .args(["-ldl", "-lpthread"])
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let out = Command::new(&target)
        .arg(dir.path().join("libsysting_heap_hooks.so"))
        .arg(scenario)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{scenario}: {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_true_frame_pointer_is_followed_to_the_caller() {
    run("gets-through");
}

#[test]
fn nothing_is_read_through_what_is_not_a_frame_pointer() {
    run("hostile");
}

#[test]
fn records_that_lead_back_or_out_of_the_stack_end_the_walk() {
    run("misleading");
}

#[test]
fn a_threads_stack_ends_at_its_control_block() {
    run("at-the-top");
}

#[test]
fn the_first_stack_ends_at_what_the_kernel_put_above_it() {
    run("at-the-top-of-the-first");
}

#[test]
fn a_threads_range_is_read_once() {
    run("remembers");
}

#[test]
fn what_was_unmapped_inside_a_remembered_range_is_not_a_fault() {
    run("outlives-its-range");
}

#[test]
fn a_thread_that_was_on_a_stack_of_the_programs_own_goes_without() {
    run("fibers");
}

#[test]
fn the_first_stack_is_followed_as_it_grows() {
    run("grows");
}

#[test]
fn threads_that_come_and_go_each_have_their_own_range() {
    run("many-threads");
}

#[test]
fn a_forked_child_goes_on_where_its_thread_was() {
    run("forks");
}

#[test]
fn where_proc_cannot_be_read_the_thread_goes_without_and_errno_is_as_it_was() {
    run("keeps-errno");
}
