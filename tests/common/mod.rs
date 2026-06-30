//! Common test utilities for systing integration tests.
//!
//! Not every test binary uses every helper here; allow the unused ones
//! rather than making each consumer cherry-pick modules.
#![allow(dead_code)]

pub mod netns;
pub mod workload;
#[allow(unused_imports)]
pub use netns::{
    assert_poll_events_recorded, assert_socket_recorded, count_poll_events_for_socket,
    validate_network_trace, NetnsTestEnv, NetworkTestConfig, NetworkValidationResult,
};
