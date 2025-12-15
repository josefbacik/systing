//! Recording subsystem for trace data collection.
//!
//! This module provides the infrastructure for collecting trace data
//! from BPF events and writing it to storage.

pub mod collector;

pub use collector::RecordCollector;
