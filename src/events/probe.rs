use std::fmt;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Controls how a probe event is attributed in Perfetto traces and how start/end
/// range keys are matched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventScope {
    /// Attribute to the specific thread (TGIDPID). Default for all events.
    #[default]
    Thread,
    /// Attribute to the process (TGID). Useful for async tasks that migrate
    /// between threads, where start and end markers may fire on different threads.
    Process,
    /// Attribute to the CPU. Events appear on per-CPU tracks under the
    /// top-level Systing track in Perfetto.
    Cpu,
}

// usdt:<path>:<provider>:<name>
#[derive(Clone, Default)]
pub struct UsdtProbeEvent {
    pub path: String,
    pub provider: String,
    pub name: String,
}

// Format is
// uprobe:<path>:<offset>
// uprobe:<path>:<symbol>
// uprobe:<path>:<symbol>+<offset>
// uretprobe:<path>:<offset>
// uretprobe:<path>:<symbol>
// uretprobe:<path>:<symbol>+<offset>
#[derive(Clone, Default)]
pub struct UProbeEvent {
    pub path: String,
    pub offset: u64,
    pub func_name: String,
    pub retprobe: bool,
}

// Format is
// kprobe:<offset>
// kprobe:<symbol>
// kprobe:<symbol>+<offset>
// kretprobe:<offset>
// kretprobe:<symbol>
// kretprobe:<symbol>+<offset>
#[derive(Clone, Default)]
pub struct KProbeEvent {
    pub offset: u64,
    pub func_name: String,
    pub retprobe: bool,
}

// Format is
// tracepoint:<category>:<name>
#[derive(Clone, Default)]
pub struct TracepointEvent {
    pub category: String,
    pub name: String,
}

#[derive(Clone, Default)]
pub enum EventProbe {
    UProbe(UProbeEvent),
    Usdt(UsdtProbeEvent),
    KProbe(KProbeEvent),
    Tracepoint(TracepointEvent),
    #[default]
    Undefined,
}

#[derive(Clone, Default, PartialEq)]
pub enum EventKeyType {
    String,
    #[default]
    Long,
    Retval,
}

#[derive(Clone, Default)]
pub struct EventKey {
    pub arg_index: u8,
    pub arg_type: EventKeyType,
    pub arg_name: String,
}

#[derive(Clone, Default)]
pub struct SystingEvent {
    pub name: String,
    pub cookie: u64,
    pub event: EventProbe,
    pub args: Vec<EventKey>,
    pub(super) scope: EventScope,
    pub stack: bool,
}

impl UProbeEvent {
    pub(super) fn from_parts(parts: Vec<&str>) -> Result<Self, anyhow::Error> {
        // Format is
        // uprobe:<path>:<offset>
        // uprobe:<path>:<symbol>
        // uprobe:<path>:<symbol>+<offset>
        // uretprobe:<path>:<offset>
        // uretprobe:<path>:<symbol>
        // uretprobe:<path>:<symbol>+<offset>
        if parts.len() != 3 {
            return Err(anyhow::anyhow!(
                "Invalid uprobe format: {}",
                parts.join(":")
            ));
        }
        let mut probe = UProbeEvent {
            path: parts[1].to_string(),
            retprobe: parts[0] == "uretprobe",
            ..Default::default()
        };

        match parts[2].parse::<u64>() {
            Ok(val) => {
                probe.offset = val;
            }
            Err(_) => {
                let symbol = parts[2].to_string();
                let mut symbol_parts = symbol.split('+');
                let symbol = symbol_parts.next().unwrap();
                if let Some(offset) = symbol_parts.next() {
                    probe.offset = offset.parse::<u64>()?;
                } else {
                    probe.offset = 0;
                }
                probe.func_name = symbol.to_string();
            }
        }
        Ok(probe)
    }
}

impl fmt::Display for UProbeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = if self.retprobe { "uretprobe" } else { "uprobe" };
        if !self.func_name.is_empty() {
            if self.offset != 0 {
                write!(f, "{}:{}+0x{:x}", name, self.func_name, self.offset,)
            } else {
                write!(f, "{}:{}", name, self.func_name)
            }
        } else if self.offset != 0 {
            write!(f, "{}:0x{:x}", name, self.offset)
        } else {
            write!(f, "{name}")
        }
    }
}

impl KProbeEvent {
    pub(super) fn from_parts(parts: Vec<&str>) -> Result<Self, anyhow::Error> {
        // Format is
        // kprobe:<offset>
        // kprobe:<symbol>
        // kprobe:<symbol>+<offset>
        // kretprobe:<offset>
        // kretprobe:<symbol>
        // kretprobe:<symbol>+<offset>
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid kprobe format: {}",
                parts.join(":")
            ));
        }
        let mut probe = KProbeEvent {
            retprobe: parts[0] == "kretprobe",
            ..Default::default()
        };

        match parts[1].parse::<u64>() {
            Ok(val) => {
                probe.offset = val;
            }
            Err(_) => {
                let symbol = parts[1].to_string();
                let mut symbol_parts = symbol.split('+');
                let symbol = symbol_parts.next().unwrap();
                if let Some(offset) = symbol_parts.next() {
                    probe.offset = offset.parse::<u64>()?;
                } else {
                    probe.offset = 0;
                }
                probe.func_name = symbol.to_string();
            }
        }
        Ok(probe)
    }
}

impl fmt::Display for KProbeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = if self.retprobe { "kretprobe" } else { "kprobe" };
        if !self.func_name.is_empty() {
            if self.offset != 0 {
                write!(f, "{}:{}+0x{:x}", name, self.func_name, self.offset,)
            } else {
                write!(f, "{}:{}", name, self.func_name)
            }
        } else if self.offset != 0 {
            write!(f, "{}:0x{:x}", name, self.offset)
        } else {
            write!(f, "{name}")
        }
    }
}

impl TracepointEvent {
    pub(super) fn from_parts(parts: Vec<&str>) -> Result<Self, anyhow::Error> {
        // Format is
        // tracepoint:<category>:<name>
        if parts.len() != 3 {
            Err(anyhow::anyhow!("Invalid tracepoint format"))?;
        }
        let tracepoint = TracepointEvent {
            category: parts[1].to_string(),
            name: parts[2].to_string(),
        };
        Ok(tracepoint)
    }
}

impl fmt::Display for TracepointEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tracepoint:{}:{}", self.category, self.name)
    }
}

impl fmt::Display for UsdtProbeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "usdt:{}:{}:{}", self.path, self.provider, self.name)
    }
}

impl UsdtProbeEvent {
    pub(super) fn from_parts(parts: Vec<&str>) -> Result<Self, anyhow::Error> {
        // Format is
        // usdt:<path>:<provider>:<name>
        if parts.len() != 4 {
            Err(anyhow::anyhow!("Invalid USDT probe format"))?;
        }
        let usdt = UsdtProbeEvent {
            path: parts[1].to_string(),
            provider: parts[2].to_string(),
            name: parts[3].to_string(),
        };
        Ok(usdt)
    }
}

impl fmt::Display for SystingEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.event {
            EventProbe::UProbe(uprobe) => write!(f, "{uprobe}"),
            EventProbe::Usdt(usdt) => write!(f, "{usdt}"),
            EventProbe::KProbe(kprobe) => write!(f, "{kprobe}"),
            EventProbe::Tracepoint(tracepoint) => write!(f, "{tracepoint}"),
            _ => write!(f, "Invalid event"),
        }
    }
}
