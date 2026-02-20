use anyhow::Result;

use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::{vfio_device_meta, vfio_event, SystingRecordEvent};
use crate::trace::{VfioDeviceRecord, VfioEventRecord};

/// VFIO IOCTL command numbers from <uapi/linux/vfio.h>.
const VFIO_CMD_DEVICE_GET_INFO: u32 = 0x3b6b;
const VFIO_CMD_DEVICE_GET_REGION_INFO: u32 = 0x3b6c;
const VFIO_CMD_DEVICE_GET_IRQ_INFO: u32 = 0x3b6d;
const VFIO_CMD_DEVICE_SET_IRQS: u32 = 0x3b6e;
const VFIO_CMD_DEVICE_RESET: u32 = 0x3b6f;
const VFIO_CMD_DEVICE_IOEVENTFD: u32 = 0x3b74;
/// Pseudo-commands for DMA operations (not real VFIO ioctls).
const VFIO_PSEUDO_MAP_DMA: u32 = 0x80000001;
const VFIO_PSEUDO_UNMAP_DMA: u32 = 0x80000002;

pub fn vfio_command_name(cmd: u32) -> &'static str {
    match cmd {
        VFIO_CMD_DEVICE_GET_INFO => "GET_INFO",
        VFIO_CMD_DEVICE_GET_REGION_INFO => "GET_REGION_INFO",
        VFIO_CMD_DEVICE_GET_IRQ_INFO => "GET_IRQ_INFO",
        VFIO_CMD_DEVICE_SET_IRQS => "SET_IRQS",
        VFIO_CMD_DEVICE_RESET => "RESET",
        VFIO_CMD_DEVICE_IOEVENTFD => "IOEVENTFD",
        VFIO_PSEUDO_MAP_DMA => "MAP_DMA",
        VFIO_PSEUDO_UNMAP_DMA => "UNMAP_DMA",
        _ => "UNKNOWN",
    }
}

#[derive(Default)]
pub struct VfioRecorder {
    ringbuf: RingBuffer<vfio_event>,
    events: Vec<vfio_event>,
    devices: Vec<VfioDeviceRecord>,
}

impl SystingRecordEvent<vfio_event> for VfioRecorder {
    fn ringbuf(&self) -> &RingBuffer<vfio_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<vfio_event> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: vfio_event) {
        self.events.push(event);
    }
}

impl VfioRecorder {
    pub fn has_data(&self) -> bool {
        !self.events.is_empty()
    }

    pub fn min_timestamp(&self) -> Option<u64> {
        self.events.iter().map(|e| e.start_ts).min()
    }

    /// Load VFIO device metadata from the BPF map into internal storage.
    /// Must be called while the BPF skeleton is still alive.
    pub fn load_device_metadata<M: libbpf_rs::MapCore>(&mut self, map: &M) {
        for key in map.keys() {
            if let Ok(Some(value)) = map.lookup(&key, libbpf_rs::MapFlags::ANY) {
                let mut meta = vfio_device_meta::default();
                if plain::copy_from_bytes(&mut meta, &value).is_ok() && key.len() >= 4 {
                    let mut device_id_bytes = [0u8; 4];
                    device_id_bytes.copy_from_slice(&key[..4]);
                    let device_id = u32::from_ne_bytes(device_id_bytes);

                    let dev = (meta.devfn >> 3) as i32;
                    let func = (meta.devfn & 0x7) as i32;
                    let bdf = format!(
                        "{:04x}:{:02x}:{:02x}.{:x}",
                        meta.domain, meta.bus, dev, func
                    );

                    self.devices.push(VfioDeviceRecord {
                        device_id: device_id as i32,
                        domain: meta.domain as i32,
                        bus: meta.bus as i32,
                        dev,
                        func,
                        vendor_id: meta.vendor_id as i32,
                        device_id_pci: meta.device_id_pci as i32,
                        subsystem_vendor: meta.subsystem_vendor as i32,
                        subsystem_device: meta.subsystem_device as i32,
                        bdf,
                    });
                }
            }
        }
    }

    /// Write all collected VFIO device metadata and events to the collector.
    pub fn write_records(&self, collector: &mut dyn RecordCollector) -> Result<()> {
        // Write device metadata
        for device in &self.devices {
            collector.add_vfio_device(device.clone())?;
        }

        // Write events
        for event in &self.events {
            let tgidpid = event.task.tgidpid;
            let pid = (tgidpid >> 32) as i64;
            let tid = (tgidpid & 0xFFFFFFFF) as i64;
            let dur = if event.end_ts > event.start_ts {
                (event.end_ts - event.start_ts) as i64
            } else {
                0
            };

            collector.add_vfio_event(VfioEventRecord {
                device_id: event.device_id as i32,
                ts: event.start_ts as i64,
                dur,
                pid,
                tid,
                command: event.command as i32,
                command_name: vfio_command_name(event.command).to_string(),
                arg1: event.arg1 as i64,
                arg2: event.arg2 as i64,
                arg3: event.arg3 as i64,
                ret: event.ret,
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(command: u32, device_id: u32, start: u64, end: u64) -> vfio_event {
        let mut event = vfio_event::default();
        event.task.tgidpid = (1234u64 << 32) | 1234;
        event.start_ts = start;
        event.end_ts = end;
        event.command = command;
        event.device_id = device_id;
        event
    }

    #[test]
    fn test_command_names() {
        assert_eq!(vfio_command_name(0x3b6b), "GET_INFO");
        assert_eq!(vfio_command_name(0x3b6f), "RESET");
        assert_eq!(vfio_command_name(0x80000001), "MAP_DMA");
        assert_eq!(vfio_command_name(0x80000002), "UNMAP_DMA");
        assert_eq!(vfio_command_name(0x12345678), "UNKNOWN");
    }

    #[test]
    fn test_handle_event() {
        let mut recorder = VfioRecorder::default();
        recorder.handle_event(make_event(0x3b6b, 1, 1000, 2000));
        recorder.handle_event(make_event(0x3b6f, 1, 3000, 4000));

        assert!(recorder.has_data());
        assert_eq!(recorder.events.len(), 2);
        assert_eq!(recorder.min_timestamp(), Some(1000));
    }

    #[test]
    fn test_write_records() {
        let mut recorder = VfioRecorder::default();
        recorder.handle_event(make_event(0x3b6b, 1, 1000, 2000));

        let mut collector = crate::record::collector::InMemoryCollector::new();
        recorder.write_records(&mut collector).unwrap();

        let data = collector.into_data();
        assert_eq!(data.vfio_events.len(), 1);
        assert_eq!(data.vfio_events[0].command_name, "GET_INFO");
        assert_eq!(data.vfio_events[0].dur, 1000);
        assert_eq!(data.vfio_events[0].device_id, 1);
    }

    #[test]
    fn test_empty_recorder() {
        let recorder = VfioRecorder::default();
        assert!(!recorder.has_data());
        assert_eq!(recorder.min_timestamp(), None);
    }
}
