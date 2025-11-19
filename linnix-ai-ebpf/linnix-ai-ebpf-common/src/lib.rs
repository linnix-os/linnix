#![cfg_attr(all(feature = "bpf", not(feature = "user")), no_std)]

#[cfg(test)]
use core::mem::size_of;

use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(
    all(feature = "user", not(target_os = "none")),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,

    pub event_type: u32,
    pub ts_ns: u64,
    pub seq: u64,

    pub comm: [u8; 16],

    pub exit_time_ns: u64,

    pub cpu_pct_milli: u16,
    pub mem_pct_milli: u16,

    /// Primary payload for the event (bytes transferred, address, etc.).
    pub data: u64,
    /// Secondary payload used by richer telemetry (sectors, fault IPs, ...).
    pub data2: u64,
    /// Auxiliary field for op codes or flags.
    pub aux: u32,
    /// Extended auxiliary field for additional flags or identifiers.
    pub aux2: u32,
}

pub const PERCENT_MILLI_UNKNOWN: u16 = u16::MAX;

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum NetOp {
    TcpSend = 0,
    TcpRecv = 1,
    UdpSend = 2,
    UdpRecv = 3,
    UnixStreamSend = 4,
    UnixStreamRecv = 5,
    UnixDgramSend = 6,
    UnixDgramRecv = 7,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum FileOp {
    Read = 0,
    Write = 1,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum BlockOp {
    Queue = 0,
    Issue = 1,
    Complete = 2,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum PageFaultOrigin {
    User = 0,
    Kernel = 1,
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct PageFaultFlags(pub u32);

impl PageFaultFlags {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const PROTECTION: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const USER: u32 = 1 << 2;
    pub const RESERVED: u32 = 1 << 3;
    pub const INSTRUCTION: u32 = 1 << 4;
    pub const SHADOW_STACK: u32 = 1 << 5;

    pub const fn contains(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct TelemetryConfig {
    pub task_real_parent_offset: u32,
    pub task_tgid_offset: u32,
    pub task_signal_offset: u32,
    pub task_mm_offset: u32,
    pub task_se_offset: u32,
    pub se_sum_exec_runtime_offset: u32,
    pub signal_rss_stat_offset: u32,
    pub mm_rss_stat_offset: u32,
    pub rss_count_offset: u32,
    pub rss_item_size: u32,
    pub rss_file_index: u32,
    pub rss_anon_index: u32,
    pub page_size: u32,
    pub _reserved: u32,
    pub total_memory_bytes: u64,
    pub rss_source: u32,
    pub _pad: u32,
}

impl TelemetryConfig {
    pub const fn zeroed() -> Self {
        Self {
            task_real_parent_offset: 0,
            task_tgid_offset: 0,
            task_signal_offset: 0,
            task_mm_offset: 0,
            task_se_offset: 0,
            se_sum_exec_runtime_offset: 0,
            signal_rss_stat_offset: 0,
            mm_rss_stat_offset: 0,
            rss_count_offset: 0,
            rss_item_size: 0,
            rss_file_index: 0,
            rss_anon_index: 0,
            page_size: 0,
            _reserved: 0,
            total_memory_bytes: 0,
            rss_source: 0,
            _pad: 0,
        }
    }
}

pub mod rss_source {
    pub const SIGNAL: u32 = 0;
    pub const MM: u32 = 1;
    pub const DISABLED: u32 = 2;
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct RssTraceEvent {
    pub pid: u32,
    pub member: u32,
    pub delta_pages: i64,
}

#[cfg(feature = "user")]
#[allow(dead_code)]
fn assert_telemetry_config_traits() {
    fn assert_traits<T: Pod + Zeroable>() {}
    assert_traits::<TelemetryConfig>();
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventType {
    Exec = 0,
    Fork = 1,
    Exit = 2,
    Net = 3,
    FileIo = 4,
    Syscall = 5,
    BlockIo = 6,
    PageFault = 7,
}

#[cfg(all(feature = "user", not(target_os = "none")))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProcessEventExt {
    pub base: ProcessEvent,
}

#[cfg(all(feature = "user", not(target_os = "none")))]
impl ProcessEventExt {
    pub fn new(base: ProcessEvent) -> Self {
        Self {
            base,
        }
    }

    pub fn exit_time(&self) -> Option<u64> {
        if self.base.exit_time_ns == 0 {
            None
        } else {
            Some(self.base.exit_time_ns)
        }
    }

    pub fn set_exit_time(&mut self, value: Option<u64>) {
        self.base.exit_time_ns = value.unwrap_or(0);
    }

    pub fn cpu_percent(&self) -> Option<f32> {
        if self.base.cpu_pct_milli == PERCENT_MILLI_UNKNOWN {
            None
        } else {
            Some(self.base.cpu_pct_milli as f32 / 1000.0)
        }
    }

    pub fn set_cpu_percent(&mut self, value: Option<f32>) {
        self.base.cpu_pct_milli = match value {
            Some(v) => {
                let scaled = (v * 1000.0).round();
                if scaled.is_finite() {
                    scaled.clamp(0.0, PERCENT_MILLI_UNKNOWN as f32 - 1.0) as u16
                } else {
                    PERCENT_MILLI_UNKNOWN
                }
            }
            None => PERCENT_MILLI_UNKNOWN,
        };
    }

    pub fn mem_percent(&self) -> Option<f32> {
        if self.base.mem_pct_milli == PERCENT_MILLI_UNKNOWN {
            None
        } else {
            Some(self.base.mem_pct_milli as f32 / 1000.0)
        }
    }

    pub fn set_mem_percent(&mut self, value: Option<f32>) {
        self.base.mem_pct_milli = match value {
            Some(v) => {
                let scaled = (v * 1000.0).round();
                if scaled.is_finite() {
                    scaled.clamp(0.0, PERCENT_MILLI_UNKNOWN as f32 - 1.0) as u16
                } else {
                    PERCENT_MILLI_UNKNOWN
                }
            }
            None => PERCENT_MILLI_UNKNOWN,
        };
    }
}

#[cfg(all(feature = "user", not(target_os = "none")))]
impl core::ops::Deref for ProcessEventExt {
    type Target = ProcessEvent;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

#[cfg(all(feature = "user", not(target_os = "none")))]
impl core::ops::DerefMut for ProcessEventExt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

#[repr(C)]
#[cfg_attr(not(feature = "user"), derive(Copy))]
#[derive(Clone, Debug)]
#[cfg_attr(
    all(feature = "user", not(target_os = "none")),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct NetEvent {
    pub pid: u32,
    pub bytes: u64,
}

#[repr(C)]
#[cfg_attr(not(feature = "user"), derive(Copy))]
#[derive(Clone, Debug)]
#[cfg_attr(
    all(feature = "user", not(target_os = "none")),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct FileIoEvent {
    pub pid: u32,
    pub bytes: u64,
}

#[repr(C)]
#[cfg_attr(not(feature = "user"), derive(Copy))]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockIoEvent {
    pub pid: u32,
    pub bytes: u64,
    pub sector: u64,
    pub device: u32,
    pub op: BlockOp,
}

#[repr(C)]
#[cfg_attr(not(feature = "user"), derive(Copy))]
#[derive(Clone, Debug)]
#[cfg_attr(
    all(feature = "user", not(target_os = "none")),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct SyscallEvent {
    pub pid: u32,
    pub syscall: u32,
}

#[repr(C)]
#[cfg_attr(not(feature = "user"), derive(Copy))]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct PageFaultEvent {
    pub pid: u32,
    pub address: u64,
    pub ip: u64,
    pub flags: PageFaultFlags,
    pub origin: PageFaultOrigin,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_aligned() {
        assert_eq!(
            size_of::<ProcessEvent>() % 8,
            0,
            "wire format should be 8-byte aligned"
        );
    }

    #[test]
    fn page_fault_flags_helpers() {
        let flags = PageFaultFlags::new(PageFaultFlags::WRITE | PageFaultFlags::PROTECTION);
        assert!(flags.contains(PageFaultFlags::WRITE));
        assert!(flags.contains(PageFaultFlags::PROTECTION));
        assert!(!flags.contains(PageFaultFlags::INSTRUCTION));
    }

    #[cfg(feature = "user")]
    #[test]
    fn block_io_event_roundtrip() {
        let event = BlockIoEvent {
            pid: 42,
            bytes: 4096,
            sector: 1234,
            device: 0x1f203,
            op: BlockOp::Complete,
        };

        let json = serde_json::to_string(&event).expect("serialize block event");
        let roundtrip: BlockIoEvent = serde_json::from_str(&json).expect("deserialize block event");
        assert_eq!(roundtrip.pid, event.pid);
        assert_eq!(roundtrip.bytes, event.bytes);
        assert_eq!(roundtrip.sector, event.sector);
        assert_eq!(roundtrip.device, event.device);
        assert_eq!(roundtrip.op as u32, event.op as u32);
    }
}
