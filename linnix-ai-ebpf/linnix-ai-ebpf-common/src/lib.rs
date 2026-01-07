#![cfg_attr(all(feature = "bpf", not(feature = "user")), no_std)]

#[cfg(test)]
use core::mem::size_of;

use bytemuck::{Pod, Zeroable};

// =============================================================================
// SEQUENCED MPSC RING BUFFER - Shared Protocol Definitions
// =============================================================================
//
// This defines the memory layout for a lock-free, strictly-ordered ring buffer
// that bypasses the kernel's standard ring buffer for better scalability.
//
// ARCHITECTURE:
//   - Multiple kernel producers (eBPF programs on different CPUs)
//   - Single userspace consumer (cognitod)
//   - Strict ordering via atomic ticket counter
//   - Cache-line aligned slots to prevent false sharing
//
// MEMORY LAYOUT (256 bytes per slot, 64-byte aligned):
//   [0..8]   flags: u64        - Slot state (EMPTY/WRITING/READY/ABANDONED)
//   [8..16]  reserved_at_ns    - Timestamp when slot was reserved
//   [16..24] ticket_id: u64    - Sequence number for ordering validation
//   [24..120] event: ProcessEvent (96 bytes)
//   [120..256] _padding        - Cache line alignment padding
// =============================================================================

/// Ring buffer size: 1 million slots (256MB total RAM)
/// Must be a power of 2 for efficient masking.
pub const SEQUENCER_RING_SIZE: u32 = 1024 * 1024;

/// Bit mask for wrapping index (RING_SIZE - 1)
pub const SEQUENCER_RING_MASK: u32 = SEQUENCER_RING_SIZE - 1;

/// Slot state flags (u8 to save space in compacted slot)
pub mod slot_flags {
    /// Slot is empty and available for reservation
    pub const EMPTY: u8 = 0;
    /// Producer has reserved this slot and is writing data
    pub const WRITING: u8 = 1;
    /// Data is complete and ready for consumer
    pub const READY: u8 = 2;
    /// Slot was abandoned (producer crashed/stalled), skipped by reaper
    pub const ABANDONED: u8 = 3;
}

/// A cache-line aligned slot in the sequencer ring buffer.
///
/// CRITICAL: This struct is 256 bytes to:
/// 1. Prevent false sharing between CPUs accessing adjacent slots
/// 2. Align to cache line boundaries (64 bytes on modern x86/ARM)
/// 3. Allow efficient memory-mapped access from userspace
///
/// COMPACTED SLOT: 128 bytes (2 cache lines) for maximum write bandwidth.
///
/// Layout (128 bytes total):
///   [0]      flags: u8         - Slot state
///   [1..8]   _pad1: [u8; 7]    - Alignment padding
///   [8..16]  ticket_id: u64    - Sequence number
///   [16..24] reserved_at_ns: u64 - Timestamp for reaper
///   [24..120] event: ProcessEvent (96 bytes)
///   [120..128] _pad2: [u8; 8]  - Final padding to 128
///
/// The slot uses a simple state machine:
///   EMPTY -> WRITING (atomic ticket reservation)
///   WRITING -> READY (data commit)
///   WRITING -> ABANDONED (producer crashed, reaper intervened)
///   READY -> EMPTY (consumer processed)
///   ABANDONED -> EMPTY (consumer skipped)
#[repr(C, align(128))]
#[derive(Copy, Clone)]
pub struct SequencedSlot {
    /// Slot state flag (see `slot_flags` module) - u8 to save space
    pub flags: u8,

    /// Alignment padding to 8-byte boundary
    pub _pad1: [u8; 7],

    /// The ticket/sequence number assigned during atomic reservation.
    /// This enables strict ordering validation in userspace.
    pub ticket_id: u64,

    /// Timestamp (ktime_get_ns) when this slot was reserved.
    /// Used by the "Reaper" to detect stalled producers.
    pub reserved_at_ns: u64,

    /// The actual event payload (96 bytes)
    pub event: ProcessEvent,

    /// Final padding to reach exactly 128 bytes.
    /// Header: 1 + 7 + 8 + 8 = 24 bytes
    /// ProcessEvent: 96 bytes
    /// Total: 24 + 96 = 120 bytes, need 8 more
    pub _pad2: [u8; 8],
}

// Ensure SequencedSlot is exactly 128 bytes (2 cache lines)
#[cfg(test)]
const _: () = {
    assert!(size_of::<SequencedSlot>() == 128);
};

impl SequencedSlot {
    /// Create an empty zeroed slot
    pub const fn zeroed() -> Self {
        Self {
            flags: slot_flags::EMPTY,
            _pad1: [0; 7],
            ticket_id: 0,
            reserved_at_ns: 0,
            event: ProcessEvent {
                pid: 0,
                ppid: 0,
                uid: 0,
                gid: 0,
                event_type: 0,
                ts_ns: 0,
                seq: 0,
                comm: [0; 16],
                exit_time_ns: 0,
                cpu_pct_milli: 0,
                mem_pct_milli: 0,
                data: 0,
                data2: 0,
                aux: 0,
                aux2: 0,
            },
            _pad2: [0; 8],
        }
    }
}

/// Default timeout for the Reaper (10ms in nanoseconds).
/// If a slot remains in WRITING state longer than this, it's considered stalled.
pub const REAPER_TIMEOUT_NS: u64 = 10_000_000;

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
    // Task struct field offsets (discovered via BTF at runtime)
    pub task_real_parent_offset: u32,
    pub task_tgid_offset: u32,
    pub task_signal_offset: u32,
    pub task_mm_offset: u32,
    pub task_se_offset: u32,
    pub se_sum_exec_runtime_offset: u32,

    // NEW: Offsets for BTF raw tracepoint support (CO-RE portability)
    /// Offset of `pid` field in task_struct (thread ID)
    pub task_pid_offset: u32,
    /// Offset of `comm` field in task_struct (16-byte process name)
    pub task_comm_offset: u32,

    // RSS stat offsets
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
            task_pid_offset: 0,
            task_comm_offset: 0,
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
    Cuda = 8, // CUDA API calls via uprobe
}

/// CUDA operation type for GPU tracing via uprobes
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum CudaOp {
    /// cudaMalloc - GPU memory allocation
    Malloc = 0,
    /// cudaFree - GPU memory deallocation
    Free = 1,
    /// cudaLaunchKernel - Kernel execution start
    LaunchKernel = 2,
    /// cudaMemcpy host-to-device
    MemcpyHtoD = 3,
    /// cudaMemcpy device-to-host
    MemcpyDtoH = 4,
    /// cudaMemcpy device-to-device  
    MemcpyDtoD = 5,
}

impl CudaOp {
    /// Convert from cudaMemcpyKind enum value
    pub fn from_memcpy_kind(kind: u32) -> Self {
        match kind {
            1 => CudaOp::MemcpyHtoD,
            2 => CudaOp::MemcpyDtoH,
            3 => CudaOp::MemcpyDtoD,
            _ => CudaOp::MemcpyHtoD, // Default to HtoD
        }
    }
}

#[cfg(all(feature = "user", not(target_os = "none")))]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProcessEventExt {
    pub base: ProcessEvent,
}

#[cfg(all(feature = "user", not(target_os = "none")))]
impl ProcessEventExt {
    pub fn new(base: ProcessEvent) -> Self {
        Self { base }
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
    fn sequenced_slot_layout() {
        // Slot must be exactly 128 bytes (2 cache lines)
        assert_eq!(
            size_of::<SequencedSlot>(),
            128,
            "SequencedSlot must be exactly 128 bytes"
        );

        // Must be aligned to 128 bytes (as declared with #[repr(C, align(128))])
        assert_eq!(
            std::mem::align_of::<SequencedSlot>(),
            128,
            "SequencedSlot must be 128-byte aligned"
        );

        // Ring size must be a power of 2
        assert!(
            SEQUENCER_RING_SIZE.is_power_of_two(),
            "SEQUENCER_RING_SIZE must be power of 2"
        );

        // Mask must be size - 1
        assert_eq!(
            SEQUENCER_RING_MASK,
            SEQUENCER_RING_SIZE - 1,
            "SEQUENCER_RING_MASK must equal RING_SIZE - 1"
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
