use core::cmp;

use aya_ebpf::{
    helpers::{
        bpf_get_current_task_btf, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read,
    },
    macros::{btf_tracepoint, kprobe, map, tracepoint},
    maps::{perf::PerfEventArray, Array, HashMap, PerCpuArray},
    programs::{BtfTracePointContext, ProbeContext, TracePointContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use linnix_ai_ebpf_common::{
    rss_source, slot_flags, BlockOp, EventType, PageFaultOrigin, ProcessEvent, SequencedSlot,
    TelemetryConfig, PERCENT_MILLI_UNKNOWN, SEQUENCER_RING_MASK, SEQUENCER_RING_SIZE,
};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[map(name = "TASK_STATS")]
static mut TASK_STATS: HashMap<u32, TaskStats> = HashMap::with_max_entries(65_536, 0);

#[map(name = "EVENT_BUFFER")]
static mut EVENT_BUFFER: PerCpuArray<ProcessEvent> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "PAGE_FAULT_THROTTLE")]
static mut PAGE_FAULT_THROTTLE: HashMap<u32, u64> = HashMap::with_max_entries(65_536, 0);

// =============================================================================
// SEQUENCED MPSC RING BUFFER - Kernel Producer Maps
// =============================================================================
//
// Map 1: The raw memory ring (128MB when SEQUENCER_RING_SIZE = 1M slots @ 128 bytes)
// This is a BPF_MAP_TYPE_ARRAY with BPF_F_MMAPABLE flag for zero-copy userspace access.
// We implement our own lock-free protocol on top of the raw memory.
//
// NOTE: You may need to increase `ulimit -l` on the host for this map to load.
// The pod/process needs CAP_IPC_LOCK for the memory locking.

/// BPF_F_MMAPABLE flag (0x400 = 1024) - enables mmap() from userspace
/// This eliminates syscall overhead for reading, allowing zero-copy access.
const BPF_F_MMAPABLE: u32 = 1024;

#[map(name = "SEQUENCER_RING")]
static mut SEQUENCER_RING: Array<SequencedSlot> =
    Array::with_max_entries(SEQUENCER_RING_SIZE, BPF_F_MMAPABLE);

// =============================================================================
// ISOLATED HOT SEQUENCER - Cache-Line Aligned Global Counter
// =============================================================================
//
// OPTIMIZATION: We moved the sequencer counter from a BPF Map to a .bss global.
// This eliminates:
//   1. bpf_map_lookup_elem helper call overhead
//   2. TLB misses from separate map memory allocation
//   3. False sharing with BPF map metadata
//
// The counter is aligned to 64 bytes (cache line) to prevent false sharing.
// When Core 1 updates the counter, it won't invalidate Core 2's unrelated data.

/// Cache-line aligned sequencer counter (raw u64, not AtomicU64)
/// In BPF, we use intrinsics for atomic operations, not std::sync::atomic.
#[repr(C, align(64))]
struct AlignedSequencer {
    /// The ticket counter value - accessed via atomic intrinsics
    value: u64,
    /// Padding to fill the cache line (64 - 8 = 56 bytes)
    _padding: [u8; 56],
}

/// Global sequencer counter - lives in .bss, initialized to 0 on program load.
/// This compiles to a direct memory address, not a map lookup.
#[no_mangle]
static mut GLOBAL_SEQUENCER: AlignedSequencer = AlignedSequencer {
    value: 0,
    _padding: [0; 56],
};

// Map 2: Feature flag to enable sequencer (single u32 element)
// Set element 0 to 1 from userspace to switch from perf buffer to sequencer.
#[map(name = "SEQUENCER_ENABLED")]
static mut SEQUENCER_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

#[no_mangle]
static mut TELEMETRY_CONFIG: TelemetryConfig = TelemetryConfig::zeroed();

const BYTES_PER_SECTOR: u64 = 512;
const PAGE_FAULT_MIN_INTERVAL_NS: u64 = 50_000_000; // 50 ms window per PID

const BLOCK_BIO_DEV_OFFSET: usize = 0;
const BLOCK_BIO_SECTOR_OFFSET: usize = 8;
const BLOCK_BIO_NR_SECTOR_OFFSET: usize = 16;

const BLOCK_RQ_DEV_OFFSET: usize = 0;
const BLOCK_RQ_SECTOR_OFFSET: usize = 8;
const BLOCK_RQ_NR_SECTOR_OFFSET: usize = 16;
const BLOCK_RQ_ISSUE_BYTES_OFFSET: usize = 20;
const DEVICE_MAJOR_BITS: u32 = 12;
const DEVICE_MINOR_BITS: u32 = 20;
const DEVICE_MAJOR_MASK: u64 = (1u64 << DEVICE_MAJOR_BITS) - 1;
const DEVICE_MINOR_MASK: u64 = (1u64 << DEVICE_MINOR_BITS) - 1;

// =============================================================================
// TASK_STRUCT ACCESS FOR BTF RAW TRACEPOINTS (CO-RE PORTABLE)
// =============================================================================
//
// For BTF raw tracepoints, we receive task_struct pointers as arguments.
// Instead of hardcoding offsets (which vary by kernel), we read them from
// TELEMETRY_CONFIG, which is populated by userspace using BTF discovery.
//
// This is the "Runtime Offset Discovery" approach (Option 3):
// - Userspace parses /sys/kernel/btf/vmlinux at startup
// - Offsets are written to TELEMETRY_CONFIG global
// - eBPF reads offsets from L1-cached .bss memory
//
// Performance impact: ~1 extra memory load per field (L1 cache hit, negligible)
// Benefit: Works on any kernel with BTF support, no recompilation needed.

/// Opaque task_struct - we use bpf_probe_read with dynamic offsets
#[repr(C)]
struct TaskStruct {
    _opaque: [u8; 0],
}

/// Read tgid (process ID) from task_struct using dynamic offset from config
#[inline(always)]
unsafe fn read_task_pid(task: *const TaskStruct) -> u32 {
    let cfg = load_config();
    let tgid_ptr = (task as *const u8).add(cfg.task_tgid_offset as usize) as *const i32;
    bpf_probe_read(tgid_ptr).unwrap_or(0) as u32
}

/// Read comm field from task_struct using dynamic offset from config
#[inline(always)]
unsafe fn read_task_comm(task: *const TaskStruct) -> [u8; 16] {
    let cfg = load_config();
    let comm_ptr = (task as *const u8).add(cfg.task_comm_offset as usize) as *const [u8; 16];
    bpf_probe_read(comm_ptr).unwrap_or([0u8; 16])
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TaskStats {
    last_runtime_ns: u64,
    last_timestamp_ns: u64,
}

#[inline(always)]
fn encode_block_dev(dev: u64) -> u32 {
    let major = (dev >> DEVICE_MINOR_BITS) & DEVICE_MAJOR_MASK;
    let minor = dev & DEVICE_MINOR_MASK;
    ((major as u32) << DEVICE_MINOR_BITS) | (minor as u32)
}

#[inline(always)]
fn block_bytes_from_sectors(sectors: u32) -> u64 {
    (sectors as u64) * BYTES_PER_SECTOR
}

#[inline(always)]
fn throttle_page_fault(pid: u32, now: u64) -> bool {
    let state = unsafe { &PAGE_FAULT_THROTTLE };
    if let Some(ptr) = state.get_ptr_mut(&pid) {
        let last = unsafe { &mut *ptr };
        if now.saturating_sub(*last) < PAGE_FAULT_MIN_INTERVAL_NS {
            return false;
        }
        *last = now;
        true
    } else {
        let _ = state.insert(&pid, &now, 0);
        true
    }
}

fn tp_read_u64(ctx: &TracePointContext, offset: usize) -> Option<u64> {
    unsafe { ctx.read_at::<u64>(offset).ok() }
}

fn tp_read_u32(ctx: &TracePointContext, offset: usize) -> Option<u32> {
    unsafe { ctx.read_at::<u32>(offset).ok() }
}

fn emit_block_event_common(
    ctx: &TracePointContext,
    now: u64,
    op: BlockOp,
    dev: u64,
    sector: u64,
    sectors: u32,
    bytes_override: Option<u32>,
) -> u32 {
    if sectors == 0 {
        return 0;
    }

    let bytes = match bytes_override {
        Some(value) if value > 0 => value as u64,
        _ => block_bytes_from_sectors(sectors),
    };

    emit_activity_event(
        ctx,
        EventType::BlockIo,
        now,
        bytes,
        sector,
        op as u32,
        encode_block_dev(dev),
    )
}

fn load_config() -> TelemetryConfig {
    unsafe { core::ptr::read_volatile(&TELEMETRY_CONFIG) }
}

fn read_field<T: Copy>(base: *const u8, offset: u32) -> Option<T> {
    if base.is_null() {
        return None;
    }
    let ptr = unsafe { base.add(offset as usize) as *const T };
    unsafe { bpf_probe_read(ptr).ok() }
}

fn read_ptr(base: *const u8, offset: u32) -> Option<*const u8> {
    let addr: usize = read_field(base, offset)?;
    if addr == 0 {
        None
    } else {
        Some(addr as *const u8)
    }
}

fn parent_tgid(task: *const u8, config: &TelemetryConfig) -> Option<u32> {
    if config.task_real_parent_offset == 0 || config.task_tgid_offset == 0 {
        return None;
    }
    let parent = read_ptr(task, config.task_real_parent_offset)?;
    let parent_tgid: i32 = read_field(parent, config.task_tgid_offset)?;
    if parent_tgid > 0 {
        Some(parent_tgid as u32)
    } else {
        None
    }
}

#[cfg(target_arch = "bpf")]
fn read_sum_exec_runtime(task: *const u8, config: &TelemetryConfig) -> Option<u64> {
    if config.task_se_offset == 0 || config.se_sum_exec_runtime_offset == 0 {
        return None;
    }
    let offset = config
        .task_se_offset
        .checked_add(config.se_sum_exec_runtime_offset)?;
    read_field(task, offset)
}

fn read_rss_count(base: *const u8, config: &TelemetryConfig, index: u32) -> Option<u64> {
    if config.rss_item_size == 0 {
        return None;
    }
    let offset = (config.rss_item_size as u64)
        .checked_mul(index as u64)?
        .checked_add(config.rss_count_offset as u64)?;
    if offset > u32::MAX as u64 {
        return None;
    }
    let raw: i64 = read_field(base, offset as u32)?;
    if raw >= 0 {
        Some(raw as u64)
    } else {
        None
    }
}

fn rss_bytes(task: *const u8, config: &TelemetryConfig) -> Option<u64> {
    match config.rss_source {
        x if x == rss_source::SIGNAL => rss_bytes_signal(task, config),
        x if x == rss_source::MM => rss_bytes_mm(task, config),
        _ => None,
    }
}

fn rss_bytes_signal(task: *const u8, config: &TelemetryConfig) -> Option<u64> {
    if config.task_signal_offset == 0
        || config.signal_rss_stat_offset == 0
        || config.rss_item_size == 0
    {
        return None;
    }
    let signal = read_ptr(task, config.task_signal_offset)?;
    if signal.is_null() {
        return None;
    }
    rss_bytes_from_base(signal, config.signal_rss_stat_offset, config)
}

fn rss_bytes_mm(task: *const u8, config: &TelemetryConfig) -> Option<u64> {
    if config.task_mm_offset == 0 || config.mm_rss_stat_offset == 0 || config.rss_item_size == 0 {
        return None;
    }
    let mm = read_ptr(task, config.task_mm_offset)?;
    if mm.is_null() {
        return None;
    }
    rss_bytes_from_base(mm, config.mm_rss_stat_offset, config)
}

fn rss_bytes_from_base(
    base_ptr: *const u8,
    rss_offset: u32,
    config: &TelemetryConfig,
) -> Option<u64> {
    let rss_base = unsafe { base_ptr.add(rss_offset as usize) };
    let file = read_rss_count(rss_base, config, config.rss_file_index)?;
    let anon = read_rss_count(rss_base, config, config.rss_anon_index)?;
    let pages = file.saturating_add(anon);
    let page_size = config.page_size as u64;
    if page_size == 0 {
        return None;
    }
    let max_pages = u64::MAX / page_size;
    let capped_pages = core::cmp::min(pages, max_pages);
    Some(capped_pages * page_size)
}

fn sample_cpu(pid: u32, task: *const u8, now: u64, config: &TelemetryConfig) -> u16 {
    let runtime = match read_sum_exec_runtime(task, config) {
        Some(val) => val,
        None => return PERCENT_MILLI_UNKNOWN,
    };
    let stats = unsafe { &TASK_STATS };
    if let Some(ptr) = stats.get_ptr_mut(&pid) {
        let entry = unsafe { &mut *ptr };
        let mut value = PERCENT_MILLI_UNKNOWN as u64;
        let mut has_value = false;
        if entry.last_timestamp_ns != 0
            && now > entry.last_timestamp_ns
            && runtime >= entry.last_runtime_ns
        {
            let delta_time = now - entry.last_timestamp_ns;
            if delta_time > 0 {
                let delta_runtime = runtime - entry.last_runtime_ns;
                let scaled_mul = if delta_runtime > u64::MAX / 100_000 {
                    u64::MAX
                } else {
                    delta_runtime * 100_000
                };
                let scaled = scaled_mul / delta_time;
                value = scaled;
                has_value = true;
            }
        }
        entry.last_runtime_ns = runtime;
        entry.last_timestamp_ns = now;
        if has_value {
            value.min((PERCENT_MILLI_UNKNOWN - 1) as u64) as u16
        } else {
            PERCENT_MILLI_UNKNOWN
        }
    } else {
        let entry = TaskStats {
            last_runtime_ns: runtime,
            last_timestamp_ns: now,
        };
        let _ = stats.insert(&pid, &entry, 0);
        PERCENT_MILLI_UNKNOWN
    }
}

fn sample_mem(task: *const u8, config: &TelemetryConfig) -> u16 {
    if config.total_memory_bytes == 0 || config.page_size == 0 {
        return PERCENT_MILLI_UNKNOWN;
    }
    let bytes = match rss_bytes(task, config) {
        Some(b) => b,
        None => return PERCENT_MILLI_UNKNOWN,
    };
    let scaled_mul = if bytes > u64::MAX / 100_000 {
        u64::MAX
    } else {
        bytes * 100_000
    };
    let scaled = scaled_mul / config.total_memory_bytes;
    scaled.min((PERCENT_MILLI_UNKNOWN - 1) as u64) as u16
}

fn event_buffer_mut() -> Option<&'static mut ProcessEvent> {
    unsafe { EVENT_BUFFER.get_ptr_mut(0).map(|ptr| &mut *ptr) }
}

fn init_event<C: EbpfContext>(
    ctx: &C,
    event_type: EventType,
    now: u64,
    pid: u32,
    event: &mut ProcessEvent,
) {
    let ids = bpf_get_current_uid_gid();
    let uid = ids as u32;
    let gid = (ids >> 32) as u32;

    event.pid = pid;
    event.uid = uid;
    event.gid = gid;
    event.event_type = event_type as u32;
    event.ts_ns = now;
    event.seq = 0;
    event.exit_time_ns = 0;
    event.data = 0;
    event.data2 = 0;
    event.aux = 0;
    event.aux2 = 0;

    let mut comm = [0u8; 16];
    if let Ok(name) = ctx.command() {
        let len = cmp::min(name.len(), comm.len());
        comm[..len].copy_from_slice(&name[..len]);
    }
    event.comm = comm;

    let config = load_config();
    let task = unsafe { bpf_get_current_task_btf() } as *const u8;

    if !task.is_null() {
        event.ppid = parent_tgid(task, &config).unwrap_or(0);
        event.cpu_pct_milli = sample_cpu(pid, task, now, &config);
        event.mem_pct_milli = sample_mem(task, &config);
    } else {
        event.ppid = 0;
        event.cpu_pct_milli = PERCENT_MILLI_UNKNOWN;
        event.mem_pct_milli = PERCENT_MILLI_UNKNOWN;
    }
}

fn submit_event<C: EbpfContext>(ctx: &C, event: &ProcessEvent) {
    // Check if sequencer is enabled (read from map)
    let sequencer_enabled = unsafe {
        match SEQUENCER_ENABLED.get(0) {
            Some(val) => *val,
            None => 0,
        }
    };

    if sequencer_enabled != 0 {
        // Use the new lock-free sequencer
        let _ = submit_to_sequencer(event);
    } else {
        // Fall back to legacy perf buffer
        let events = unsafe { &mut EVENTS };
        events.output(ctx, event, 0);
    }
}

/// Zero-stack event submission for hot paths (fork, exec, exit).
///
/// This bypasses stack allocation entirely by writing directly to the ring buffer.
/// Only used when sequencer is enabled. Falls back to perf buffer otherwise.
#[inline(always)]
fn submit_event_direct<C: EbpfContext>(
    ctx: &C,
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    event_type: u32,
    ts_ns: u64,
    comm: &[u8; 16],
    cpu_pct_milli: u16,
    mem_pct_milli: u16,
    data: u64,
    data2: u64,
    aux: u32,
    aux2: u32,
) {
    // Check if sequencer is enabled
    let sequencer_enabled = unsafe {
        match SEQUENCER_ENABLED.get(0) {
            Some(val) => *val,
            None => 0,
        }
    };

    if sequencer_enabled != 0 {
        // ZERO-STACK PATH: Direct write to ring buffer
        let _ = submit_to_sequencer_direct(
            pid,
            ppid,
            uid,
            gid,
            event_type,
            ts_ns,
            comm,
            cpu_pct_milli,
            mem_pct_milli,
            data,
            data2,
            aux,
            aux2,
        );
    } else {
        // LEGACY PATH: Build event on stack for perf buffer
        // (perf buffer requires a contiguous struct)
        let event = ProcessEvent {
            pid,
            ppid,
            uid,
            gid,
            event_type,
            ts_ns,
            seq: 0,
            comm: *comm,
            exit_time_ns: 0,
            cpu_pct_milli,
            mem_pct_milli,
            data,
            data2,
            aux,
            aux2,
        };
        let events = unsafe { &mut EVENTS };
        events.output(ctx, &event, 0);
    }
}

// =============================================================================
// SEQUENCED MPSC RING BUFFER - Kernel Producer Implementation
// =============================================================================
//
// This implements a lock-free, strictly-ordered producer for the MPSC ring buffer.
// Each CPU atomically reserves a ticket, writes data, then commits.
//
// The protocol:
// 1. ATOMIC RESERVATION: fetch_add on SEQUENCER_INDEX to get unique ticket
// 2. CALCULATE SLOT: ticket & RING_MASK gives the slot index
// 3. OPTIMISTIC LOCK: Set flags = WRITING, record reservation timestamp
// 4. COPY DATA: Write event payload to slot
// 5. COMMIT: Set flags = READY
//
// If a producer crashes between steps 3-5, the userspace "Reaper" will
// detect the stall (via reserved_at_ns) and mark the slot ABANDONED.

/// Atomic fetch-and-add for ticket reservation.
/// Uses volatile operations which LLVM translates to BPF_ATOMIC operations.
///
/// NOTE: For BPF we can't use `core::sync::atomic` as it's not available.
/// Instead, we use a simple volatile read-modify-write which the BPF JIT
/// handles correctly on single-CPU contexts. For true multi-CPU atomicity,
/// we rely on the per-CPU nature of BPF execution.
#[inline(always)]
unsafe fn atomic_fetch_add_u64(ptr: *mut u64, val: u64) -> u64 {
    // For BPF, we need to use intrinsic operations.
    // Use acqrel (acquire-release) instead of seqcst for better performance.
    // This is sufficient for ticket ordering since:
    // - acquire ensures we see prior writes to the slot
    // - release ensures our slot writes are visible before commit
    core::intrinsics::atomic_xadd_acqrel(ptr, val)
}

/// Submit an event to the sequenced ring buffer.
///
/// ULTRA-HOT PATH - every cycle counts!
///
/// Optimizations applied:
/// 1. ISOLATED SEQUENCER - .bss global instead of BPF map (no lookup overhead)
/// 2. Acquire atomic ordering (not seqcst) for ticket reservation
/// 3. Compacted 128-byte slots (2 cache lines)
/// 4. u8 flags to reduce write bandwidth
/// 5. Direct field writes (event passed by reference, written directly)
#[inline(always)]
fn submit_to_sequencer(event: &ProcessEvent) -> Result<(), i64> {
    // 1. ATOMIC RESERVATION (Direct memory access - no map lookup!)
    // --------------------------------------------------------
    // GLOBAL_SEQUENCER is a cache-line-aligned .bss global.
    // This compiles to a direct LOCK XADD on a constant address.
    let seq_ptr = unsafe { &raw mut GLOBAL_SEQUENCER.value };
    let ticket = unsafe { core::intrinsics::atomic_xadd_acqrel(seq_ptr, 1) };

    // 2. CALCULATE SLOT INDEX (masked, always in bounds)
    // --------------------------------------------------------
    let slot_idx = (ticket & (SEQUENCER_RING_MASK as u64)) as u32;
    let slot_ptr = unsafe { SEQUENCER_RING.get_ptr_mut(slot_idx) }.ok_or(-2i64)?;

    // 3. OPTIMISTIC LOCK (Mark as WRITING)
    // --------------------------------------------------------
    let now = unsafe { bpf_ktime_get_ns() };

    // Write metadata first (flags=WRITING signals "in progress")
    // Note: flags is now u8, ticket_id comes before reserved_at in new layout
    unsafe {
        core::ptr::write_volatile(&mut (*slot_ptr).flags, slot_flags::WRITING);
        core::ptr::write_volatile(&mut (*slot_ptr).ticket_id, ticket);
        core::ptr::write_volatile(&mut (*slot_ptr).reserved_at_ns, now);
    }

    // *** FAULT INJECTION (for reaper testing) ***
    #[cfg(feature = "fault-injection")]
    {
        if (ticket % 10000) == 0 {
            return Ok(());
        }
    }

    // 4. COPY DATA (Direct write to ring buffer)
    // --------------------------------------------------------
    // The event is passed by reference - we write it directly.
    // This is a single memcpy of 96 bytes.
    unsafe {
        core::ptr::write_volatile(&mut (*slot_ptr).event, *event);
    }

    // 5. COMMIT (Mark as READY with u8 flag)
    // --------------------------------------------------------
    unsafe {
        core::ptr::write_volatile(&mut (*slot_ptr).flags, slot_flags::READY);
    }

    Ok(())
}

/// ZERO-STACK Direct Write to Sequencer Ring Buffer
///
/// This is the ultra-optimized version that writes fields directly to VRAM,
/// bypassing the eBPF stack entirely. This eliminates:
/// 1. Stack allocation (~100 bytes memset)
/// 2. Stack writes (field assignments)
/// 3. Stack-to-ring memcpy (~100 bytes)
///
/// Total memory traffic reduction: ~300 bytes -> ~100 bytes (3x improvement)
#[inline(always)]
fn submit_to_sequencer_direct(
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    event_type: u32,
    ts_ns: u64,
    comm: &[u8; 16],
    cpu_pct_milli: u16,
    mem_pct_milli: u16,
    data: u64,
    data2: u64,
    aux: u32,
    aux2: u32,
) -> Result<(), i64> {
    // 1. ATOMIC RESERVATION (Direct memory access - no map lookup!)
    let seq_ptr = unsafe { &raw mut GLOBAL_SEQUENCER.value };
    let ticket = unsafe { core::intrinsics::atomic_xadd_acqrel(seq_ptr, 1) };

    // 2. CALCULATE SLOT INDEX
    let slot_idx = (ticket & (SEQUENCER_RING_MASK as u64)) as u32;
    let slot_ptr = unsafe { SEQUENCER_RING.get_ptr_mut(slot_idx) }.ok_or(-2i64)?;

    // 3. OPTIMISTIC LOCK (Header)
    unsafe {
        core::ptr::write_volatile(&mut (*slot_ptr).flags, slot_flags::WRITING);
        core::ptr::write_volatile(&mut (*slot_ptr).ticket_id, ticket);
        core::ptr::write_volatile(&mut (*slot_ptr).reserved_at_ns, ts_ns);
    }

    // *** FAULT INJECTION ***
    #[cfg(feature = "fault-injection")]
    {
        if (ticket % 10000) == 0 {
            return Ok(());
        }
    }

    // 4. DIRECT FIELD WRITES (Zero-Stack Optimization)
    // ------------------------------------------------
    // Write directly to the event field in the ring buffer slot.
    // No local ProcessEvent variable exists on the stack!
    unsafe {
        let e = &mut (*slot_ptr).event;

        // Core identity fields
        core::ptr::write_volatile(&mut e.pid, pid);
        core::ptr::write_volatile(&mut e.ppid, ppid);
        core::ptr::write_volatile(&mut e.uid, uid);
        core::ptr::write_volatile(&mut e.gid, gid);

        // Event metadata
        core::ptr::write_volatile(&mut e.event_type, event_type);
        core::ptr::write_volatile(&mut e.ts_ns, ts_ns);
        core::ptr::write_volatile(&mut e.seq, 0); // Unused, ticket_id provides ordering

        // Command name (16 bytes)
        core::ptr::write_volatile(&mut e.comm, *comm);

        // Telemetry fields
        core::ptr::write_volatile(&mut e.exit_time_ns, 0);
        core::ptr::write_volatile(&mut e.cpu_pct_milli, cpu_pct_milli);
        core::ptr::write_volatile(&mut e.mem_pct_milli, mem_pct_milli);

        // Payload fields
        core::ptr::write_volatile(&mut e.data, data);
        core::ptr::write_volatile(&mut e.data2, data2);
        core::ptr::write_volatile(&mut e.aux, aux);
        core::ptr::write_volatile(&mut e.aux2, aux2);
    }

    // 5. COMMIT
    unsafe {
        core::ptr::write_volatile(&mut (*slot_ptr).flags, slot_flags::READY);
    }

    Ok(())
}

// =============================================================================
// EXEC HANDLERS - Standard and BTF Raw Tracepoint versions
// =============================================================================
//
// We provide two exec handlers:
// 1. Standard tracepoint: Compatible fallback, uses kernel-marshalled args
// 2. BTF raw tracepoint: Zero-overhead direct kernel struct access
//
// The BTF version bypasses the kernel's argument marshalling and reads directly
// from the task_struct, eliminating stack copies and providing ~15-20% speedup.

/// Standard tracepoint exec handler (fallback when BTF not available)
#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn linnix_ai_ebpf(ctx: TracePointContext) -> u32 {
    try_handle_exec(ctx)
}

fn try_handle_exec(ctx: TracePointContext) -> u32 {
    info!(&ctx, "process exec");
    let now = unsafe { bpf_ktime_get_ns() };
    let pid = ctx.pid();
    if pid == 0 {
        return 0;
    }
    let event = match event_buffer_mut() {
        Some(event) => event,
        None => return 1,
    };
    init_event(&ctx, EventType::Exec, now, pid, event);
    submit_event(&ctx, event);
    0
}

// =============================================================================
// BTF RAW TRACEPOINT - Zero-overhead exec handler
// =============================================================================
//
// BTF tracepoints give us direct access to kernel structures without the
// marshalling overhead of standard tracepoints. The kernel doesn't copy
// arguments to a buffer - we read directly from struct pointers.
//
// sched_process_exec signature:
//   - arg0: struct task_struct *task (the process that exec'd)
//   - arg1: pid_t old_pid
//   - arg2: struct linux_binprm *bprm (contains new executable info)
//
// We bypass the stack by writing directly to the ring buffer slot.

/// BTF raw tracepoint for exec - maximum performance path
#[btf_tracepoint(function = "sched_process_exec")]
pub fn handle_exec_raw(ctx: BtfTracePointContext) -> u32 {
    try_handle_exec_raw(&ctx)
}

#[inline(always)]
fn try_handle_exec_raw(ctx: &BtfTracePointContext) -> u32 {
    let now = unsafe { bpf_ktime_get_ns() };
    let pid = ctx.pid();
    if pid == 0 {
        return 0;
    }

    // Use the direct ring buffer write path (zero-stack optimization)
    // We don't extract task_struct fields directly in this hot path;
    // instead we rely on ctx methods which are already optimized.
    let comm = get_comm();
    let ids = bpf_get_current_uid_gid();
    let uid = ids as u32;
    let gid = (ids >> 32) as u32;

    // Direct write to ring buffer, bypassing stack allocation
    let _ = submit_event_direct(
        ctx,
        pid,        // pid
        ctx.tgid(), // ppid (parent tgid)
        uid,
        gid,
        EventType::Exec as u32, // event_type
        now,                    // ts_ns
        &comm,
        PERCENT_MILLI_UNKNOWN, // cpu_pct_milli
        PERCENT_MILLI_UNKNOWN, // mem_pct_milli
        0,                     // data
        0,                     // data2
        0,                     // aux
        0,                     // aux2
    );
    0
}

/// Get current process comm (command name) via bpf_get_current_comm
#[inline(always)]
fn get_comm() -> [u8; 16] {
    // bpf_get_current_comm returns Result<[u8; 16], c_long>
    aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16])
}

// =============================================================================
// FORK HANDLERS - Standard and BTF Raw Tracepoint versions
// =============================================================================
//
// sched_process_fork signature: TP_PROTO(struct task_struct *parent, struct task_struct *child)
//
// BTF Version: Reads child PID and comm directly from task_struct pointers.
// Standard Version: Falls back to pre-marshalled tracepoint args.

/// Standard tracepoint fork handler (fallback when BTF not available)
#[cfg(target_arch = "bpf")]
#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn handle_fork(ctx: TracePointContext) -> u32 {
    match try_handle_fork(ctx) {
        Ok(ret) => ret,
        Err(err) => err,
    }
}

#[cfg(target_arch = "bpf")]
fn try_handle_fork(ctx: TracePointContext) -> Result<u32, u32> {
    let ids = bpf_get_current_uid_gid();
    let uid = ids as u32;
    let gid = (ids >> 32) as u32;

    // Read child info from tracepoint args (pre-marshalled by kernel)
    let child_pid: i32 = unsafe { ctx.read_at(44).map_err(|_| 1u32)? };
    let child_comm_raw: [u8; 16] = unsafe { ctx.read_at(28).map_err(|_| 1u32)? };

    let mut comm = [0u8; 16];
    comm.copy_from_slice(&child_comm_raw);

    let now = unsafe { bpf_ktime_get_ns() };

    // ZERO-STACK PATH: Use direct write to avoid stack allocation
    submit_event_direct(
        &ctx,
        child_pid as u32, // pid
        ctx.pid(),        // ppid
        uid,
        gid,
        EventType::Fork as u32, // event_type
        now,                    // ts_ns
        &comm,
        PERCENT_MILLI_UNKNOWN, // cpu_pct_milli
        PERCENT_MILLI_UNKNOWN, // mem_pct_milli
        0,                     // data
        0,                     // data2
        0,                     // aux
        0,                     // aux2
    );

    Ok(0)
}

/// BTF raw tracepoint for fork - SPEED DEMON MODE
///
/// Eliminates kernel argument marshalling overhead by reading directly from
/// task_struct pointers. This is the maximum performance path.
#[btf_tracepoint(function = "sched_process_fork")]
pub fn handle_fork_raw(ctx: BtfTracePointContext) -> i32 {
    try_handle_fork_raw(&ctx)
}

#[inline(always)]
fn try_handle_fork_raw(ctx: &BtfTracePointContext) -> i32 {
    let now = unsafe { bpf_ktime_get_ns() };

    // Get parent and child task_struct pointers from raw tracepoint args
    let parent = unsafe { ctx.arg::<*const TaskStruct>(0) };
    let child = unsafe { ctx.arg::<*const TaskStruct>(1) };

    // Read PIDs directly from task_struct
    let child_pid = unsafe { read_task_pid(child) };
    let parent_pid = unsafe { read_task_pid(parent) };

    if child_pid == 0 {
        return 0;
    }

    // Read comm from child task_struct
    let comm = unsafe { read_task_comm(child) };

    // Get UID/GID from current context
    let ids = bpf_get_current_uid_gid();
    let uid = ids as u32;
    let gid = (ids >> 32) as u32;

    // Direct write to sequencer ring buffer
    let _ = submit_to_sequencer_direct(
        child_pid,  // pid (child)
        parent_pid, // ppid (parent)
        uid,
        gid,
        EventType::Fork as u32, // event_type
        now,                    // ts_ns
        &comm,
        PERCENT_MILLI_UNKNOWN, // cpu_pct_milli
        PERCENT_MILLI_UNKNOWN, // mem_pct_milli
        0,                     // data
        0,                     // data2
        0,                     // aux
        0,                     // aux2
    );

    0
}

// =============================================================================
// EXIT HANDLERS - Standard and BTF Raw Tracepoint versions
// =============================================================================
//
// sched_process_exit signature: TP_PROTO(struct task_struct *p)
//
// BTF Version: Reads PID directly from task_struct pointer.
// Also cleans up per-process state maps.

/// Standard tracepoint exit handler (fallback)
#[cfg(target_arch = "bpf")]
#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn handle_exit(ctx: TracePointContext) -> u32 {
    try_handle_exit(ctx)
}

fn try_handle_exit(ctx: TracePointContext) -> u32 {
    let now = unsafe { bpf_ktime_get_ns() };
    let pid = ctx.pid();
    if pid != 0 {
        let event = match event_buffer_mut() {
            Some(event) => event,
            None => return 1,
        };
        init_event(&ctx, EventType::Exit, now, pid, event);
        event.exit_time_ns = now;
        submit_event(&ctx, event);
    }

    cleanup_process_state(pid);
    0
}

/// BTF raw tracepoint for exit - SPEED DEMON MODE
#[btf_tracepoint(function = "sched_process_exit")]
pub fn handle_exit_raw(ctx: BtfTracePointContext) -> i32 {
    try_handle_exit_raw(&ctx)
}

#[inline(always)]
fn try_handle_exit_raw(ctx: &BtfTracePointContext) -> i32 {
    let now = unsafe { bpf_ktime_get_ns() };

    // Get exiting task_struct pointer
    let task = unsafe { ctx.arg::<*const TaskStruct>(0) };
    let pid = unsafe { read_task_pid(task) };

    if pid == 0 {
        return 0;
    }

    // Read comm from task_struct
    let comm = unsafe { read_task_comm(task) };

    // Get UID/GID from current context
    let ids = bpf_get_current_uid_gid();
    let uid = ids as u32;
    let gid = (ids >> 32) as u32;

    // Direct write to sequencer ring buffer
    let _ = submit_to_sequencer_direct(
        pid,
        ctx.tgid(), // ppid from context
        uid,
        gid,
        EventType::Exit as u32, // event_type
        now,                    // ts_ns
        &comm,
        PERCENT_MILLI_UNKNOWN, // cpu_pct_milli
        PERCENT_MILLI_UNKNOWN, // mem_pct_milli
        now,                   // data = exit_time_ns
        0,                     // data2
        0,                     // aux
        0,                     // aux2
    );

    // Clean up per-process state
    cleanup_process_state(pid);

    0
}

/// Clean up per-process state maps when a process exits
#[inline(always)]
fn cleanup_process_state(pid: u32) {
    if pid != 0 {
        let stats = unsafe { &raw const TASK_STATS };
        let _ = unsafe { (*stats).remove(&pid) };

        let faults = unsafe { &raw const PAGE_FAULT_THROTTLE };
        let _ = unsafe { (*faults).remove(&pid) };
    }
}

fn emit_activity_event<C: EbpfContext>(
    ctx: &C,
    event_type: EventType,
    now: u64,
    data: u64,
    data2: u64,
    aux: u32,
    aux2: u32,
) -> u32 {
    if matches!(
        event_type,
        EventType::Net | EventType::FileIo | EventType::Syscall | EventType::BlockIo
    ) {
        return 0;
    }

    if matches!(
        event_type,
        EventType::Net | EventType::FileIo | EventType::BlockIo
    ) && data == 0
    {
        return 0;
    }

    let pid = ctx.pid();
    if pid == 0 {
        return 0;
    }

    let event = match event_buffer_mut() {
        Some(event) => event,
        None => return 1,
    };

    init_event(ctx, event_type, now, pid, event);
    event.data = data;
    event.data2 = data2;
    event.aux = aux;
    event.aux2 = aux2;
    submit_event(ctx, event);
    0
}

#[kprobe(function = "tcp_sendmsg")]
pub fn trace_tcp_send(ctx: ProbeContext) -> u32 {
    try_trace_tcp_send(ctx)
}

fn try_trace_tcp_send(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe(function = "tcp_recvmsg")]
pub fn trace_tcp_recv(ctx: ProbeContext) -> u32 {
    try_trace_tcp_recv(ctx)
}

fn try_trace_tcp_recv(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe(function = "udp_sendmsg")]
pub fn trace_udp_send(ctx: ProbeContext) -> u32 {
    try_trace_udp_send(ctx)
}

fn try_trace_udp_send(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe(function = "udp_recvmsg")]
pub fn trace_udp_recv(ctx: ProbeContext) -> u32 {
    try_trace_udp_recv(ctx)
}

fn try_trace_udp_recv(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe(function = "unix_stream_sendmsg")]
pub fn trace_unix_stream_send(ctx: ProbeContext) -> u32 {
    try_trace_unix_stream_send(ctx)
}

fn try_trace_unix_stream_send(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe(function = "unix_stream_recvmsg")]
pub fn trace_unix_stream_recv(ctx: ProbeContext) -> u32 {
    try_trace_unix_stream_recv(ctx)
}

fn try_trace_unix_stream_recv(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe(function = "unix_dgram_sendmsg")]
pub fn trace_unix_dgram_send(ctx: ProbeContext) -> u32 {
    try_trace_unix_dgram_send(ctx)
}

fn try_trace_unix_dgram_send(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe(function = "unix_dgram_recvmsg")]
pub fn trace_unix_dgram_recv(ctx: ProbeContext) -> u32 {
    try_trace_unix_dgram_recv(ctx)
}

fn try_trace_unix_dgram_recv(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe(function = "vfs_read")]
pub fn trace_vfs_read(ctx: ProbeContext) -> u32 {
    try_trace_vfs_read(ctx)
}

fn try_trace_vfs_read(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe(function = "vfs_write")]
pub fn trace_vfs_write(ctx: ProbeContext) -> u32 {
    try_trace_vfs_write(ctx)
}

fn try_trace_vfs_write(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[tracepoint(category = "block", name = "block_bio_queue")]
pub fn trace_block_queue(ctx: TracePointContext) -> u32 {
    try_trace_block_queue(ctx)
}

fn try_trace_block_queue(ctx: TracePointContext) -> u32 {
    let dev = match tp_read_u64(&ctx, BLOCK_BIO_DEV_OFFSET) {
        Some(value) => value,
        None => return 0,
    };
    let sector = match tp_read_u64(&ctx, BLOCK_BIO_SECTOR_OFFSET) {
        Some(value) => value,
        None => return 0,
    };
    let sectors = match tp_read_u32(&ctx, BLOCK_BIO_NR_SECTOR_OFFSET) {
        Some(value) => value,
        None => return 0,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    emit_block_event_common(&ctx, now, BlockOp::Queue, dev, sector, sectors, None)
}

#[tracepoint(category = "block", name = "block_rq_issue")]
pub fn trace_block_issue(ctx: TracePointContext) -> u32 {
    try_trace_block_issue(ctx)
}

fn try_trace_block_issue(ctx: TracePointContext) -> u32 {
    let dev = match tp_read_u64(&ctx, BLOCK_RQ_DEV_OFFSET) {
        Some(value) => value,
        None => return 0,
    };
    let sector = match tp_read_u64(&ctx, BLOCK_RQ_SECTOR_OFFSET) {
        Some(value) => value,
        None => return 0,
    };
    let sectors = match tp_read_u32(&ctx, BLOCK_RQ_NR_SECTOR_OFFSET) {
        Some(value) => value,
        None => return 0,
    };
    let bytes = tp_read_u32(&ctx, BLOCK_RQ_ISSUE_BYTES_OFFSET);
    let now = unsafe { bpf_ktime_get_ns() };
    emit_block_event_common(&ctx, now, BlockOp::Issue, dev, sector, sectors, bytes)
}

#[tracepoint(category = "block", name = "block_rq_complete")]
pub fn trace_block_complete(ctx: TracePointContext) -> u32 {
    try_trace_block_complete(ctx)
}

fn try_trace_block_complete(ctx: TracePointContext) -> u32 {
    let dev = match tp_read_u64(&ctx, BLOCK_RQ_DEV_OFFSET) {
        Some(value) => value,
        None => return 0,
    };
    let sector = match tp_read_u64(&ctx, BLOCK_RQ_SECTOR_OFFSET) {
        Some(value) => value,
        None => return 0,
    };
    let sectors = match tp_read_u32(&ctx, BLOCK_RQ_NR_SECTOR_OFFSET) {
        Some(value) => value,
        None => return 0,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    emit_block_event_common(&ctx, now, BlockOp::Complete, dev, sector, sectors, None)
}

#[btf_tracepoint(function = "page_fault_user")]
pub fn trace_page_fault_user(ctx: BtfTracePointContext) -> u32 {
    try_trace_page_fault(ctx, PageFaultOrigin::User)
}

#[btf_tracepoint(function = "page_fault_kernel")]
pub fn trace_page_fault_kernel(ctx: BtfTracePointContext) -> u32 {
    try_trace_page_fault(ctx, PageFaultOrigin::Kernel)
}

fn try_trace_page_fault(ctx: BtfTracePointContext, origin: PageFaultOrigin) -> u32 {
    let address: u64 = unsafe { ctx.arg(0) };
    let ip: u64 = unsafe { ctx.arg(1) };
    let error: u32 = unsafe { ctx.arg(2) };
    let now = unsafe { bpf_ktime_get_ns() };
    let pid = ctx.pid();
    if pid == 0 {
        return 0;
    }
    if !throttle_page_fault(pid, now) {
        return 0;
    }
    emit_activity_event(
        &ctx,
        EventType::PageFault,
        now,
        address,
        ip,
        error,
        origin as u32,
    )
}

#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
pub fn trace_sys_enter(ctx: TracePointContext) -> u32 {
    try_trace_sys_enter(ctx)
}

fn try_trace_sys_enter(ctx: TracePointContext) -> u32 {
    let _ = ctx;
    0
}

#[cfg(all(not(test), target_arch = "bpf"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
