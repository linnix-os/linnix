use core::cmp;

use aya_ebpf::{
    helpers::{
        bpf_get_current_task_btf, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read,
    },
    macros::{btf_tracepoint, kprobe, map, tracepoint},
    maps::{perf::PerfEventArray, HashMap, PerCpuArray},
    programs::{BtfTracePointContext, ProbeContext, TracePointContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use linnix_ai_ebpf_common::{
    rss_source, BlockOp, EventType, PageFaultOrigin, ProcessEvent, TelemetryConfig,
    PERCENT_MILLI_UNKNOWN,
};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[map(name = "TASK_STATS")]
static mut TASK_STATS: HashMap<u32, TaskStats> = HashMap::with_max_entries(65_536, 0);

#[map(name = "EVENT_BUFFER")]
static mut EVENT_BUFFER: PerCpuArray<ProcessEvent> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "PAGE_FAULT_THROTTLE")]
static mut PAGE_FAULT_THROTTLE: HashMap<u32, u64> = HashMap::with_max_entries(65_536, 0);

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
    let events = unsafe { &mut EVENTS };
    events.output(ctx, event, 0);
}

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

    let child_pid: i32 = unsafe { ctx.read_at(44).map_err(|_| 1u32)? };
    let child_comm_raw: [u8; 16] = unsafe { ctx.read_at(28).map_err(|_| 1u32)? };

    let mut comm = [0u8; 16];
    comm.copy_from_slice(&child_comm_raw);

    let now = unsafe { bpf_ktime_get_ns() };

    let event = ProcessEvent {
        pid: child_pid as u32,
        ppid: ctx.pid(),
        uid,
        gid,
        event_type: EventType::Fork as u32,
        ts_ns: now,
        seq: 0,
        comm,
        exit_time_ns: 0,
        cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
        mem_pct_milli: PERCENT_MILLI_UNKNOWN,
        data: 0,
        data2: 0,
        aux: 0,
        aux2: 0,
    };

    submit_event(&ctx, &event);
    Ok(0)
}

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

    if pid != 0 {
        let stats = unsafe { &raw const TASK_STATS };
        let _ = unsafe { (*stats).remove(&pid) };

        let faults = unsafe { &raw const PAGE_FAULT_THROTTLE };
        let _ = unsafe { (*faults).remove(&pid) };
    }

    0
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
