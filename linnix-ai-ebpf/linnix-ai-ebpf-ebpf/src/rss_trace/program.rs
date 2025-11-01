use aya_ebpf::{
    macros::{map, tracepoint},
    maps::perf::PerfEventArray,
    programs::TracePointContext,
    EbpfContext,
};
use linnix_ai_ebpf_common::RssTraceEvent;

#[map(name = "RSS_EVENTS")]
static mut RSS_EVENTS: PerfEventArray<RssTraceEvent> = PerfEventArray::new(0);

#[tracepoint(category = "mm", name = "rss_stat")]
pub fn trace_rss_stat(ctx: TracePointContext) -> u32 {
    handle_rss_stat(ctx)
}

// Accessing the global map requires touching a `static mut`; allow it explicitly.
#[allow(static_mut_refs)]
fn handle_rss_stat(ctx: TracePointContext) -> u32 {
    let pid = ctx.pid();
    if pid == 0 {
        return 0;
    }

    let member_idx: i32 = unsafe { ctx.read_at::<i32>(20) }.unwrap_or_default();
    let delta: i64 = unsafe { ctx.read_at::<i64>(24) }.unwrap_or_default();

    let event = RssTraceEvent {
        pid,
        member: member_idx as u32,
        delta_pages: delta,
    };

    unsafe {
        RSS_EVENTS.output(&ctx, &event, 0);
    }
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
