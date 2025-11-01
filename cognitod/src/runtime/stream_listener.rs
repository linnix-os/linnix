// linnix-project/cognitod/src/runtime/stream_listener.rs
use crate::config::OfflineGuard;
use crate::context::ContextStore;
use crate::handler::HandlerList;
use crate::metrics::Metrics;
use crate::runtime::lineage::LineageCache;
use crate::{ProcessEvent, ProcessEventWire};
use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::{MapData, ring_buf::RingBuf};
use bytes::BytesMut;
use linnix_ai_ebpf_common::EventType;
use std::{io, mem, ptr, sync::Arc, thread, time::Duration};
use tokio::io::unix::AsyncFd;
use tokio::runtime::Handle;

fn event_label(kind: u32) -> &'static str {
    match kind {
        x if x == EventType::Exec as u32 => "Exec",
        x if x == EventType::Fork as u32 => "Fork",
        x if x == EventType::Exit as u32 => "Exit",
        x if x == EventType::Net as u32 => "Net",
        x if x == EventType::FileIo as u32 => "FileIo",
        x if x == EventType::Syscall as u32 => "Syscall",
        x if x == EventType::BlockIo as u32 => "BlockIo",
        x if x == EventType::PageFault as u32 => "PageFault",
        _ => "Unknown",
    }
}

#[allow(dead_code)]
pub fn start_listener(
    mut ringbuf: RingBuf<MapData>,
    context: Arc<ContextStore>,
    metrics: Arc<Metrics>,
    handlers: Arc<HandlerList>,
    _offline: Arc<OfflineGuard>,
    rate_cap: u64,
) {
    println!("[cognitod] Starting listener for BPF ring buffer...");
    tokio::task::spawn_blocking(move || {
        let rt_handle = Handle::current();
        let handlers = handlers.clone();
        loop {
            if let Some(data) = ringbuf.next() {
                if let Some(event) = parse_event(data.as_ref()) {
                    let metrics_clone = metrics.clone();
                    if !metrics_clone.record_event(rate_cap, event.event_type) {
                        continue;
                    }
                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("invalid")
                        .trim_end_matches('\0')
                        .to_string();

                    // Process event asynchronously
                    let context_clone = context.clone();
                    let mut event_for_llm = event.clone();
                    let handlers_clone = handlers.clone();
                    rt_handle.spawn(async move {
                        event_for_llm.tags = Vec::new();
                        println!(
                            "[event] type={:?} pid={} ppid={} uid={} gid={} comm={} tags={:?}",
                            event_label(event_for_llm.event_type),
                            event_for_llm.pid,
                            event_for_llm.ppid,
                            event_for_llm.uid,
                            event_for_llm.gid,
                            comm,
                            event_for_llm.tags
                        );
                        handlers_clone.on_event(&event_for_llm).await;
                        context_clone.add(event_for_llm);
                    });
                } else {
                    metrics.inc_rb_overflow();
                    println!("[cognitod] Failed to parse event");
                }
            } else {
                metrics.inc_rb_overflow();
                thread::sleep(Duration::from_millis(1));
            }
        }
    });
}

pub fn start_perf_listener(
    buffers: Vec<PerfEventArrayBuffer<MapData>>,
    context: Arc<ContextStore>,
    metrics: Arc<Metrics>,
    handlers: Arc<HandlerList>,
    _offline: Arc<OfflineGuard>,
    rate_cap: u64,
) {
    println!("[cognitod] Starting listener for BPF perf buffers...");

    let lineage_cache: Arc<LineageCache> = Arc::new(LineageCache::default());

    for buffer in buffers {
        let context = Arc::clone(&context);
        let metrics = Arc::clone(&metrics);
        let handlers = Arc::clone(&handlers);
        let lineage = Arc::clone(&lineage_cache);

        tokio::spawn(async move {
            let mut async_buffer = match AsyncFd::new(buffer) {
                Ok(fd) => fd,
                Err(e) => {
                    log::error!("failed to create AsyncFd for perf buffer: {e}");
                    return;
                }
            };

            const SCRATCH_SLOTS: usize = 16;
            let mut scratch: Vec<BytesMut> = (0..SCRATCH_SLOTS)
                .map(|_| BytesMut::with_capacity(64 * 1024))
                .collect();

            loop {
                let mut ready = match async_buffer.readable_mut().await {
                    Ok(guard) => guard,
                    Err(e) => {
                        log::warn!("perf buffer readable wait failed: {e}");
                        metrics.inc_perf_poll_error();
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        continue;
                    }
                };

                let events = match ready.try_io(|inner| {
                    inner
                        .get_mut()
                        .read_events(scratch.as_mut_slice())
                        .map_err(io::Error::other)
                }) {
                    Ok(Ok(events)) => events,
                    Ok(Err(e)) => {
                        ready.clear_ready();
                        log::warn!("perf.read_events error: {e}");
                        metrics.inc_perf_poll_error();
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(_would_block) => {
                        ready.clear_ready();
                        continue;
                    }
                };
                ready.clear_ready();

                if events.lost > 0 {
                    metrics.inc_rb_overflow();
                }

                for buf in scratch.iter_mut().take(events.read) {
                    if buf.len() < mem::size_of::<ProcessEventWire>() {
                        buf.clear();
                        continue;
                    }

                    let event_wire: ProcessEventWire =
                        unsafe { ptr::read_unaligned(buf.as_ptr() as *const ProcessEventWire) };
                    buf.clear();

                    if !metrics.record_event(rate_cap, event_wire.event_type) {
                        continue;
                    }

                    let mut event_for_llm = ProcessEvent::new(event_wire);
                    let comm = std::str::from_utf8(&event_for_llm.comm)
                        .unwrap_or("invalid")
                        .trim_end_matches('\0')
                        .to_string();

                    log::debug!(
                        "[perf] received event type={:?} pid={} ppid={} comm={}",
                        event_label(event_for_llm.event_type),
                        event_for_llm.pid,
                        event_for_llm.ppid,
                        comm
                    );

                    let metrics_for_llm = Arc::clone(&metrics);
                    let handlers_clone = Arc::clone(&handlers);
                    let context_clone = Arc::clone(&context);
                    let lineage_clone = Arc::clone(&lineage);

                    tokio::spawn(async move {
                        if event_for_llm.event_type == EventType::Fork as u32 {
                            lineage_clone
                                .record_fork(event_for_llm.pid, event_for_llm.ppid)
                                .await;
                        } else if event_for_llm.ppid == 0 {
                            match lineage_clone.lookup(event_for_llm.pid).await {
                                Some(ppid) => {
                                    event_for_llm.ppid = ppid;
                                    metrics_for_llm.inc_lineage_hit();
                                }
                                None => {
                                    metrics_for_llm.inc_lineage_miss();
                                }
                            }
                        }

                        event_for_llm.tags = Vec::new();

                        println!(
                            "[event] type={:?} pid={} ppid={} uid={} gid={} comm={} tags={:?}",
                            event_label(event_for_llm.event_type),
                            event_for_llm.pid,
                            event_for_llm.ppid,
                            event_for_llm.uid,
                            event_for_llm.gid,
                            comm,
                            event_for_llm.tags
                        );
                        handlers_clone.on_event(&event_for_llm).await;
                        context_clone.add(event_for_llm);
                    });
                }
            }
        });
    }
}

#[allow(dead_code)]
fn parse_event(bytes: &[u8]) -> Option<ProcessEvent> {
    if bytes.len() < std::mem::size_of::<ProcessEventWire>() {
        return None;
    }
    let ptr = bytes.as_ptr() as *const ProcessEventWire;
    let raw = unsafe { *ptr };
    Some(ProcessEvent::new(raw))
}
