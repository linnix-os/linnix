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
use tokio::sync::mpsc::{self, error::TrySendError};

struct QueuedEvent {
    event: ProcessEvent,
    comm: String,
}

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
    event_queue_capacity: usize,
) {
    println!("[cognitod] Starting listener for BPF ring buffer...");
    let (event_tx, event_rx) = mpsc::channel(listener_queue_capacity(event_queue_capacity));
    spawn_event_worker(
        context.clone(),
        metrics.clone(),
        handlers.clone(),
        None,
        event_rx,
    );

    tokio::task::spawn_blocking(move || {
        loop {
            if let Some(data) = ringbuf.next() {
                if let Some(event) = parse_event(data.as_ref()) {
                    if !metrics.record_event(rate_cap, event.event_type) {
                        continue;
                    }
                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("invalid")
                        .trim_end_matches('\0')
                        .to_string();

                    try_enqueue_event(&event_tx, &metrics, QueuedEvent { event, comm });
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
    event_queue_capacity: usize,
) {
    println!("[cognitod] Starting listener for BPF perf buffers...");

    let lineage_cache: Arc<LineageCache> = Arc::new(LineageCache::default());
    let (event_tx, event_rx) = mpsc::channel(listener_queue_capacity(event_queue_capacity));
    spawn_event_worker(
        context.clone(),
        metrics.clone(),
        handlers.clone(),
        Some(Arc::clone(&lineage_cache)),
        event_rx,
    );

    for buffer in buffers {
        let metrics = Arc::clone(&metrics);
        let event_tx = event_tx.clone();

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

                    let event = ProcessEvent::new(event_wire);
                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("invalid")
                        .trim_end_matches('\0')
                        .to_string();

                    log::debug!(
                        "[perf] received event type={:?} pid={} ppid={} comm={}",
                        event_label(event.event_type),
                        event.pid,
                        event.ppid,
                        comm
                    );

                    try_enqueue_event(&event_tx, &metrics, QueuedEvent { event, comm });
                }
            }
        });
    }
}

fn listener_queue_capacity(configured: usize) -> usize {
    if configured == 0 {
        log::warn!("[config] runtime.event_queue_capacity=0 is invalid; using 1");
        1
    } else {
        configured
    }
}

fn spawn_event_worker(
    context: Arc<ContextStore>,
    metrics: Arc<Metrics>,
    handlers: Arc<HandlerList>,
    lineage: Option<Arc<LineageCache>>,
    mut event_rx: mpsc::Receiver<QueuedEvent>,
) {
    tokio::spawn(async move {
        while let Some(queued) = event_rx.recv().await {
            metrics.set_listener_queue_depth(event_rx.len());
            process_queued_event(
                queued,
                Arc::clone(&context),
                Arc::clone(&metrics),
                Arc::clone(&handlers),
                lineage.clone(),
            )
            .await;
            metrics.set_listener_queue_depth(event_rx.len());
        }
        metrics.set_listener_queue_depth(0);
    });
}

fn try_enqueue_event(event_tx: &mpsc::Sender<QueuedEvent>, metrics: &Metrics, queued: QueuedEvent) {
    let event_type = queued.event.event_type;
    match event_tx.try_send(queued) {
        Ok(()) => {
            metrics.set_listener_queue_depth(
                event_tx.max_capacity().saturating_sub(event_tx.capacity()),
            );
        }
        Err(TrySendError::Full(_)) => {
            metrics.record_listener_queue_drop(event_type);
            metrics.set_listener_queue_depth(event_tx.max_capacity());
        }
        Err(TrySendError::Closed(_)) => {
            metrics.record_listener_queue_drop(event_type);
            metrics.set_listener_queue_depth(0);
            log::warn!("listener event worker is closed; dropping event");
        }
    }
}

async fn process_queued_event(
    queued: QueuedEvent,
    context: Arc<ContextStore>,
    metrics: Arc<Metrics>,
    handlers: Arc<HandlerList>,
    lineage: Option<Arc<LineageCache>>,
) {
    let QueuedEvent { mut event, comm } = queued;

    if let Some(lineage) = lineage {
        if event.event_type == EventType::Fork as u32 {
            lineage.record_fork(event.pid, event.ppid).await;
        } else if event.ppid == 0 {
            match lineage.lookup(event.pid).await {
                Some(ppid) => {
                    event.ppid = ppid;
                    metrics.inc_lineage_hit();
                }
                None => {
                    metrics.inc_lineage_miss();
                }
            }
        }
    }

    println!(
        "[event] type={:?} pid={} ppid={} uid={} gid={} comm={}",
        event_label(event.event_type),
        event.pid,
        event.ppid,
        event.uid,
        event.gid,
        comm
    );
    handlers.on_event(&event).await;
    context.add(event);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PERCENT_MILLI_UNKNOWN;
    use crate::handler::Handler;
    use crate::types::SystemSnapshot;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use tokio::sync::Notify;

    fn event(pid: u32, sequence: u64) -> ProcessEvent {
        ProcessEvent::new(ProcessEventWire {
            pid,
            ppid: 0,
            uid: 0,
            gid: 0,
            event_type: EventType::Net as u32,
            ts_ns: sequence,
            seq: sequence,
            comm: [0; 16],
            exit_time_ns: 0,
            cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
            mem_pct_milli: PERCENT_MILLI_UNKNOWN,
            data: sequence,
            data2: 0,
            aux: 0,
            aux2: 0,
        })
    }

    #[test]
    fn burst_enqueue_is_bounded_and_accounted() {
        let metrics = Metrics::new();
        let (tx, _rx) = mpsc::channel(2);

        for sequence in 0..10 {
            try_enqueue_event(
                &tx,
                &metrics,
                QueuedEvent {
                    event: event(42, sequence),
                    comm: "burst".to_string(),
                },
            );
        }

        assert_eq!(metrics.listener_queue_depth(), 2);
        assert_eq!(metrics.listener_queue_drops(), 8);
        assert_eq!(
            metrics
                .dropped_events_total
                .load(std::sync::atomic::Ordering::Relaxed),
            8
        );
        assert_eq!(
            metrics
                .drops_by_type()
                .into_iter()
                .find(|(event_type, _)| *event_type == EventType::Net as u32)
                .map(|(_, drops)| drops),
            Some(8)
        );
    }

    #[derive(Clone)]
    struct RecordingHandler {
        seen: Arc<Mutex<Vec<u64>>>,
        notify: Arc<Notify>,
    }

    #[async_trait]
    impl Handler for RecordingHandler {
        fn name(&self) -> &'static str {
            "recording"
        }

        async fn on_event(&self, event: &ProcessEvent) {
            self.seen.lock().unwrap().push(event.data);
            self.notify.notify_waiters();
        }

        async fn on_snapshot(&self, _snapshot: &SystemSnapshot) {}
    }

    #[tokio::test]
    async fn worker_preserves_per_pid_enqueue_order() {
        let context = Arc::new(ContextStore::new(Duration::from_secs(60), 64, None));
        let metrics = Arc::new(Metrics::new());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let handler = RecordingHandler {
            seen: Arc::clone(&seen),
            notify: Arc::clone(&notify),
        };
        let mut handler_list = HandlerList::new();
        handler_list.register(handler);
        let handlers = Arc::new(handler_list);
        let (tx, rx) = mpsc::channel(8);
        spawn_event_worker(context, Arc::clone(&metrics), handlers, None, rx);

        for sequence in 0..6 {
            try_enqueue_event(
                &tx,
                &metrics,
                QueuedEvent {
                    event: event(42, sequence),
                    comm: "ordered".to_string(),
                },
            );
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let notified = notify.notified();
            if seen.lock().unwrap().len() == 6 {
                break;
            }
            let now = tokio::time::Instant::now();
            assert!(now < deadline, "worker did not process the synthetic burst");
            tokio::time::timeout(deadline - now, notified)
                .await
                .expect("worker did not process the synthetic burst");
        }

        assert_eq!(*seen.lock().unwrap(), vec![0, 1, 2, 3, 4, 5]);
        assert!(metrics.listener_queue_depth() <= 8);
        assert_eq!(metrics.listener_queue_drops(), 0);
    }
}
