mod auth;

use crate::runtime::probes::ProbeState;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{
        IntoResponse, Json, Response,
        sse::{Event, Sse},
    },
    routing::get,
};
use futures_util::stream::{BoxStream, Stream, StreamExt};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{Value, json, to_string};
use std::collections::VecDeque;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio_stream::wrappers::{BroadcastStream, IntervalStream, errors::BroadcastStreamRecvError};

use crate::ProcessEvent;
#[cfg(test)]
use crate::ProcessEventWire;
use crate::alerts::Alert;
use crate::config::{OfflineGuard, ReasonerConfig};
use crate::context::ContextStore;
#[cfg(feature = "fake-events")]
use crate::fake_events;
use crate::handler::local_ilm::schema::insight_json_schema;
use crate::insights::{InsightRecord, InsightStore};
use crate::metrics::Metrics;
use crate::types::ProcessAlert;
use crate::types::SystemSnapshot;
use linnix_ai_ebpf_common::EventType;
use sysinfo::{Pid, System};
use tokio::sync::broadcast;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum EventKind {
    Exec,
    Fork,
    Exit,
    Net,
    FileIo,
    Syscall,
    BlockIo,
    PageFault,
    Unknown,
}

impl From<u32> for EventKind {
    fn from(value: u32) -> Self {
        match value {
            x if x == EventType::Exec as u32 => EventKind::Exec,
            x if x == EventType::Fork as u32 => EventKind::Fork,
            x if x == EventType::Exit as u32 => EventKind::Exit,
            x if x == EventType::Net as u32 => EventKind::Net,
            x if x == EventType::FileIo as u32 => EventKind::FileIo,
            x if x == EventType::Syscall as u32 => EventKind::Syscall,
            x if x == EventType::BlockIo as u32 => EventKind::BlockIo,
            x if x == EventType::PageFault as u32 => EventKind::PageFault,
            _ => EventKind::Unknown,
        }
    }
}

#[derive(Serialize)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    event_type: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_pct: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mem_pct: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    age_sec: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Serialize)]
struct GraphNode {
    pid: u32,
    ppid: u32,
    comm: String,
    uid: u32,
    gid: u32,
    event_type: EventKind,
    relationship: String, // "ancestor", "root", "descendant"
    level: isize,         // 0 for root, increasing away from root
}

#[derive(Serialize)]
struct GraphResponse {
    root: u32,
    nodes: Vec<GraphNode>,
}

#[derive(Serialize)]
struct ProcessEventSse {
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    event_type: u32,
    event_type_name: String,
    ts_ns: u64,
    seq: u64,
    exit_time_ns: u64,
    cpu_pct_milli: u16,
    mem_pct_milli: u16,
    data: u64,
    data2: u64,
    aux: u32,
    aux2: u32,
}

#[derive(Serialize)]
struct TopRssEntry {
    pid: u32,
    comm: String,
    mem_percent: f32,
}

#[derive(Serialize)]
struct TopCpuEntry {
    pid: u32,
    comm: String,
    cpu_percent: f32,
}

// Alert timeline structures
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AlertRecord {
    id: String,
    timestamp: u64,
    severity: String,
    rule: String,
    message: String,
    host: String,
}

#[derive(Debug, Clone, Serialize)]
struct AlertDetail {
    id: String,
    timestamp: u64,
    severity: String,
    rule: String,
    message: String,
    host: String,
    explanation: String,
    remediation: String,
}

// System metrics structure
#[derive(Serialize)]
struct SystemMetrics {
    cpu_total_pct: f32,
    memory_total_mb: u64,
    memory_used_mb: u64,
    processes_total: usize,
    timestamp: u64,
}

// Alert history storage (ring buffer)
pub struct AlertHistory {
    records: RwLock<VecDeque<AlertRecord>>,
    next_id: AtomicU64,
    max_size: usize,
}

impl AlertHistory {
    pub fn new(max_size: usize) -> Self {
        Self {
            records: RwLock::new(VecDeque::with_capacity(max_size)),
            next_id: AtomicU64::new(1),
            max_size,
        }
    }

    pub async fn add_alert(&self, alert: Alert) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record = AlertRecord {
            id: format!("alert-{}", id),
            timestamp,
            severity: alert.severity.as_str().to_string(),
            rule: alert.rule,
            message: alert.message,
            host: alert.host,
        };

        let mut records = self.records.write().await;
        if records.len() >= self.max_size {
            records.pop_front();
        }
        records.push_back(record);
    }

    pub async fn get_all(&self) -> Vec<AlertRecord> {
        self.records.read().await.iter().cloned().collect()
    }

    pub async fn get_by_id(&self, id: &str) -> Option<AlertRecord> {
        self.records
            .read()
            .await
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    uptime_s: u64,
    offline: bool,
    cpu_pct: f64,
    rss_mb: u64,
    events_per_sec: u64,
    rb_overflows: u64,
    rate_limited: u64,
    kernel_version: String,
    aya_version: String,
    transport: &'static str,
    active_rules: usize,
    top_rss: Vec<TopRssEntry>,
    top_cpu: Vec<TopCpuEntry>,
    probes: StatusProbeState,
    reasoner: ReasonerStatus,
}

#[derive(Serialize)]
struct StatusProbeState {
    rss_probe: String,
    btf: bool,
}

#[derive(Serialize)]
struct ReasonerStatus {
    configured: bool,
    endpoint: Option<String>,
    ilm_enabled: bool,
    ilm_disabled_reason: Option<String>,
    window_seconds: u64,
    timeout_ms: u64,
    min_eps_to_enable: u64,
    topk_kb: usize,
    tools_enabled: bool,
    ilm_windows: u64,
    ilm_timeouts: u64,
    ilm_insights: u64,
    ilm_schema_errors: u64,
}

async fn status_handler(State(app_state): State<Arc<AppState>>) -> Json<StatusResponse> {
    use procfs::{page_size, process::Process, ticks_per_second};

    let metrics = &app_state.metrics;
    let uptime = metrics.uptime_seconds();

    let mut cpu_pct = 0.0;
    let mut rss_mb = 0u64;

    if let Ok(proc) = Process::myself()
        && let Ok(stat) = proc.stat()
    {
        let total_time = stat.utime + stat.stime;
        let ticks = ticks_per_second() as f64;
        if uptime > 0 {
            cpu_pct = (total_time as f64 / ticks) / uptime as f64 * 100.0;
        }
        let page_kb = page_size() / 1024;
        rss_mb = stat.rss * page_kb / 1024;
    }

    let reasoner_cfg = &app_state.reasoner;
    let top_rss = app_state
        .context
        .top_rss_processes(5)
        .into_iter()
        .map(|proc| TopRssEntry {
            pid: proc.pid,
            comm: proc.comm,
            mem_percent: proc.mem_percent,
        })
        .collect();
    let top_cpu = app_state
        .context
        .top_cpu_processes(5)
        .into_iter()
        .map(|proc| TopCpuEntry {
            pid: proc.pid,
            comm: proc.comm,
            cpu_percent: proc.mem_percent, // mem_percent field holds CPU value
        })
        .collect();
    let reasoner = ReasonerStatus {
        configured: reasoner_cfg.enabled,
        endpoint: if reasoner_cfg.endpoint.is_empty() {
            None
        } else {
            Some(reasoner_cfg.endpoint.clone())
        },
        ilm_enabled: metrics.ilm_enabled(),
        ilm_disabled_reason: metrics.ilm_disabled_reason(),
        window_seconds: reasoner_cfg.window_seconds,
        timeout_ms: reasoner_cfg.timeout_ms,
        min_eps_to_enable: reasoner_cfg.min_eps_to_enable,
        topk_kb: reasoner_cfg.topk_kb,
        tools_enabled: reasoner_cfg.tools_enabled,
        ilm_windows: metrics.ilm_windows(),
        ilm_timeouts: metrics.ilm_timeouts(),
        ilm_insights: metrics.ilm_insights(),
        ilm_schema_errors: metrics.ilm_schema_errors(),
    };

    let resp = StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        uptime_s: uptime,
        offline: app_state.offline.is_offline(),
        cpu_pct,
        rss_mb,
        events_per_sec: metrics.events_per_sec(),
        rb_overflows: metrics.rb_overflows(),
        rate_limited: metrics.rate_limited_events(),
        kernel_version: kernel_version_string(),
        aya_version: aya_version_string(),
        transport: app_state.transport,
        active_rules: metrics.active_rules(),
        top_rss,
        top_cpu,
        probes: StatusProbeState {
            rss_probe: app_state.probe_state.rss_probe.as_str().to_string(),
            btf: app_state.probe_state.btf_available,
        },
        reasoner,
    };
    Json(resp)
}

async fn get_context_route(State(app_state): State<Arc<AppState>>) -> Json<Vec<ProcessInfo>> {
    let ctx = &app_state.context;
    let events = ctx.get_recent();
    let data: Vec<ProcessInfo> = events
        .into_iter()
        .map(|e| ProcessInfo {
            pid: e.pid,
            ppid: e.ppid,
            uid: e.uid,
            gid: e.gid,
            comm: String::from_utf8_lossy(&e.comm)
                .trim_end_matches('\0')
                .to_string(),
            event_type: e.event_type.into(),
            cpu_pct: e.cpu_percent(),
            mem_pct: e.mem_percent(),
            age_sec: calculate_age_sec(e.ts_ns),
            state: Some(process_state_str(e.event_type, e.exit_time_ns)),
        })
        .collect();
    Json(data)
}

#[derive(Deserialize)]
struct ProcessesQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    sort: Option<String>,
}

fn calculate_age_sec(ts_ns: u64) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos() as u64;
    if ts_ns > 0 && now > ts_ns {
        Some((now - ts_ns) / 1_000_000_000)
    } else {
        None
    }
}

fn process_state_str(event_type: u32, exit_time_ns: u64) -> String {
    if exit_time_ns > 0 {
        "exited".to_string()
    } else {
        match event_type {
            0 => "exec".to_string(),
            1 => "fork".to_string(),
            _ => "running".to_string(),
        }
    }
}

async fn get_processes(
    State(app_state): State<Arc<AppState>>,
    Query(query): Query<ProcessesQuery>,
) -> Json<Vec<ProcessInfo>> {
    let ctx = &app_state.context;
    let snapshots = ctx.live_snapshot();
    let mut data: Vec<ProcessInfo> = snapshots
        .into_iter()
        .map(|e| ProcessInfo {
            pid: e.pid,
            ppid: e.ppid,
            uid: e.uid,
            gid: e.gid,
            comm: String::from_utf8_lossy(&e.comm)
                .trim_end_matches('\0')
                .to_string(),
            event_type: e.event_type.into(),
            cpu_pct: e.cpu_percent(),
            mem_pct: e.mem_percent(),
            age_sec: calculate_age_sec(e.ts_ns),
            state: Some(process_state_str(e.event_type, e.exit_time_ns)),
        })
        .collect();

    // Apply filtering if specified
    if let Some(filter) = query.filter {
        // Simple filter: cpu_pct>10 or mem_pct>50
        if let Some(threshold_str) = filter.strip_prefix("cpu_pct>") {
            if let Ok(threshold) = threshold_str.parse::<f32>() {
                data.retain(|p| p.cpu_pct.unwrap_or(0.0) > threshold);
            }
        } else if let Some(threshold_str) = filter.strip_prefix("mem_pct>")
            && let Ok(threshold) = threshold_str.parse::<f32>()
        {
            data.retain(|p| p.mem_pct.unwrap_or(0.0) > threshold);
        }
    }

    // Apply sorting if specified
    if let Some(sort) = query.sort {
        if sort == "cpu_pct:desc" {
            data.sort_by(|a, b| {
                b.cpu_pct
                    .unwrap_or(0.0)
                    .partial_cmp(&a.cpu_pct.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        } else if sort == "mem_pct:desc" {
            data.sort_by(|a, b| {
                b.mem_pct
                    .unwrap_or(0.0)
                    .partial_cmp(&a.mem_pct.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
    }

    Json(data)
}

async fn get_process_by_pid(
    State(app_state): State<Arc<AppState>>,
    Path(pid): Path<u32>,
) -> impl IntoResponse {
    let ctx = &app_state.context;
    if let Some(e) = ctx.get_process_by_pid(pid) {
        let info = ProcessInfo {
            pid: e.pid,
            ppid: e.ppid,
            uid: e.uid,
            gid: e.gid,
            comm: String::from_utf8_lossy(&e.comm)
                .trim_end_matches('\0')
                .to_string(),
            event_type: e.event_type.into(),
            cpu_pct: e.cpu_percent(),
            mem_pct: e.mem_percent(),
            age_sec: calculate_age_sec(e.ts_ns),
            state: Some(process_state_str(e.event_type, e.exit_time_ns)),
        };
        (axum::http::StatusCode::OK, Json(info)).into_response()
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Not found"})),
        )
            .into_response()
    }
}

async fn get_by_ppid(
    State(app_state): State<Arc<AppState>>,
    Path(ppid): Path<u32>,
) -> Json<Vec<ProcessInfo>> {
    let ctx = &app_state.context;
    let matches = ctx
        .live_snapshot()
        .into_iter()
        .filter(|e| e.ppid == ppid)
        .map(|e| ProcessInfo {
            pid: e.pid,
            ppid: e.ppid,
            uid: e.uid,
            gid: e.gid,
            comm: String::from_utf8_lossy(&e.comm)
                .trim_end_matches('\0')
                .to_string(),
            event_type: e.event_type.into(),
            cpu_pct: e.cpu_percent(),
            mem_pct: e.mem_percent(),
            age_sec: calculate_age_sec(e.ts_ns),
            state: Some(process_state_str(e.event_type, e.exit_time_ns)),
        })
        .collect();
    Json(matches)
}

async fn get_graph(
    State(app_state): State<Arc<AppState>>,
    Path(pid): Path<u32>,
) -> impl IntoResponse {
    let ctx = &app_state.context;
    let live = ctx.get_live_map();
    let mut nodes = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if let Some(proc) = live.get(&pid) {
        // Add self
        nodes.push(GraphNode {
            pid: proc.pid,
            ppid: proc.ppid,
            comm: String::from_utf8_lossy(&proc.comm)
                .trim_end_matches('\0')
                .to_string(),
            uid: proc.uid,
            gid: proc.gid,
            event_type: proc.event_type.into(),
            relationship: "self".to_string(),
            level: 0,
        });
        seen.insert(proc.pid);

        // Add ancestor chain (or virtual root if parent not found)
        let mut level = -1isize;
        let mut current_pid = proc.ppid;
        let mut parent_found = false;
        while current_pid != 0 && current_pid != pid && !seen.contains(&current_pid) {
            if let Some(parent) = live.get(&current_pid) {
                nodes.push(GraphNode {
                    pid: parent.pid,
                    ppid: parent.ppid,
                    comm: String::from_utf8_lossy(&parent.comm)
                        .trim_end_matches('\0')
                        .to_string(),
                    uid: parent.uid,
                    gid: parent.gid,
                    event_type: parent.event_type.into(),
                    relationship: "ancestor".to_string(),
                    level,
                });
                seen.insert(parent.pid);
                current_pid = parent.ppid;
                level -= 1;
                parent_found = true;
            } else {
                break;
            }
        }
        // If parent not found, add virtual root
        if !parent_found && proc.ppid != 0 {
            nodes.push(GraphNode {
                pid: proc.ppid,
                ppid: 0,
                comm: "".to_string(),
                uid: 0,
                gid: 0,
                event_type: EventKind::Unknown,
                relationship: "virtual_root".to_string(),
                level: -1,
            });
        }

        // Add siblings
        for sibling in live.values() {
            if sibling.ppid == proc.ppid && sibling.pid != pid && !seen.contains(&sibling.pid) {
                nodes.push(GraphNode {
                    pid: sibling.pid,
                    ppid: sibling.ppid,
                    comm: String::from_utf8_lossy(&sibling.comm)
                        .trim_end_matches('\0')
                        .to_string(),
                    uid: sibling.uid,
                    gid: sibling.gid,
                    event_type: sibling.event_type.into(),
                    relationship: "sibling".to_string(),
                    level: 0,
                });
                seen.insert(sibling.pid);
            }
        }

        // Add descendants
        fn collect_descendants(
            pid: u32,
            live: &std::collections::HashMap<u32, ProcessEvent>,
            seen: &mut std::collections::HashSet<u32>,
            nodes: &mut Vec<GraphNode>,
            level: isize,
        ) {
            for proc in live.values() {
                if proc.ppid == pid && seen.insert(proc.pid) {
                    nodes.push(GraphNode {
                        pid: proc.pid,
                        ppid: proc.ppid,
                        comm: String::from_utf8_lossy(&proc.comm)
                            .trim_end_matches('\0')
                            .to_string(),
                        uid: proc.uid,
                        gid: proc.gid,
                        event_type: proc.event_type.into(),
                        relationship: "descendant".to_string(),
                        level,
                    });
                    collect_descendants(proc.pid, live, seen, nodes, level + 1);
                }
            }
        }
        collect_descendants(pid, &live, &mut seen, &mut nodes, 1);

        (StatusCode::OK, Json(GraphResponse { root: pid, nodes })).into_response()
    } else {
        // If not found as PID, but is a PPID, show virtual root and descendants
        let has_children = live.values().any(|proc| proc.ppid == pid);
        if has_children {
            nodes.push(GraphNode {
                pid,
                ppid: 0,
                comm: "".to_string(),
                uid: 0,
                gid: 0,
                event_type: EventKind::Unknown,
                relationship: "virtual_root".to_string(),
                level: 0,
            });
            seen.insert(pid);

            fn collect_descendants(
                pid: u32,
                live: &std::collections::HashMap<u32, ProcessEvent>,
                seen: &mut std::collections::HashSet<u32>,
                nodes: &mut Vec<GraphNode>,
                level: isize,
            ) {
                for proc in live.values() {
                    if proc.ppid == pid && seen.insert(proc.pid) {
                        nodes.push(GraphNode {
                            pid: proc.pid,
                            ppid: proc.ppid,
                            comm: String::from_utf8_lossy(&proc.comm)
                                .trim_end_matches('\0')
                                .to_string(),
                            uid: proc.uid,
                            gid: proc.gid,
                            event_type: proc.event_type.into(),
                            relationship: "descendant".to_string(),
                            level,
                        });
                        collect_descendants(proc.pid, live, seen, nodes, level + 1);
                    }
                }
            }
            collect_descendants(pid, &live, &mut seen, &mut nodes, 1);

            (StatusCode::OK, Json(GraphResponse { root: pid, nodes })).into_response()
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "PID not found" })),
            )
                .into_response()
        }
    }
}

pub async fn stream_events(
    State(app_state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let ctx = &app_state.context;
    let rx = ctx.broadcaster().subscribe();
    let metrics = Arc::clone(&app_state.metrics);
    metrics.subscribers.fetch_add(1, Ordering::Relaxed);
    let metrics_clone = metrics.clone();

    let event_stream = BroadcastStream::new(rx).filter_map(move |msg| {
        let metrics = metrics_clone.clone();
        async move {
            match msg {
                Ok(event) => {
                    let event_type_name = match event.event_type {
                        0 => "exec",
                        1 => "fork",
                        2 => "exit",
                        3 => "net",
                        4 => "fileio",
                        5 => "syscall",
                        6 => "blockio",
                        7 => "pagefault",
                        _ => "unknown",
                    }
                    .to_string();

                    let sse_event = ProcessEventSse {
                        pid: event.pid,
                        ppid: event.ppid,
                        uid: event.uid,
                        gid: event.gid,
                        comm: String::from_utf8_lossy(&event.comm)
                            .trim_end_matches('\0')
                            .to_string(),
                        event_type: event.event_type,
                        event_type_name,
                        ts_ns: event.ts_ns,
                        seq: event.seq,
                        exit_time_ns: event.exit_time_ns,
                        cpu_pct_milli: event.cpu_pct_milli,
                        mem_pct_milli: event.mem_pct_milli,
                        data: event.data,
                        data2: event.data2,
                        aux: event.aux,
                        aux2: event.aux2,
                    };
                    let json = to_string(&sse_event).unwrap();
                    Some(Ok(Event::default().data(json)))
                }
                Err(BroadcastStreamRecvError::Lagged(n)) => {
                    log::warn!("dropped {n} events (broadcast lag)");
                    metrics.dropped_events_total.fetch_add(n, Ordering::Relaxed);
                    None
                }
            }
        }
    });

    let keepalive = IntervalStream::new(tokio::time::interval(Duration::from_secs(10)))
        .map(|_| Ok(Event::default().comment("keep-alive")));

    #[cfg(feature = "fake-events")]
    let event_stream = futures_util::stream::select(event_stream, fake_events::sse_stream());

    let merged = futures_util::stream::select(event_stream, keepalive);

    struct SubscriberGuard {
        metrics: Arc<Metrics>,
    }

    impl Drop for SubscriberGuard {
        fn drop(&mut self) {
            self.metrics.subscribers.fetch_sub(1, Ordering::Relaxed);
        }
    }

    let guard = SubscriberGuard { metrics };

    let stream = merged.inspect(move |_| {
        let _ = &guard;
    });

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keep-alive"),
    )
}

pub async fn stream_alerts(
    State(app_state): State<Arc<AppState>>,
) -> Sse<BoxStream<'static, Result<Event, std::convert::Infallible>>> {
    // Heartbeat every 10s
    let keepalive = IntervalStream::new(tokio::time::interval(Duration::from_secs(10)))
        .map(|_| Ok(Event::default().comment("keep-alive")));

    // Subscribe to real alerts if available; otherwise use a dummy channel
    let rx = if let Some(tx) = &app_state.alerts {
        tx.subscribe()
    } else {
        let (_dummy_tx, dummy_rx) = broadcast::channel::<Alert>(1);
        dummy_rx
    };

    // Convert alerts to SSE events
    let alert_stream = BroadcastStream::new(rx).filter_map(|msg| async move {
        match msg {
            Ok(alert) => {
                let json = to_string(&alert).unwrap();
                Some(Ok(Event::default().event("alert").data(json)))
            }
            // Ignore lagged messages; no `Closed` variant in this version
            Err(BroadcastStreamRecvError::Lagged(_)) => None,
        }
    });

    // Merge alerts with keepalives and box the stream type
    let combined: BoxStream<Result<Event, std::convert::Infallible>> =
        futures_util::stream::select(alert_stream, keepalive).boxed();

    Sse::new(combined)
}

pub async fn stream_processes_live(
    State(app_state): State<Arc<AppState>>,
) -> Sse<BoxStream<'static, Result<Event, std::convert::Infallible>>> {
    let ctx = Arc::clone(&app_state.context);

    // Send process list every 2 seconds
    let process_stream =
        IntervalStream::new(tokio::time::interval(Duration::from_secs(2))).map(move |_| {
            let snapshots = ctx.live_snapshot();
            let data: Vec<ProcessInfo> = snapshots
                .into_iter()
                .map(|e| ProcessInfo {
                    pid: e.pid,
                    ppid: e.ppid,
                    uid: e.uid,
                    gid: e.gid,
                    comm: String::from_utf8_lossy(&e.comm)
                        .trim_end_matches('\0')
                        .to_string(),
                    event_type: e.event_type.into(),
                    cpu_pct: e.cpu_percent(),
                    mem_pct: e.mem_percent(),
                    age_sec: calculate_age_sec(e.ts_ns),
                    state: Some(process_state_str(e.event_type, e.exit_time_ns)),
                })
                .collect();

            let json = to_string(&json!({ "event": "update", "processes": data })).unwrap();
            Ok(Event::default().event("processes").data(json))
        });

    // Heartbeat every 10s
    let keepalive = IntervalStream::new(tokio::time::interval(Duration::from_secs(10)))
        .map(|_| Ok(Event::default().comment("keep-alive")));

    // Merge process updates with keepalives
    let combined: BoxStream<Result<Event, std::convert::Infallible>> =
        futures_util::stream::select(process_stream, keepalive).boxed();

    Sse::new(combined)
}

pub async fn system_snapshot(State(app_state): State<Arc<AppState>>) -> Json<SystemSnapshot> {
    let ctx = &app_state.context;
    let snapshot = ctx.get_system_snapshot();
    Json(snapshot)
}

// Query parameters for timeline endpoint
#[derive(Deserialize)]
struct TimelineQuery {
    #[serde(default)]
    start: Option<u64>,
    #[serde(default)]
    end: Option<u64>,
    #[serde(default)]
    severity: Option<String>,
}

// GET /api/timeline - Get alert history
async fn get_timeline(
    State(app_state): State<Arc<AppState>>,
    Query(query): Query<TimelineQuery>,
) -> Json<Vec<AlertRecord>> {
    let mut alerts = app_state.alert_history.get_all().await;

    // Filter by time range
    if let Some(start) = query.start {
        alerts.retain(|a| a.timestamp >= start);
    }
    if let Some(end) = query.end {
        alerts.retain(|a| a.timestamp <= end);
    }

    // Filter by severity
    if let Some(severity) = query.severity {
        let severity_lower = severity.to_lowercase();
        alerts.retain(|a| a.severity.to_lowercase() == severity_lower);
    }

    // Sort by timestamp descending (newest first)
    alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Limit to 1000 results
    alerts.truncate(1000);

    Json(alerts)
}

// GET /api/alerts/:id - Get alert details by ID
async fn get_alert_by_id(
    State(app_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(alert) = app_state.alert_history.get_by_id(&id).await {
        // Create detailed response with additional fields
        let detail = AlertDetail {
            id: alert.id.clone(),
            timestamp: alert.timestamp,
            severity: alert.severity.clone(),
            rule: alert.rule.clone(),
            message: alert.message.clone(),
            host: alert.host.clone(),
            explanation: format!("Alert triggered by rule: {}", alert.rule),
            remediation: generate_remediation(&alert.rule, &alert.message),
        };
        (StatusCode::OK, Json(detail)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Alert not found"})),
        )
            .into_response()
    }
}

// Helper function to generate remediation suggestions
fn generate_remediation(rule: &str, message: &str) -> String {
    match rule {
        r if r.contains("fork") => {
            "Identify and terminate the process causing excessive forks. Use 'kill -9 <pid>' or set process limits with ulimit.".to_string()
        }
        r if r.contains("cpu") => {
            "Investigate high CPU usage. Check process with 'top' or 'htop', consider restarting or throttling the process.".to_string()
        }
        r if r.contains("memory") || r.contains("rss") => {
            "Monitor memory usage. Check for memory leaks, restart the process, or increase available memory.".to_string()
        }
        _ => {
            format!("Review alert message: {}", message)
        }
    }
}

// GET /api/metrics/system - Get current system metrics
async fn get_system_metrics(State(app_state): State<Arc<AppState>>) -> Json<SystemMetrics> {
    let ctx = &app_state.context;
    let snapshot = ctx.get_system_snapshot();

    // Get CPU from system snapshot
    let cpu_total_pct = snapshot.cpu_percent;

    // Use sysinfo to get detailed system metrics
    let mut sys = System::new_all();
    sys.refresh_all();

    let memory_total_mb = sys.total_memory() / 1024 / 1024;
    let memory_used_mb = sys.used_memory() / 1024 / 1024;

    // Get process count from context
    let processes_total = ctx.live_snapshot().len();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Json(SystemMetrics {
        cpu_total_pct,
        memory_total_mb,
        memory_used_mb,
        processes_total,
        timestamp,
    })
}

fn generate_alerts(ctx: &ContextStore) -> Vec<ProcessAlert> {
    let processes = ctx.live_snapshot();
    let mut alerts = Vec::new();

    for proc in processes {
        let comm = String::from_utf8_lossy(&proc.comm)
            .trim_end_matches('\0')
            .to_string();

        // Alert rules based on CPU/memory thresholds only
        let mut reasons = Vec::new();
        if proc.cpu_percent().unwrap_or(0.0) > 50.0 {
            reasons.push("High CPU usage");
        }
        if proc.mem_percent().unwrap_or(0.0) > 30.0 {
            reasons.push("High memory usage");
        }

        if !reasons.is_empty() {
            alerts.push(ProcessAlert {
                pid: proc.pid,
                comm,
                cpu_percent: proc.cpu_percent(),
                mem_percent: proc.mem_percent(),
                event_type: proc.event_type,
                reason: reasons.join(", "),
            });
        }
    }
    alerts
}

#[allow(dead_code)]
pub async fn get_alerts(State(app_state): State<Arc<AppState>>) -> Json<Vec<ProcessAlert>> {
    let ctx = &app_state.context;
    let alerts = generate_alerts(ctx);
    Json(alerts)
}

#[derive(Serialize)]
#[allow(dead_code)]
struct InsightsRequest {
    system: SystemSnapshot,
    alerts: Vec<ProcessAlert>,
}

#[derive(Deserialize, Serialize)]
#[allow(dead_code)]
struct InsightsResponse {
    summary: String,
    risks: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct RecentInsightsQuery {
    #[serde(default = "default_recent_insights_limit")]
    limit: usize,
}

fn default_recent_insights_limit() -> usize {
    20
}

pub async fn get_recent_insights(
    State(app_state): State<Arc<AppState>>,
    Query(query): Query<RecentInsightsQuery>,
) -> Json<Vec<InsightRecord>> {
    let limit = query.limit.clamp(1, 200);
    let records = app_state.insights.recent(limit);
    Json(records)
}

pub async fn get_insights(
    State(app_state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !app_state.offline.check("insights") {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let ctx = &app_state.context;

    // Update system snapshot on-demand for insights (critical for LLM analysis)
    ctx.update_system_snapshot();
    ctx.update_process_stats();

    // Fetch system state
    let system = ctx.get_system_snapshot();
    // Fetch alerts (limit to top 5 for prompt brevity)
    let mut alerts = generate_alerts(ctx);
    alerts.truncate(5); // Only include first 5 alerts to keep prompt short

    // Get top processes by CPU and memory
    let top_cpu = ctx.top_cpu_processes(5);
    let top_rss = ctx.top_rss_processes(5);

    // Create a concise summary instead of full JSON dump
    let alert_summary = if alerts.is_empty() {
        "No active alerts".to_string()
    } else {
        alerts
            .iter()
            .map(|a| format!("{}: {}", a.comm, a.reason))
            .collect::<Vec<_>>()
            .join("; ")
    };

    // Build top CPU summary
    let top_cpu_summary = if top_cpu.is_empty() {
        "No CPU data available".to_string()
    } else {
        top_cpu
            .iter()
            .map(|p| format!("{} ({:.1}%)", p.comm, p.mem_percent)) // mem_percent holds CPU value
            .collect::<Vec<_>>()
            .join(", ")
    };

    // Build top memory summary
    let top_mem_summary = if top_rss.is_empty() {
        "No memory data available".to_string()
    } else {
        top_rss
            .iter()
            .map(|p| format!("{} ({:.1}%)", p.comm, p.mem_percent))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let prompt = format!(
        "System Health Analysis:\n\
         CPU: {:.1}% | Memory: {:.1}% | Load Avg: [{:.2}, {:.2}, {:.2}]\n\
         Top CPU Consumers: {}\n\
         Top Memory Consumers: {}\n\
         Alerts: {}\n\n\
         Analyze the system state and provide: 1) Overall health assessment, 2) Key risks or anomalies, 3) Recommended actions.",
        system.cpu_percent,
        system.mem_percent,
        system.load_avg[0],
        system.load_avg[1],
        system.load_avg[2],
        top_cpu_summary,
        top_mem_summary,
        alert_summary
    );

    // Call LLM - supports both local models and OpenAI
    // Default to local Linnix model if available
    let model = std::env::var("LLM_MODEL").unwrap_or_else(|_| "linnix-3b-distilled".to_string());
    let llm_endpoint = std::env::var("LLM_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:8090/v1/chat/completions".to_string());

    // API key is optional for local models
    let api_key =
        std::env::var("OPENAI_API_KEY").unwrap_or_else(|_| "not-needed-for-local".to_string());

    log::info!(
        "[insights] Using LLM endpoint: {} with model: {}",
        llm_endpoint,
        model
    );
    let req_body = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are an infrastructure monitoring assistant. Summarize Linux system health and risks for operators in clear, concise language."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 200  // Limit response for faster generation on CPU
    });

    let client = Client::new();
    let res = client
        .post(&llm_endpoint)
        .bearer_auth(api_key)
        .json(&req_body)
        .timeout(std::time::Duration::from_secs(120)) // 2 minutes for CPU inference
        .send()
        .await
        .map_err(|e| {
            log::error!("[insights] LLM request failed: {}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Check HTTP status code
    let status = res.status();
    if !status.is_success() {
        let error_text = res
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        log::error!(
            "[insights] LLM returned error status {}: {}",
            status,
            error_text
        );
        let output = serde_json::json!({
            "summary": format!("LLM API error: HTTP {}", status),
            "risks": []
        });
        return Ok(Json(output));
    }

    let resp_json: serde_json::Value = res.json().await.map_err(|e| {
        log::error!("[insights] Failed to parse LLM response as JSON: {}", e);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    log::debug!("[insights] LLM response: {:?}", resp_json);

    // Extract the summary from the response (supports both OpenAI and local formats)
    let summary = resp_json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_else(|| {
            log::warn!("[insights] Could not extract content from LLM response");
            "LLM response format error"
        })
        .to_string();

    // Build structured response with metrics and top processes
    let top_cpu_data: Vec<serde_json::Value> = top_cpu
        .iter()
        .map(|p| {
            serde_json::json!({
                "pid": p.pid,
                "comm": p.comm,
                "cpu_percent": format!("{:.1}", p.mem_percent) // mem_percent field holds CPU value
            })
        })
        .collect();

    let top_rss_data: Vec<serde_json::Value> = top_rss
        .iter()
        .map(|p| {
            serde_json::json!({
                "pid": p.pid,
                "comm": p.comm,
                "mem_percent": format!("{:.1}", p.mem_percent)
            })
        })
        .collect();

    let alerts_data: Vec<serde_json::Value> = alerts
        .iter()
        .map(|a| {
            serde_json::json!({
                "comm": a.comm,
                "reason": a.reason,
                "pid": a.pid
            })
        })
        .collect();

    let output = serde_json::json!({
        "summary": summary,
        "metrics": {
            "cpu_percent": format!("{:.1}", system.cpu_percent),
            "mem_percent": format!("{:.1}", system.mem_percent),
            "load_avg": [
                format!("{:.2}", system.load_avg[0]),
                format!("{:.2}", system.load_avg[1]),
                format!("{:.2}", system.load_avg[2])
            ]
        },
        "top_cpu": top_cpu_data,
        "top_memory": top_rss_data,
        "alerts": alerts_data,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });

    Ok(Json(output))
}

pub async fn healthz() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn get_insight_schema_route() -> Json<Value> {
    Json(insight_json_schema().clone())
}

async fn get_actions(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<crate::enforcement::EnforcementAction>> {
    if let Some(queue) = &state.enforcement {
        let all = queue.get_all().await;
        Json(all)
    } else {
        Json(vec![])
    }
}

async fn get_action_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<crate::enforcement::EnforcementAction>, StatusCode> {
    if let Some(queue) = &state.enforcement {
        queue
            .get_by_id(&id)
            .await
            .map(Json)
            .ok_or(StatusCode::NOT_FOUND)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
struct ApprovalRequest {
    approver: String,
}

async fn approve_action(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ApprovalRequest>,
) -> Result<Json<crate::enforcement::EnforcementAction>, StatusCode> {
    if let Some(queue) = &state.enforcement {
        queue
            .approve(&id, req.approver)
            .await
            .map(Json)
            .map_err(|_| StatusCode::BAD_REQUEST)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn reject_action(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ApprovalRequest>,
) -> Result<StatusCode, StatusCode> {
    if let Some(queue) = &state.enforcement {
        queue
            .reject(&id, req.approver)
            .await
            .map(|_| StatusCode::OK)
            .map_err(|_| StatusCode::BAD_REQUEST)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Serialize)]
struct DropBreakdown {
    event_type: u32,
    drops: u64,
}

#[derive(Serialize)]
pub struct MetricsResponse {
    cpu_percent: f32,
    rss: u64,
    subscribers: usize,
    queue_depth: usize,
    dropped_events_total: u64,
    alerts_active: usize,
    uptime_seconds: u64,
    events_per_sec: u64,
    perf_poll_errors: u64,
    rate_limited: u64,
    alerts_emitted: u64,
    lineage_hits: u64,
    lineage_misses: u64,
    drops_by_type: Vec<DropBreakdown>,
    rss_probe_mode: String,
    kernel_btf_available: bool,
    ilm_windows: u64,
    ilm_timeouts: u64,
    ilm_insights: u64,
    ilm_schema_errors: u64,
    ilm_enabled: bool,
    ilm_disabled_reason: Option<String>,
}

pub async fn prometheus_metrics(State(app_state): State<Arc<AppState>>) -> Response {
    if !app_state.prometheus_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let metrics = &app_state.metrics;

    let events_total = metrics.events_total.load(Ordering::Relaxed);
    let dropped_total = metrics.dropped_events_total.load(Ordering::Relaxed);
    let alerts_emitted = metrics.alerts_emitted();
    let rb_overflows = metrics.rb_overflows();
    let rate_limited = metrics.rate_limited_events();
    let perf_errors = metrics.perf_poll_errors();
    let subscribers = metrics.subscribers.load(Ordering::Relaxed);
    let alerts_active = metrics.alerts_active.load(Ordering::Relaxed);
    let events_per_sec = metrics.events_per_sec();
    let uptime_seconds = metrics.uptime_seconds();
    let queue_depth = app_state.context.queue_depth() as u64;
    let lineage_hits = metrics.lineage_hits();
    let lineage_misses = metrics.lineage_misses();
    let ilm_windows = metrics.ilm_windows();
    let ilm_timeouts = metrics.ilm_timeouts();
    let ilm_insights = metrics.ilm_insights();
    let ilm_schema_errors = metrics.ilm_schema_errors();
    let ilm_enabled = metrics.ilm_enabled();
    let kernel_btf_available = if metrics.kernel_btf_available() { 1 } else { 0 };
    let rss_probe_mode = metrics.rss_probe_mode();

    let mut sys = System::new_all();
    sys.refresh_all();
    let pid = Pid::from_u32(std::process::id());
    let (proc_cpu_percent, proc_rss_bytes) = if let Some(proc) = sys.process(pid) {
        (proc.cpu_usage(), proc.memory() * 1024)
    } else {
        (0.0, 0)
    };

    let mut body = String::new();

    let _ = writeln!(
        body,
        "# HELP linnix_events_total Total process events received."
    );
    let _ = writeln!(body, "# TYPE linnix_events_total counter");
    let _ = writeln!(body, "linnix_events_total {}", events_total);

    let _ = writeln!(
        body,
        "# HELP linnix_events_per_second Approximate events per second over the last second."
    );
    let _ = writeln!(body, "# TYPE linnix_events_per_second gauge");
    let _ = writeln!(body, "linnix_events_per_second {}", events_per_sec);

    let _ = writeln!(body, "# HELP linnix_alerts_active Current active alerts.");
    let _ = writeln!(body, "# TYPE linnix_alerts_active gauge");
    let _ = writeln!(body, "linnix_alerts_active {}", alerts_active);

    let _ = writeln!(
        body,
        "# HELP linnix_alerts_emitted_total Total alerts emitted."
    );
    let _ = writeln!(body, "# TYPE linnix_alerts_emitted_total counter");
    let _ = writeln!(body, "linnix_alerts_emitted_total {}", alerts_emitted);

    let _ = writeln!(
        body,
        "# HELP linnix_dropped_events_total Total events dropped (sampling/backpressure)."
    );
    let _ = writeln!(body, "# TYPE linnix_dropped_events_total counter");
    let _ = writeln!(body, "linnix_dropped_events_total {}", dropped_total);

    let _ = writeln!(
        body,
        "# HELP linnix_ringbuf_overflows_total Total ring buffer overflows observed."
    );
    let _ = writeln!(body, "# TYPE linnix_ringbuf_overflows_total counter");
    let _ = writeln!(body, "linnix_ringbuf_overflows_total {}", rb_overflows);

    let _ = writeln!(
        body,
        "# HELP linnix_rate_limited_total Events skipped due to configured rate caps."
    );
    let _ = writeln!(body, "# TYPE linnix_rate_limited_total counter");
    let _ = writeln!(body, "linnix_rate_limited_total {}", rate_limited);

    let _ = writeln!(
        body,
        "# HELP linnix_perf_poll_errors_total Perf buffer polling errors."
    );
    let _ = writeln!(body, "# TYPE linnix_perf_poll_errors_total counter");
    let _ = writeln!(body, "linnix_perf_poll_errors_total {}", perf_errors);

    let _ = writeln!(body, "# HELP linnix_lineage_hits_total Lineage cache hits.");
    let _ = writeln!(body, "# TYPE linnix_lineage_hits_total counter");
    let _ = writeln!(body, "linnix_lineage_hits_total {}", lineage_hits);

    let _ = writeln!(
        body,
        "# HELP linnix_lineage_misses_total Lineage cache misses."
    );
    let _ = writeln!(body, "# TYPE linnix_lineage_misses_total counter");
    let _ = writeln!(body, "linnix_lineage_misses_total {}", lineage_misses);

    let _ = writeln!(
        body,
        "# HELP linnix_context_queue_depth Current context queue backlog."
    );
    let _ = writeln!(body, "# TYPE linnix_context_queue_depth gauge");
    let _ = writeln!(body, "linnix_context_queue_depth {}", queue_depth);

    let _ = writeln!(body, "# HELP linnix_subscribers Number of SSE subscribers.");
    let _ = writeln!(body, "# TYPE linnix_subscribers gauge");
    let _ = writeln!(body, "linnix_subscribers {}", subscribers);

    let _ = writeln!(
        body,
        "# HELP linnix_uptime_seconds Cognitod uptime in seconds."
    );
    let _ = writeln!(body, "# TYPE linnix_uptime_seconds gauge");
    let _ = writeln!(body, "linnix_uptime_seconds {}", uptime_seconds);

    let _ = writeln!(
        body,
        "# HELP linnix_kernel_btf_available Kernel BTF availability (1=yes)."
    );
    let _ = writeln!(body, "# TYPE linnix_kernel_btf_available gauge");
    let _ = writeln!(body, "linnix_kernel_btf_available {}", kernel_btf_available);

    let _ = writeln!(
        body,
        "# HELP linnix_rss_probe_mode RSS probe operating mode (numeric enum)."
    );
    let _ = writeln!(body, "# TYPE linnix_rss_probe_mode gauge");
    let _ = writeln!(body, "linnix_rss_probe_mode {}", rss_probe_mode);

    let _ = writeln!(
        body,
        "# HELP linnix_process_cpu_percent Cognitod process CPU usage percentage."
    );
    let _ = writeln!(body, "# TYPE linnix_process_cpu_percent gauge");
    let _ = writeln!(body, "linnix_process_cpu_percent {}", proc_cpu_percent);

    let _ = writeln!(
        body,
        "# HELP linnix_process_rss_bytes Cognitod process RSS in bytes."
    );
    let _ = writeln!(body, "# TYPE linnix_process_rss_bytes gauge");
    let _ = writeln!(body, "linnix_process_rss_bytes {}", proc_rss_bytes);

    let _ = writeln!(
        body,
        "# HELP linnix_ilm_windows_total ILM evaluation windows processed."
    );
    let _ = writeln!(body, "# TYPE linnix_ilm_windows_total counter");
    let _ = writeln!(body, "linnix_ilm_windows_total {}", ilm_windows);

    let _ = writeln!(
        body,
        "# HELP linnix_ilm_timeouts_total ILM request timeouts."
    );
    let _ = writeln!(body, "# TYPE linnix_ilm_timeouts_total counter");
    let _ = writeln!(body, "linnix_ilm_timeouts_total {}", ilm_timeouts);

    let _ = writeln!(
        body,
        "# HELP linnix_ilm_insights_total Valid insights produced."
    );
    let _ = writeln!(body, "# TYPE linnix_ilm_insights_total counter");
    let _ = writeln!(body, "linnix_ilm_insights_total {}", ilm_insights);

    let _ = writeln!(
        body,
        "# HELP linnix_ilm_schema_errors_total Insight schema repair failures."
    );
    let _ = writeln!(body, "# TYPE linnix_ilm_schema_errors_total counter");
    let _ = writeln!(body, "linnix_ilm_schema_errors_total {}", ilm_schema_errors);

    let _ = writeln!(
        body,
        "# HELP linnix_ilm_enabled ILM handler state (1=enabled)."
    );
    let _ = writeln!(body, "# TYPE linnix_ilm_enabled gauge");
    let _ = writeln!(
        body,
        "linnix_ilm_enabled {}",
        if ilm_enabled { 1 } else { 0 }
    );

    let _ = writeln!(
        body,
        "# HELP linnix_dropped_events_by_type_total Drops broken down by event type."
    );
    let _ = writeln!(body, "# TYPE linnix_dropped_events_by_type_total counter");
    for (event_type, drops) in metrics.drops_by_type() {
        let _ = writeln!(
            body,
            "linnix_dropped_events_by_type_total{{event_type=\"{}\"}} {}",
            event_type, drops
        );
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(body.into())
        .unwrap()
}

pub async fn metrics_handler(State(app_state): State<Arc<AppState>>) -> Json<MetricsResponse> {
    let mut sys = System::new_all();
    sys.refresh_all();
    let pid = Pid::from_u32(std::process::id());
    let (cpu_percent, rss) = if let Some(proc) = sys.process(pid) {
        // proc.memory() returns bytes, convert to KB for the response
        (proc.cpu_usage(), proc.memory() / 1024)
    } else {
        (0.0, 0)
    };

    let metrics = &app_state.metrics;
    let resp = MetricsResponse {
        cpu_percent,
        rss,
        subscribers: metrics.subscribers.load(Ordering::Relaxed),
        queue_depth: app_state.context.queue_depth(),
        dropped_events_total: metrics.dropped_events_total.load(Ordering::Relaxed),
        alerts_active: metrics.alerts_active.load(Ordering::Relaxed),
        uptime_seconds: metrics.uptime_seconds(),
        events_per_sec: metrics.events_per_sec(),
        perf_poll_errors: metrics.perf_poll_errors(),
        rate_limited: metrics.rate_limited_events(),
        alerts_emitted: metrics.alerts_emitted(),
        lineage_hits: metrics.lineage_hits(),
        lineage_misses: metrics.lineage_misses(),
        drops_by_type: metrics
            .drops_by_type()
            .into_iter()
            .map(|(event_type, drops)| DropBreakdown { event_type, drops })
            .collect(),
        rss_probe_mode: probe_mode_label(metrics.rss_probe_mode()).to_string(),
        kernel_btf_available: metrics.kernel_btf_available(),
        ilm_windows: metrics.ilm_windows(),
        ilm_timeouts: metrics.ilm_timeouts(),
        ilm_insights: metrics.ilm_insights(),
        ilm_schema_errors: metrics.ilm_schema_errors(),
        ilm_enabled: metrics.ilm_enabled(),
        ilm_disabled_reason: metrics.ilm_disabled_reason(),
    };
    Json(resp)
}

fn probe_mode_label(mode: u8) -> &'static str {
    match mode {
        1 => "core:signal",
        2 => "core:mm",
        3 => "tracepoint:mm/rss_stat",
        _ => "disabled",
    }
}

pub struct AppState {
    pub context: Arc<ContextStore>,
    pub metrics: Arc<Metrics>,
    pub alerts: Option<broadcast::Sender<Alert>>,
    pub insights: Arc<InsightStore>,
    pub offline: Arc<OfflineGuard>,
    pub transport: &'static str,
    pub probe_state: ProbeState,
    pub reasoner: ReasonerConfig,
    pub prometheus_enabled: bool,
    pub alert_history: Arc<AlertHistory>,
    pub auth_token: Option<String>,
    pub enforcement: Option<Arc<crate::enforcement::EnforcementQueue>>,
}

pub fn all_routes(app_state: Arc<AppState>) -> Router {
    let prometheus_enabled = app_state.prometheus_enabled;
    let auth_token = app_state.auth_token.clone();

    let mut router = Router::new()
        .route("/", get(crate::ui::dashboard_handler))
        .route("/dashboard", get(crate::ui::dashboard_handler))
        .route("/context", get(get_context_route))
        .route("/processes", get(get_processes))
        .route("/processes/live", get(stream_processes_live))
        .route("/processes/{pid}", get(get_process_by_pid))
        .route("/ppid/{ppid}", get(get_by_ppid))
        .route("/graph/{pid}", get(get_graph))
        .route("/events", get(stream_events))
        .route("/stream", get(stream_events))
        .route("/system", get(system_snapshot))
        .route("/timeline", get(get_timeline))
        .route("/metrics/system", get(get_system_metrics))
        .route("/alerts", get(stream_alerts))
        .route("/alerts/{id}", get(get_alert_by_id))
        .route("/insights", get(get_insights))
        .route("/insights/recent", get(get_recent_insights))
        .route("/metrics", get(metrics_handler))
        .route("/status", get(status_handler))
        .route("/healthz", get(healthz))
        .route("/schema/insight", get(get_insight_schema_route))
        .route("/actions", get(get_actions))
        .route("/actions/{id}", get(get_action_by_id))
        .route("/actions/{id}/approve", axum::routing::post(approve_action))
        .route("/actions/{id}/reject", axum::routing::post(reject_action));

    if prometheus_enabled {
        router = router.route("/metrics/prometheus", get(prometheus_metrics));
    }

    if auth_token.is_some() {
        router = router.layer(axum::middleware::from_fn_with_state(
            auth_token,
            auth::auth_middleware,
        ));
    }

    router.with_state(app_state)
}

const CARGO_LOCK: &str = include_str!("../../../Cargo.lock");
static AYA_VERSION: Lazy<String> =
    Lazy::new(|| dependency_version("aya").unwrap_or_else(|| "unknown".into()));

fn kernel_version_string() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn aya_version_string() -> String {
    AYA_VERSION.clone()
}

fn dependency_version(target: &str) -> Option<String> {
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in CARGO_LOCK.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if current_name.as_deref() == Some(target) {
                return current_version;
            }
            current_name = None;
            current_version = None;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("name = \"") {
            current_name = Some(rest.trim_end_matches('"').to_string());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("version = \"") {
            current_version = Some(rest.trim_end_matches('"').to_string());
        }
    }

    if current_name.as_deref() == Some(target) {
        return current_version;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insights::InsightStore;
    use crate::runtime::probes::{ProbeState, RssProbeMode};
    use crate::{PERCENT_MILLI_UNKNOWN, ProcessEvent};
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use futures_util::StreamExt;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    #[tokio::test]
    async fn heartbeats_emit_every_10s() {
        tokio::time::pause();
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let _metrics = Arc::new(Metrics::new());
        let rx = ctx.broadcaster().subscribe();

        let event_stream = BroadcastStream::new(rx).filter_map(|msg| async move {
            match msg {
                Ok(_) => Some(Ok::<Event, std::convert::Infallible>(Event::default())),
                Err(_) => None,
            }
        });
        let keepalive = IntervalStream::new(tokio::time::interval(Duration::from_secs(10)))
            .map(|_| Ok(Event::default().comment("keep-alive")));
        let merged = futures_util::stream::select(event_stream, keepalive);
        futures_util::pin_mut!(merged);

        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(merged.next().await.is_some());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(merged.next().await.is_some());
    }

    #[tokio::test]
    async fn drops_are_counted() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 100));
        let metrics = Arc::new(Metrics::new());
        let rx = ctx.broadcaster().subscribe();
        let metrics_clone = metrics.clone();
        let stream = BroadcastStream::new(rx).filter_map(move |msg| {
            let metrics = metrics_clone.clone();
            async move {
                match msg {
                    Ok(_) => Some(Ok::<Event, std::convert::Infallible>(Event::default())),
                    Err(BroadcastStreamRecvError::Lagged(n)) => {
                        metrics.dropped_events_total.fetch_add(n, Ordering::Relaxed);
                        None
                    }
                }
            }
        });
        futures_util::pin_mut!(stream);

        let base_wire = ProcessEventWire {
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            event_type: 0,
            ts_ns: 0,
            seq: 0,
            comm: [0; 16],
            exit_time_ns: 0,
            cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
            mem_pct_milli: PERCENT_MILLI_UNKNOWN,
            data: 0,
            data2: 0,
            aux: 0,
            aux2: 0,
        };
        let base_event = ProcessEvent::new(base_wire);
        for _ in 0..1500 {
            ctx.add(base_event.clone());
        }
        let _ = stream.next().await;
        assert!(metrics.dropped_events_total.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn status_keys_present() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
        });
        let Json(resp) = super::status_handler(State(app_state)).await;
        let val = serde_json::to_value(resp).unwrap();
        let obj = val.as_object().unwrap();
        for key in [
            "version",
            "uptime_s",
            "offline",
            "cpu_pct",
            "rss_mb",
            "events_per_sec",
            "rb_overflows",
            "rate_limited",
            "kernel_version",
            "aya_version",
            "transport",
            "active_rules",
            "top_rss",
            "probes",
        ] {
            assert!(obj.contains_key(key));
        }
    }

    #[tokio::test]
    async fn metrics_includes_probe_state() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let metrics = Arc::new(Metrics::new());
        metrics.set_rss_probe_mode(RssProbeMode::CoreMm.metric_value());
        metrics.set_kernel_btf_available(true);
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "tracepoint",
            probe_state: ProbeState {
                rss_probe: RssProbeMode::CoreMm,
                btf_available: true,
            },
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
        });

        let Json(resp) = super::metrics_handler(State(app_state)).await;
        let val = serde_json::to_value(resp).unwrap();
        let obj = val.as_object().unwrap();
        assert_eq!(obj.get("rss_probe_mode").unwrap(), "core:mm");
        assert_eq!(
            obj.get("kernel_btf_available").unwrap(),
            &serde_json::json!(true)
        );
    }

    #[tokio::test]
    async fn insight_schema_route_exposes_required_properties() {
        let Json(schema) = super::get_insight_schema_route().await;
        let props = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("schema properties object");
        for key in ["class", "confidence", "primary_process", "why", "actions"] {
            assert!(
                props.contains_key(key),
                "schema properties must contain {key}"
            );
        }
    }

    #[tokio::test]
    async fn prometheus_endpoint_respects_flag() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
        });
        let router = super::all_routes(Arc::clone(&app_state));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/metrics/prometheus")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn prometheus_endpoint_returns_metrics_when_enabled() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let metrics = Arc::new(Metrics::new());
        metrics.events_total.fetch_add(42, Ordering::Relaxed);
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: true,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
        });
        let router = super::all_routes(Arc::clone(&app_state));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/metrics/prometheus")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("text/plain"),
            "unexpected content-type: {content_type}"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            body_text.contains("linnix_events_total"),
            "expected metric missing: {body_text}"
        );
    }

    #[tokio::test]
    async fn test_no_auth_allows_requests() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
        });
        let router = super::all_routes(app_state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_required_when_token_set() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: Some("secret123".to_string()),
        });
        let router = super::all_routes(app_state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/processes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_with_valid_bearer_token() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: Some("secret123".to_string()),
        });
        let router = super::all_routes(app_state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .header("Authorization", "Bearer secret123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_with_invalid_token() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: Some("secret123".to_string()),
        });
        let router = super::all_routes(app_state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/processes")
                    .header("Authorization", "Bearer wrong_token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_with_malformed_header() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: Some("secret123".to_string()),
        });
        let router = super::all_routes(app_state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/processes")
                    .header("Authorization", "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
