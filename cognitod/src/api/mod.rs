mod auth;

use crate::runtime::probes::ProbeState;
use axum::{
    Router,
    extract::{Form, Path, Query, State},
    http::{StatusCode, header},
    response::{
        IntoResponse, Json, Response,
        sse::{Event, Sse},
    },
    routing::{get, post},
};
use futures_util::stream::{BoxStream, Stream, StreamExt};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{json, to_string};
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
use crate::config::{OfflineGuard, ReasonerConfig};
use crate::context::ContextStore;
use crate::insights::{InsightRecord, InsightStore as InsightsStore};
use crate::metrics::Metrics;
use crate::types::ProcessAlert;
use crate::types::SystemSnapshot;
use cognitod::alerts::Alert;
use cognitod::{Incident, IncidentStats, IncidentStore};
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
    k8s: Option<cognitod::k8s::K8sMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<cognitod::k8s::Priority>,
}

impl ProcessInfo {
    fn from_event(e: &ProcessEvent, app_state: &AppState) -> Self {
        let k8s = app_state
            .k8s
            .as_ref()
            .and_then(|k| k.get_metadata_for_pid(e.pid));
        Self {
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
            k8s: k8s.clone(),
            priority: k8s.map(|m| m.priority),
        }
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mem_percent: Option<f32>,
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
    k8s: Option<cognitod::k8s::K8sMetadata>,
}

#[derive(Serialize)]
struct TopCpuEntry {
    pid: u32,
    comm: String,
    cpu_percent: f32,
    k8s: Option<cognitod::k8s::K8sMetadata>,
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
    incidents_last_1h: Option<usize>,
    feedback_entries: u64,
    slack_stats: SlackStats,
    perf_poll_errors: u64,
    dropped_events_total: u64,
}

#[derive(Serialize)]
struct SlackStats {
    sent: u64,
    failed: u64,
    approved: u64,
    denied: u64,
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
    timeout_ms: u64,
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
    let ctx = &app_state.context;
    let top_rss = ctx
        .top_rss_processes(5)
        .into_iter()
        .map(|p| TopRssEntry {
            pid: p.pid,
            comm: p.comm,
            mem_percent: p.mem_percent,
            k8s: app_state
                .k8s
                .as_ref()
                .and_then(|k| k.get_metadata_for_pid(p.pid)),
        })
        .collect();

    let top_cpu = ctx
        .top_cpu_processes(5)
        .into_iter()
        .map(|p| TopCpuEntry {
            pid: p.pid,
            comm: p.comm,
            cpu_percent: p.mem_percent, // Reusing mem_percent field for CPU in summary struct
            k8s: app_state
                .k8s
                .as_ref()
                .and_then(|k| k.get_metadata_for_pid(p.pid)),
        })
        .collect();
    let reasoner = ReasonerStatus {
        configured: reasoner_cfg.enabled,
        endpoint: if reasoner_cfg.endpoint.is_empty() {
            None
        } else {
            Some(reasoner_cfg.endpoint.clone())
        },
        timeout_ms: reasoner_cfg.timeout_ms,
    };

    let incidents_last_1h = if let Some(store) = &app_state.incident_store {
        let one_hour_ago = chrono::Utc::now().timestamp() - 3600;
        store.since(one_hour_ago, None).await.ok().map(|v| v.len())
    } else {
        None
    };

    let slack_stats = SlackStats {
        sent: metrics.slack_sent(),
        failed: metrics.slack_failed(),
        approved: metrics.slack_approved(),
        denied: metrics.slack_denied(),
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
        incidents_last_1h,
        feedback_entries: metrics.feedback_entries(),
        slack_stats,
        perf_poll_errors: metrics.perf_poll_errors(),
        dropped_events_total: metrics
            .dropped_events_total
            .load(std::sync::atomic::Ordering::Relaxed),
    };
    Json(resp)
}

async fn get_context_route(State(app_state): State<Arc<AppState>>) -> Json<Vec<ProcessInfo>> {
    let ctx = &app_state.context;
    let events = ctx.get_recent();
    let data: Vec<ProcessInfo> = events
        .into_iter()
        .map(|e| ProcessInfo::from_event(&e, &app_state))
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
        .map(|e| ProcessInfo::from_event(&e, &app_state))
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
        let info = ProcessInfo::from_event(&e, &app_state);
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
        .map(|e| ProcessInfo::from_event(&e, &app_state))
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

    if let Some((proc, _)) = live.get(&pid) {
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
            if let Some((parent, _)) = live.get(&current_pid) {
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
        for (sibling, _) in live.values() {
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
            live: &std::collections::HashMap<
                u32,
                (ProcessEvent, Option<Arc<cognitod::k8s::K8sMetadata>>),
            >,
            seen: &mut std::collections::HashSet<u32>,
            nodes: &mut Vec<GraphNode>,
            level: isize,
        ) {
            for (proc, _) in live.values() {
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
        let has_children = live.values().any(|(proc, _)| proc.ppid == pid);
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
                live: &std::collections::HashMap<
                    u32,
                    (ProcessEvent, Option<Arc<cognitod::k8s::K8sMetadata>>),
                >,
                seen: &mut std::collections::HashSet<u32>,
                nodes: &mut Vec<GraphNode>,
                level: isize,
            ) {
                for (proc, _) in live.values() {
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
                        cpu_percent: event.cpu_percent(),
                        mem_percent: event.mem_percent(),
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
                .map(|e| ProcessInfo::from_event(&e, &app_state))
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
    alerts.sort_by_key(|a| std::cmp::Reverse(a.timestamp));

    // Limit to 1000 results
    alerts.truncate(1000);

    Json(alerts)
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

    // Call LLM - supports both local models and OpenAI.
    // LLM_ENDPOINT/LLM_MODEL are already folded into [reasoner] at startup, so
    // read the resolved config rather than the environment: consulting env here
    // too is what let this path and the incident analyzer target different models.
    let model = app_state.reasoner.model.clone();
    let llm_endpoint = app_state.reasoner.endpoint.clone();

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

/// Liveness. Answers "is the process alive?" and nothing more.
///
/// Deliberately returns 200 even when the eBPF probes failed to attach: a
/// kernel that cannot load our programs will never load them, so failing
/// liveness would produce a restart loop that hides the real cause. The
/// degradation is reported here for humans, and gated on by /readyz.
pub async fn healthz(State(app_state): State<Arc<AppState>>) -> axum::Json<serde_json::Value> {
    let instrumented = kernel_instrumentation_active(&app_state);
    axum::Json(serde_json::json!({
        "status": "ok",
        "kernel_instrumentation": if instrumented { "active" } else { "unavailable" },
        "transport": app_state.transport,
    }))
}

/// True when the eBPF probes actually attached and events can flow.
///
/// `transport` is set to "perf" only after `init_ebpf` succeeds; it stays
/// "userspace" when the object failed to load or verify.
pub fn kernel_instrumentation_active(app_state: &AppState) -> bool {
    app_state.transport != "userspace"
}

/// Readiness. Answers "is this instance doing its job?"
///
/// Linnix exists to attribute stalls to processes using kernel telemetry. When
/// the probes are not attached, PSI still reports that pressure exists — but the
/// per-process attribution, the part that distinguishes Linnix from reading
/// /proc/pressure directly, is gone. Reporting ready in that state hides a dead
/// collector behind a green pod.
pub async fn readyz(State(app_state): State<Arc<AppState>>) -> impl IntoResponse {
    let instrumented = kernel_instrumentation_active(&app_state);
    let required = app_state.require_kernel_instrumentation;
    let ready = instrumented || !required;

    let body = serde_json::json!({
        "ready": ready,
        "kernel_instrumentation": if instrumented { "active" } else { "unavailable" },
        "transport": app_state.transport,
        "btf_available": app_state.probe_state.btf_available,
        "rss_probe": app_state.probe_state.rss_probe.as_str(),
        "reason": if ready {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(
                "eBPF probes are not attached; running userspace-only, so no \
                 per-process stall attribution is being produced. Check the kernel \
                 version (5.12+ x86_64 / 5.18+ arm64), BTF availability, tracefs \
                 mount, and CAP_BPF/CAP_PERFMON."
                    .to_string(),
            )
        },
    });

    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, axum::Json(body))
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
struct AttributionQuery {
    pod: String,
    namespace: String,
    #[serde(default = "default_window")]
    window: i64, // minutes
    /// Absolute unix-second bounds. When both are given they replace `window`,
    /// which is what turns a query into something citable: `window` answers
    /// "lately" and means something different every time it is asked.
    from: Option<i64>,
    to: Option<i64>,
    /// Highest attribution row id the answer may include.
    ///
    /// Timestamps are not sufficient on their own: they have one-second
    /// resolution, so a row written later in the same second as `to` falls
    /// inside the bounds but was not in the original answer. The watermark
    /// pins the answer to the rows that existed when it was given.
    max_id: Option<i64>,
    /// Narrows the answer to a single stall event. Rows written before the PSI
    /// monitor emitted ids carry none, so an event filter never matches them —
    /// correctly, since their grouping was only ever inferred.
    event: Option<String>,
}

fn default_window() -> i64 {
    5
}

/// Serialises one stored attribution with its dominant signal attached.
///
/// The reason is derived here rather than by each client because it has to
/// name whichever term dominated the stored blame score, and that
/// normalisation deliberately lives in exactly one place. A client that
/// recomputed it would drift the moment either side of the score changed.
/// Rows carrying no signal at all are left unclassified. A real attribution is
/// only persisted when its blame score exceeds zero, which takes at least one
/// non-zero signal, so all three at zero means the columns were never
/// populated — migration 005 added them with zero defaults. Classifying that
/// would report `high_cpu_contention`, the branch three zeros happen to fall
/// into, as though it were a finding.
fn with_blame_reason(attr: &cognitod::incidents::StallAttribution) -> serde_json::Value {
    let mut value = serde_json::to_value(attr).unwrap_or_default();
    let has_signal = attr.cpu_share > 0.0 || attr.fork_count > 0 || attr.short_job_count > 0;
    if has_signal && let Some(obj) = value.as_object_mut() {
        let reason = cognitod::attribution::BlameReason::classify(
            attr.cpu_share,
            attr.fork_count,
            attr.short_job_count,
        );
        obj.insert("reason".into(), reason.as_str().into());
    }
    value
}

async fn get_attributions(
    State(app_state): State<Arc<AppState>>,
    Query(query): Query<AttributionQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match &app_state.incident_store {
        Some(store) => {
            // Resolved once, then used for both the query and the link. Asking
            // the clock twice would hand back a permalink to a window that is
            // not quite the one just answered.
            let (from, to) = query.resolve_bounds();

            let (attributions, watermark) = store
                .query_attributions_filtered(
                    &query.pod,
                    &query.namespace,
                    from,
                    to,
                    query.max_id,
                    query.event.as_deref(),
                )
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let attributions: Vec<serde_json::Value> =
                attributions.iter().map(with_blame_reason).collect();

            Ok(Json(serde_json::json!({
                "victim": {
                    "pod": query.pod,
                    "namespace": query.namespace
                },
                // Derived from the bounds rather than echoed from `window`.
                // A permalink carries `from`/`to` and no `window`, so echoing
                // the input would report the 5-minute default beside bounds
                // spanning any duration at all.
                "window_minutes": (to - from) / 60,
                // The bounds actually queried, always absolute — a caller that
                // asked for "the last 15 minutes" can cite what that turned
                // out to mean instead of re-asking and getting a later answer.
                "from": from,
                "to": to,
                "permalink": query.permalink(from, to, watermark),
                "attributions": attributions
            })))
        }
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

impl AttributionQuery {
    /// The absolute bounds this query means right now.
    ///
    /// Explicit `from`/`to` win. A half-specified range is treated as the open
    /// side being unbounded rather than as an error: `from` alone reads as
    /// "since then", which is what someone pasting a start time intends.
    fn resolve_bounds(&self) -> (i64, i64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        match (self.from, self.to) {
            (Some(from), Some(to)) => (from, to),
            (Some(from), None) => (from, now),
            (None, Some(to)) => (to - self.window * 60, to),
            (None, None) => (now - self.window * 60, now),
        }
    }

    /// A query string that returns these exact rows whenever it is opened.
    ///
    /// Carries the row-id watermark as well as the time bounds, so a row
    /// written later in the same second as `to` — or backfilled afterwards
    /// with an older timestamp — cannot appear in evidence that has already
    /// been cited.
    fn permalink(&self, from: i64, to: i64, max_id: i64) -> String {
        let base = format!(
            "/attribution?pod={}&namespace={}&from={}&to={}&max_id={}",
            urlencode(&self.pod),
            urlencode(&self.namespace),
            from,
            to,
            max_id
        );
        // Without this the link silently widens: an answer about one stall
        // event would reopen as every event in its window.
        match &self.event {
            Some(event) => format!("{base}&event={}", urlencode(event)),
            None => base,
        }
    }
}

/// Percent-encodes the characters that can appear in a Kubernetes name and
/// still break a query string. Names are restricted to lowercase alphanumerics,
/// `-` and `.`, so this is a guard against malformed input reaching a link
/// rather than a general-purpose encoder.
fn urlencode(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' | '_' | '~' => c.to_string(),
            other => other
                .to_string()
                .bytes()
                .map(|b| format!("%{b:02X}"))
                .collect(),
        })
        .collect()
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
    pub slack_sent: u64,
    pub slack_failed: u64,
    pub alerts_generated: u64,
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
        "# HELP linnix_kernel_instrumentation_active 1 if the eBPF probes are attached, 0 if running userspace-only."
    );
    let _ = writeln!(body, "# TYPE linnix_kernel_instrumentation_active gauge");
    let _ = writeln!(
        body,
        "linnix_kernel_instrumentation_active {}",
        u8::from(kernel_instrumentation_active(&app_state))
    );

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

    // Who is stalling, and who is stalling them.
    app_state.blame_metrics.render_prometheus(&mut body);

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
        slack_sent: metrics.slack_sent(),
        slack_failed: metrics.slack_failed(),
        alerts_generated: metrics.alerts_generated(),
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
    pub insights: Arc<InsightsStore>,
    pub offline: Arc<OfflineGuard>,
    pub transport: &'static str,
    pub probe_state: ProbeState,
    /// When true, /readyz returns 503 if the eBPF probes are not attached.
    pub require_kernel_instrumentation: bool,
    pub reasoner: ReasonerConfig,
    pub prometheus_enabled: bool,
    pub alert_history: Arc<AlertHistory>,
    pub auth_token: Option<String>,
    pub enforcement: Option<Arc<crate::enforcement::EnforcementQueue>>,
    pub incident_store: Option<Arc<IncidentStore>>,
    pub k8s: Option<Arc<cognitod::k8s::K8sContext>>,
    /// Noisy-neighbour counters fed by the PSI monitor's attribution sink.
    pub blame_metrics: Arc<cognitod::attribution::BlameMetrics>,
}

/// Every route the daemon serves, listed once.
///
/// Both listeners build from this. The difference between them is the auth
/// layer, not the route set — and on an auth boundary that distinction has to
/// be structural rather than clerical. Two hand-maintained lists meant a route
/// added to one and forgotten in the other either vanished silently from the
/// socket, or became reachable over TCP *without token auth*.
fn base_router(prometheus_enabled: bool) -> Router<Arc<AppState>> {
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
        .route("/insights", get(get_insights))
        .route("/insights/recent", get(get_recent_insights))
        .route("/insights/{id}", get(get_insight_by_id))
        .route("/insights/{id}/feedback", post(submit_feedback))
        .route("/api/feedback", post(submit_feedback_api))
        .route("/api/slack/interactions", post(handle_slack_interaction))
        .route("/incidents", get(get_incidents))
        .route("/incidents/summary", get(get_incident_summary))
        .route("/incidents/stats", get(get_incident_stats))
        .route("/incidents/{id}", get(get_incident_by_id))
        .route("/attribution", get(get_attributions))
        .route("/metrics", get(metrics_handler))
        .route("/status", get(status_handler))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // .route("/insights/schema", get(get_insight_schema_route)) // Removed (YAGNI cleanup)
        .route("/actions", get(get_actions))
        .route("/actions/{id}", get(get_action_by_id))
        .route("/actions/{id}/approve", axum::routing::post(approve_action))
        .route("/actions/{id}/reject", axum::routing::post(reject_action));

    if prometheus_enabled {
        router = router.route("/metrics/prometheus", get(prometheus_metrics));
    }

    router
}

/// Build routes for the TCP listener, which requires a bearer token when one
/// is configured.
pub fn all_routes(app_state: Arc<AppState>) -> Router {
    let auth_token = app_state.auth_token.clone();
    let mut router = base_router(app_state.prometheus_enabled);

    if auth_token.is_some() {
        router = router.layer(axum::middleware::from_fn_with_state(
            auth_token,
            auth::auth_middleware,
        ));
    }

    router.with_state(app_state)
}

/// Build routes for the Unix domain socket listener.
///
/// Same routes as `all_routes` — guaranteed, not maintained — but no auth
/// middleware: UDS connections are trusted because local process identity is
/// verified by socket credentials (`SO_PEERCRED`).
pub fn uds_routes(app_state: Arc<AppState>) -> Router {
    base_router(app_state.prometheus_enabled).with_state(app_state)
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

// ========================================
// Feedback API Endpoints
// ========================================

#[derive(Deserialize)]
struct FeedbackRequest {
    insight_id: String,
    label: String,  // "useful", "noise", "wrong"
    source: String, // "cli", "slack", "web"
    user_id: Option<String>,
}

async fn submit_feedback_api(
    State(app): State<Arc<AppState>>,
    Json(req): Json<FeedbackRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let store = app.incident_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Incident store not available".to_string(),
        )
    })?;

    store
        .insert_feedback(
            &req.insight_id,
            &req.label,
            &req.source,
            req.user_id.as_deref(),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    app.metrics.inc_feedback_entry();

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

// ========================================
// Incident API Endpoints
// ========================================

#[derive(Deserialize)]
#[allow(dead_code)]
struct IncidentQueryParams {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    analyzed: Option<bool>,
}

fn default_limit() -> i64 {
    10
}

/// GET /incidents - List recent incidents
async fn get_incidents(
    Query(params): Query<IncidentQueryParams>,
    State(app): State<Arc<AppState>>,
) -> Result<Json<Vec<Incident>>, (StatusCode, String)> {
    let store = app.incident_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Incident store not available".to_string(),
        )
    })?;

    let incidents = store
        .recent(params.limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Filter by analyzed status if requested
    let filtered = if let Some(analyzed) = params.analyzed {
        incidents
            .into_iter()
            .filter(|i| analyzed == i.llm_analysis.is_some())
            .collect()
    } else {
        incidents
    };

    Ok(Json(filtered))
}

/// GET /incidents/:id - Get incident by ID
async fn get_incident_by_id(
    Path(id): Path<i64>,
    State(app): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let store = app.incident_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Incident store not available".to_string(),
        )
    })?;

    let incident = store
        .get(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Incident not found".to_string()))?;

    Ok(Json(with_rendered_investigation(&incident)))
}

/// Serialises an incident with its investigation made legible.
///
/// The column holds JSON as text, so the endpoint used to return it as one
/// escaped string — the grounding work was there and unreadable. This parses it
/// into a real object and adds `investigation_rendered`, the same text
/// `IncidentInvestigation::render` produces.
///
/// Rendering happens here rather than in each client for the reason the
/// grounding exists at all: every cited fact is resolved through the daemon's
/// own wording, so no consumer can restate a fact while claiming to quote it.
fn with_rendered_investigation(incident: &Incident) -> serde_json::Value {
    let mut value = serde_json::to_value(incident).unwrap_or_default();

    let Some(raw) = incident.investigation.as_deref() else {
        return value;
    };

    // A stored investigation that no longer parses is left exactly as it is.
    // It is evidence about a past incident, and silently dropping it would be
    // worse than showing it in the shape it was written.
    // An explicit null says "this build tried and could not". Omitting the key
    // instead would be indistinguishable from an older daemon that never had
    // this field, and a client cannot tell an unreadable record from a version
    // skew without that difference.
    let unreadable = |mut value: serde_json::Value| {
        if let Some(obj) = value.as_object_mut() {
            obj.insert("investigation_rendered".into(), serde_json::Value::Null);
        }
        value
    };

    let Ok(parsed) = serde_json::from_str::<cognitod::incidents::IncidentInvestigation>(raw) else {
        return unreadable(value);
    };

    // Serde ignores unknown fields, so an investigation written by a newer
    // build parses here and would be re-serialised at *this* version — quietly
    // dropping whatever it knew and rendering the remainder with older
    // semantics. `IncidentStore::get_investigation` already refuses those, and
    // this path has to agree or one row means two things depending on route.
    if parsed.schema_version > cognitod::incidents::investigation::SCHEMA_VERSION {
        return unreadable(value);
    }

    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "investigation".into(),
            serde_json::to_value(&parsed).unwrap_or_default(),
        );
        obj.insert("investigation_rendered".into(), parsed.render().into());
    }

    value
}

/// GET /incidents/stats - Get incident statistics
async fn get_incident_stats(
    State(app): State<Arc<AppState>>,
) -> Result<Json<IncidentStats>, (StatusCode, String)> {
    let store = app.incident_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Incident store not available".to_string(),
        )
    })?;

    let stats = store
        .stats()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(stats))
}

#[derive(Serialize)]
struct IncidentSummary {
    total: u64,
    analyzed: u64,
    pending_analysis: u64,
    by_event_type: std::collections::HashMap<String, u64>,
    recent: Vec<Incident>,
}

/// GET /incidents/summary - Get comprehensive incident summary
async fn get_incident_summary(
    State(app): State<Arc<AppState>>,
) -> Result<Json<IncidentSummary>, (StatusCode, String)> {
    let store = app.incident_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Incident store not available".to_string(),
        )
    })?;

    let stats = store
        .stats()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let recent = store
        .recent(10)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let analyzed = recent.iter().filter(|i| i.llm_analysis.is_some()).count() as u64;
    let pending = recent.len() as u64 - analyzed;

    let mut by_event_type = std::collections::HashMap::new();
    for incident in &recent {
        *by_event_type
            .entry(incident.event_type.clone())
            .or_insert(0) += 1;
    }

    Ok(Json(IncidentSummary {
        total: stats.total,
        analyzed,
        pending_analysis: pending,
        by_event_type,
        recent,
    }))
}

#[derive(Debug, Deserialize)]
struct SlackInteractionPayload {
    payload: String,
}

#[derive(Debug, Deserialize)]
struct SlackAction {
    action_id: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct SlackPayload {
    actions: Vec<SlackAction>,
}

async fn get_insight_by_id(
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(app): State<Arc<AppState>>,
) -> Response {
    let record = app.insights.get_by_id(&id);

    match record {
        Some(rec) => {
            // Check if HTML format is requested
            if params.get("format") == Some(&"html".to_string()) {
                let insight = &rec.insight;
                let html = format!(
                    r#"<!DOCTYPE html>
<html>
<head>
    <title>Incident {}</title>
    <style>
        body {{ font-family: system-ui; max-width: 800px; margin: 40px auto; padding: 20px; }}
        .header {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .reason {{ color: #d32f2f; font-size: 24px; font-weight: bold; }}
        .confidence {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }}
        th {{ background: #f5f5f5; font-weight: 600; }}
        .summary {{ background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }}
        .next-step {{ background: #d1ecf1; padding: 15px; border-left: 4px solid #0c5460; margin: 20px 0; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="reason">🚨 {}</div>
        <div class="confidence">Confidence: {:.0}%</div>
        <div style="margin-top: 10px; color: #666;">ID: {}</div>
    </div>
    
    <div class="summary">
        <strong>Summary:</strong><br>
        {}
    </div>
    
    <h3>Top Contributing Pods</h3>
    <table>
        <tr>
            <th>Namespace</th>
            <th>Pod</th>
            <th>CPU Usage</th>
            <th>PSI Contribution</th>
        </tr>
        {}
    </table>
    
    <div class="next-step">
        <strong>Suggested Next Step:</strong><br>
        {}
    </div>
    
    <div class="footer">
        <a href="/insights/{}">View as JSON</a> | 
        Generated by Linnix v0.2.0
    </div>
</body>
</html>"#,
                    id,
                    insight.reason_code.as_str(),
                    insight.confidence * 100.0,
                    id,
                    insight.summary,
                    insight
                        .top_pods
                        .iter()
                        .map(|p| format!(
                            "<tr><td>{}</td><td>{}</td><td>{:.1}%</td><td>{:.1}%</td></tr>",
                            p.namespace, p.pod, p.cpu_usage, p.psi_contribution
                        ))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    insight.suggested_next_step,
                    id
                );

                (StatusCode::OK, [("content-type", "text/html")], html).into_response()
            } else {
                // Default: JSON
                Json(rec).into_response()
            }
        }
        None => (StatusCode::NOT_FOUND, "Insight not found").into_response(),
    }
}

#[derive(Deserialize)]
struct FeedbackPayload {
    feedback: crate::insights::Feedback,
}

async fn submit_feedback(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<FeedbackPayload>,
) -> impl IntoResponse {
    if state
        .insights
        .update_feedback(&id, payload.feedback.clone())
    {
        log::info!(
            "Received feedback {:?} for insight {}",
            payload.feedback,
            id
        );
        (StatusCode::OK, Json(json!({"status": "ok"}))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Insight not found"})),
        )
            .into_response()
    }
}

async fn handle_slack_interaction(
    State(state): State<Arc<AppState>>,
    Form(form): Form<SlackInteractionPayload>,
) -> impl IntoResponse {
    let payload: SlackPayload = match serde_json::from_str(&form.payload) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Failed to parse Slack payload: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid payload").into_response();
        }
    };

    if let Some(enforcement) = &state.enforcement {
        for action in payload.actions {
            if action.action_id == "approve_action" {
                if let Some(ids_str) = action.value.strip_prefix("approve:") {
                    for id in ids_str.split('|') {
                        if !id.is_empty() {
                            match enforcement.approve(id, "slack_user".to_string()).await {
                                Ok(_) => {
                                    log::info!("Approved action {} via Slack", id);
                                    state.metrics.inc_slack_approved();
                                }
                                Err(e) => {
                                    log::warn!("Failed to approve action {} via Slack: {}", id, e)
                                }
                            }
                        }
                    }
                }
            } else if action.action_id == "deny_action" {
                if let Some(ids_str) = action.value.strip_prefix("deny:") {
                    for id in ids_str.split('|') {
                        if !id.is_empty() {
                            match enforcement.reject(id, "slack_user".to_string()).await {
                                Ok(_) => {
                                    log::info!("Rejected action {} via Slack", id);
                                    state.metrics.inc_slack_denied();
                                }
                                Err(e) => {
                                    log::warn!("Failed to reject action {} via Slack: {}", id, e)
                                }
                            }
                        }
                    }
                }
            } else if action.action_id == "feedback_useful"
                && let Some(id) = action.value.strip_prefix("useful:")
                && state
                    .insights
                    .update_feedback(id, crate::insights::Feedback::Useful)
            {
                log::info!("Marked insight {} as Useful", id);
            } else if action.action_id == "feedback_noise"
                && let Some(id) = action.value.strip_prefix("noise:")
                && state
                    .insights
                    .update_feedback(id, crate::insights::Feedback::Noise)
            {
                log::info!("Marked insight {} as Noise", id);
            }
        }
    } else {
        log::warn!("Received Slack interaction but enforcement is disabled");
    }

    (StatusCode::OK, "").into_response()
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

    fn stored_attribution(
        cpu_share: f64,
        fork_count: u64,
        short_job_count: u64,
    ) -> cognitod::incidents::StallAttribution {
        cognitod::incidents::StallAttribution {
            event_id: Some("evt-test".to_string()),
            offender_pod: "image-resizer".to_string(),
            offender_namespace: "media".to_string(),
            stall_us: 900_000,
            attributed_stall_us: Some(600_000),
            blame_score: 2.0,
            timestamp: 1_700_000_000,
            cpu_share,
            fork_count,
            short_job_count,
        }
    }

    #[test]
    fn attribution_rows_carry_the_dominant_signal() {
        // The stored columns survive the round trip alongside the new field.
        let value = with_blame_reason(&stored_attribution(0.8, 12, 3));
        assert_eq!(value["offender_pod"], "image-resizer");
        assert_eq!(value["attributed_stall_us"], 600_000);
        assert_eq!(value["reason"], "high_cpu_contention");
    }

    #[test]
    fn dominant_signal_follows_the_scores_own_normalisation() {
        // 100 forks saturates the fork term, beating a 0.5 CPU share; 60 short
        // jobs saturates its term while forks stay low. Both cases go through
        // the same normalisation the blame score uses, so they cannot drift.
        let forky = with_blame_reason(&stored_attribution(0.5, 100, 0));
        assert_eq!(forky["reason"], "fork_storm");

        let churny = with_blame_reason(&stored_attribution(0.1, 2, 60));
        assert_eq!(churny["reason"], "short_job_churn");
    }

    #[test]
    fn a_row_with_no_signal_is_left_unclassified() {
        // Only rows predating migration 005 read as all-zero: a live
        // attribution needs a non-zero score to be stored at all. Classifying
        // the defaults would report high CPU contention as a finding.
        let value = with_blame_reason(&stored_attribution(0.0, 0, 0));
        assert!(value.get("reason").is_none());
    }

    #[tokio::test]
    async fn heartbeats_emit_every_10s() {
        tokio::time::pause();
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
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
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 100, None));
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

    /// AppState for a node where the eBPF probes failed to attach:
    /// transport stays "userspace", which is what init_ebpf leaves on failure.
    fn degraded_app_state() -> Arc<AppState> {
        Arc::new(AppState {
            context: Arc::new(ContextStore::new(Duration::from_secs(60), 10, None)),
            metrics: Arc::new(Metrics::new()),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "userspace",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: None,
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
        })
    }

    #[tokio::test]
    async fn readyz_503_when_probes_not_attached() {
        // transport stays "userspace" when init_ebpf fails -- the exact state a
        // node below the kernel floor ends up in. It must not report ready.
        let app_state = degraded_app_state();
        let app = all_routes(Arc::clone(&app_state));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ready"], false);
        assert_eq!(v["kernel_instrumentation"], "unavailable");
        assert!(v["reason"].as_str().unwrap().contains("userspace-only"));
    }

    #[tokio::test]
    async fn healthz_stays_200_when_degraded() {
        // Liveness must not flap on an unsupported kernel -- restarting cannot fix it.
        let app_state = degraded_app_state();
        let app = all_routes(Arc::clone(&app_state));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["kernel_instrumentation"], "unavailable");
    }

    #[tokio::test]
    async fn status_keys_present() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: None,
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
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
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
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
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: None,
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
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
    async fn prometheus_endpoint_respects_flag() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: None,
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
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
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
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
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: true,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: None,
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
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
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: None,
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
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
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            incident_store: None,
            auth_token: Some("secret123".to_string()),
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
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
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            incident_store: None,
            auth_token: Some("secret123".to_string()),
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
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
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            incident_store: None,
            auth_token: Some("secret123".to_string()),
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
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
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            incident_store: None,
            auth_token: Some("secret123".to_string()),
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
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

    /// The exposed `/metrics/prometheus` text, byte for byte, for a known
    /// state.
    ///
    /// This is a contract test, not a unit test. The metric names, labels,
    /// `# TYPE` lines and ordering here are what the shipped Grafana dashboard
    /// (`k8s/grafana/linnix-noisy-neighbor.json`) queries by name; renaming a
    /// metric or dropping a label is a breaking change that no other test in
    /// this repo would notice, and that surfaces as blank panels in someone
    /// else's cluster rather than as a red build.
    ///
    /// Three values are volatile by nature — uptime and this process's own CPU
    /// and RSS — so they are scrubbed to `<volatile>` before comparison. The
    /// *lines* still have to be present and correctly named; only the numbers
    /// are free to move.
    ///
    /// If this fails and the change was deliberate, re-record with:
    /// `UPDATE_METRICS_FIXTURE=1 cargo test -p cognitod --bin cognitod metrics_prometheus`
    #[tokio::test]
    async fn metrics_prometheus_matches_the_recorded_contract() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));

        let metrics = Arc::new(Metrics::new());
        metrics.events_total.fetch_add(4_242, Ordering::Relaxed);
        metrics
            .dropped_events_total
            .fetch_add(17, Ordering::Relaxed);
        metrics.subscribers.fetch_add(3, Ordering::Relaxed);
        metrics.alerts_active.fetch_add(2, Ordering::Relaxed);
        metrics.inc_alerts_emitted();
        metrics.inc_rb_overflow();
        metrics.inc_lineage_hit();
        metrics.inc_lineage_miss();
        metrics.inc_perf_poll_error();
        metrics.set_kernel_btf_available(true);
        metrics.set_psi_cpu(75.2);
        metrics.set_psi_memory_some(3.1);

        // One victim and one offender pair, deliberately: these render out of
        // `HashMap`s, so several series would order differently run to run and
        // the fixture would flap for reasons that have nothing to do with the
        // contract.
        let blame = Arc::new(cognitod::attribution::BlameMetrics::new("test-node"));
        blame.record_victim_pressure("payments", "payment-api", "container-1", 900_000);
        blame.record_attribution(&cognitod::collectors::psi::BlameAttribution {
            event_id: "evt-fixture".to_string(),
            victim_pod: "payment-api".to_string(),
            victim_namespace: "payments".to_string(),
            offender_pod: "image-resizer".to_string(),
            offender_namespace: "media".to_string(),
            blame_score: 1.5,
            stall_us: 900_000,
            attributed_stall_us: 684_000,
            timestamp: 1_700_000_000,
            cpu_share: 0.71,
            fork_count: 186,
            short_job_count: 42,
        });

        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: true,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: None,
            k8s: None,
            blame_metrics: Arc::clone(&blame),
        });

        let response = super::all_routes(app_state)
            .oneshot(
                Request::builder()
                    .uri("/metrics/prometheus")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let scrubbed = scrub_volatile(std::str::from_utf8(&body).unwrap());

        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/metrics_prometheus.txt"
        );

        if std::env::var("UPDATE_METRICS_FIXTURE").is_ok() {
            std::fs::write(fixture_path, &scrubbed).unwrap();
            return;
        }

        let expected = std::fs::read_to_string(fixture_path).unwrap();
        if scrubbed != expected {
            // Deliberately not `assert_eq!`: on a 73-line body that prints two
            // full copies of the text and leaves the reader to spot the
            // difference. What a person needs here is the lines that moved.
            panic!(
                "the exposed metric text changed.\n\n{}\n\nIf this was deliberate, re-record with \
                 UPDATE_METRICS_FIXTURE=1 and review the fixture diff as a change to a public \
                 contract — the shipped Grafana dashboard queries these names.",
                line_diff(&expected, &scrubbed)
            );
        }
    }

    #[test]
    fn scrubbing_hides_values_without_hiding_contract_changes() {
        let scrubbed = scrub_volatile(
            "# HELP linnix_uptime_seconds Cognitod uptime in seconds.\n\
             # TYPE linnix_uptime_seconds gauge\n\
             linnix_uptime_seconds 4210\n\
             linnix_process_cpu_percent{pid=\"7\"} 1.5\n\
             linnix_uptime_seconds_total 9\n\
             linnix_events_total 4242\n",
        );

        let lines: Vec<&str> = scrubbed.lines().collect();

        // Help and type text is contract, not value: never touched.
        assert_eq!(
            lines[0],
            "# HELP linnix_uptime_seconds Cognitod uptime in seconds."
        );
        assert_eq!(lines[2], "linnix_uptime_seconds <volatile>");

        // A label added to a volatile metric is itself a contract change, so
        // it has to survive scrubbing and fail the comparison.
        assert_eq!(lines[3], "linnix_process_cpu_percent{pid=\"7\"} <volatile>");

        // A different metric that merely starts with a volatile name keeps its
        // value: prefix matching would have swallowed it.
        assert_eq!(lines[4], "linnix_uptime_seconds_total 9");

        assert_eq!(lines[5], "linnix_events_total 4242");
    }

    /// The differing lines between two metric bodies, as `-expected/+actual`.
    fn line_diff(expected: &str, actual: &str) -> String {
        let expected_lines: Vec<&str> = expected.lines().collect();
        let actual_lines: Vec<&str> = actual.lines().collect();

        let mut out = Vec::new();
        for idx in 0..expected_lines.len().max(actual_lines.len()) {
            let e = expected_lines.get(idx).copied();
            let a = actual_lines.get(idx).copied();
            if e != a {
                if let Some(e) = e {
                    out.push(format!("  line {}: -{e}", idx + 1));
                }
                if let Some(a) = a {
                    out.push(format!("  line {}: +{a}", idx + 1));
                }
            }
        }
        out.join("\n")
    }

    /// Replaces the value of every metric whose number cannot be held fixed,
    /// leaving the name and the rest of the line intact.
    fn scrub_volatile(body: &str) -> String {
        const VOLATILE: [&str; 3] = [
            "linnix_uptime_seconds",
            "linnix_process_cpu_percent",
            "linnix_process_rss_bytes",
        ];

        body.lines()
            .map(|line| {
                // Only the value is replaced, and only when the metric *name*
                // matches exactly. Rebuilding the line from the name alone
                // would erase whatever sits between it and the value, so a
                // label added to one of these — or a longer name sharing the
                // prefix — would be scrubbed out of existence and the fixture
                // would keep passing through the very change it exists to
                // catch.
                let Some((series, _value)) = line.rsplit_once(' ') else {
                    return line.to_string();
                };
                let name = series
                    .split_once('{')
                    .map(|(name, _labels)| name)
                    .unwrap_or(series);

                if VOLATILE.contains(&name) {
                    format!("{series} <volatile>")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    #[test]
    fn explicit_bounds_are_used_verbatim_and_echoed_as_a_link() {
        let query = super::AttributionQuery {
            pod: "payment-api".to_string(),
            namespace: "payments".to_string(),
            window: 5,
            from: Some(1_700_000_000),
            to: Some(1_700_000_900),
            max_id: Some(4_096),
            event: None,
        };

        // The whole point: the same request tomorrow returns the same rows, so
        // `window` must not quietly re-enter the calculation.
        assert_eq!(query.resolve_bounds(), (1_700_000_000, 1_700_000_900));
        assert_eq!(
            query.permalink(1_700_000_000, 1_700_000_900, 4_096),
            "/attribution?pod=payment-api&namespace=payments&from=1700000000&to=1700000900&max_id=4096"
        );
    }

    #[test]
    fn a_relative_window_resolves_to_absolute_bounds() {
        let query = super::AttributionQuery {
            pod: "payment-api".to_string(),
            namespace: "payments".to_string(),
            window: 15,
            from: None,
            to: None,
            max_id: None,
            event: None,
        };

        let (from, to) = query.resolve_bounds();
        assert_eq!(to - from, 15 * 60, "the window must survive resolution");

        // A caller who asked for "the last 15 minutes" gets back the fixed
        // range that turned out to be, which is the thing they can cite.
        let link = query.permalink(from, to, 77);
        assert!(link.contains(&format!("from={from}")), "{link}");
        assert!(link.contains(&format!("to={to}")), "{link}");
        assert!(
            !link.contains("window="),
            "a link must not be relative: {link}"
        );
    }

    #[test]
    fn one_sided_bounds_leave_the_open_end_open() {
        let since = super::AttributionQuery {
            pod: "p".to_string(),
            namespace: "n".to_string(),
            window: 5,
            from: Some(1_700_000_000),
            to: None,
            max_id: None,
            event: None,
        };
        let (from, to) = since.resolve_bounds();
        assert_eq!(from, 1_700_000_000, "an explicit start must be honoured");
        assert!(to > from, "an open end runs to now");

        let until = super::AttributionQuery {
            pod: "p".to_string(),
            namespace: "n".to_string(),
            window: 5,
            from: None,
            to: Some(1_700_000_900),
            max_id: None,
            event: None,
        };
        assert_eq!(until.resolve_bounds(), (1_700_000_900 - 300, 1_700_000_900));
    }

    #[test]
    fn names_that_would_break_a_link_are_encoded() {
        let query = super::AttributionQuery {
            pod: "pod name&evil=1".to_string(),
            namespace: "ns/../etc".to_string(),
            window: 5,
            from: None,
            to: None,
            max_id: None,
            event: None,
        };

        let link = query.permalink(1, 2, 3);
        assert!(
            !link.contains("&evil=1") && !link.contains(' '),
            "a name must not be able to inject query parameters: {link}"
        );
        assert!(!link.contains("ns/../etc"), "{link}");
    }

    /// End to end, through the endpoint rather than the store: an answer is
    /// given, a row lands in the same second, and the link that was handed out
    /// must still return exactly what it returned the first time.
    ///
    /// This is the scenario the review raised. Asserting it at the store layer
    /// leaves the question of whether the *handler* threads the watermark
    /// through, which is where it could still be lost.
    #[tokio::test]
    async fn a_permalink_reproduces_its_answer_after_a_same_second_row_lands() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            cognitod::IncidentStore::new(dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let row = |offender: &str, blame: f64| cognitod::collectors::psi::BlameAttribution {
            event_id: format!("evt-{offender}"),
            victim_pod: "payment-api".to_string(),
            victim_namespace: "payments".to_string(),
            offender_pod: offender.to_string(),
            offender_namespace: "media".to_string(),
            blame_score: blame,
            stall_us: 900_000,
            attributed_stall_us: 600_000,
            timestamp: now,
            cpu_share: 0.7,
            fork_count: 10,
            short_job_count: 2,
        };
        store
            .insert_stall_attribution(&row("image-resizer", 2.0))
            .await
            .unwrap();

        let app_state = Arc::new(AppState {
            context: Arc::new(ContextStore::new(Duration::from_secs(60), 10, None)),
            metrics: Arc::new(Metrics::new()),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: Some(Arc::clone(&store)),
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
        });

        let get = |uri: String, state: Arc<AppState>| async move {
            let response = super::all_routes(state)
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        };

        let first = get(
            "/attribution?pod=payment-api&namespace=payments&window=5".to_string(),
            Arc::clone(&app_state),
        )
        .await;
        assert_eq!(first["attributions"].as_array().unwrap().len(), 1);
        let link = first["permalink"].as_str().unwrap().to_string();
        assert!(
            link.contains("max_id="),
            "link must carry a watermark: {link}"
        );

        // A second offender is attributed in the very same second, after the
        // answer above was handed out.
        store
            .insert_stall_attribution(&row("batch-etl", 1.0))
            .await
            .unwrap();

        let live = get(
            "/attribution?pod=payment-api&namespace=payments&window=5".to_string(),
            Arc::clone(&app_state),
        )
        .await;
        assert_eq!(
            live["attributions"].as_array().unwrap().len(),
            2,
            "a fresh query must see the new row"
        );

        let reopened = get(link.clone(), Arc::clone(&app_state)).await;
        assert_eq!(
            reopened["attributions"].as_array().unwrap().len(),
            1,
            "the shared link must still show the evidence it was cited for: {link}"
        );
        assert_eq!(reopened["attributions"][0]["offender_pod"], "image-resizer");

        // And the metadata must not contradict the bounds it was opened with.
        assert_eq!(reopened["window_minutes"], first["window_minutes"]);
    }

    /// An event-specific link must stay event-specific when reopened.
    ///
    /// The store-level tests proved the SQL filters; nothing proved the
    /// *handler* passed the parameter to it, which is exactly how it shipped
    /// accepting `?event=` and ignoring it.
    #[tokio::test]
    async fn an_event_link_returns_only_that_event_through_the_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            cognitod::IncidentStore::new(dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Two stall events in the same second, so only the id separates them.
        for (event, offender) in [("evt-a", "image-resizer"), ("evt-b", "batch-etl")] {
            store
                .insert_stall_attribution(&cognitod::collectors::psi::BlameAttribution {
                    event_id: event.to_string(),
                    victim_pod: "payment-api".to_string(),
                    victim_namespace: "payments".to_string(),
                    offender_pod: offender.to_string(),
                    offender_namespace: "media".to_string(),
                    blame_score: 2.0,
                    stall_us: 900_000,
                    attributed_stall_us: 600_000,
                    timestamp: now,
                    cpu_share: 0.7,
                    fork_count: 10,
                    short_job_count: 2,
                })
                .await
                .unwrap();
        }

        let app_state = Arc::new(AppState {
            context: Arc::new(ContextStore::new(Duration::from_secs(60), 10, None)),
            metrics: Arc::new(Metrics::new()),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: Some(Arc::clone(&store)),
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
        });

        let get = |uri: String, state: Arc<AppState>| async move {
            let response = super::all_routes(state)
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        };

        let whole_window = get(
            "/attribution?pod=payment-api&namespace=payments&window=5".to_string(),
            Arc::clone(&app_state),
        )
        .await;
        assert_eq!(
            whole_window["attributions"].as_array().unwrap().len(),
            2,
            "an unfiltered query sees both events"
        );

        let one_event = get(
            "/attribution?pod=payment-api&namespace=payments&window=5&event=evt-a".to_string(),
            Arc::clone(&app_state),
        )
        .await;
        assert_eq!(
            one_event["attributions"].as_array().unwrap().len(),
            1,
            "the handler must apply the event filter, not merely echo it"
        );
        assert_eq!(
            one_event["attributions"][0]["offender_pod"],
            "image-resizer"
        );

        // And reopening the link it handed back must not widen the answer.
        let link = one_event["permalink"].as_str().unwrap().to_string();
        assert!(
            link.contains("event=evt-a"),
            "link must carry the event: {link}"
        );
        let reopened = get(link.clone(), Arc::clone(&app_state)).await;
        assert_eq!(
            reopened["attributions"].as_array().unwrap().len(),
            1,
            "an event link must stay event-specific when reopened: {link}"
        );
    }

    /// The grounding work has to reach a human. Until now `/incidents/{id}`
    /// returned the investigation as one escaped JSON string and
    /// `IncidentInvestigation::render` was called only from tests.
    #[tokio::test]
    async fn an_incident_exposes_its_investigation_as_text_and_structure() {
        use cognitod::incidents::investigation::{Fact, parse_and_ground};

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            cognitod::IncidentStore::new(dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );

        let facts = vec![
            Fact::new("f1", "CPU usage was 96.3%"),
            Fact::new("f2", "CPU pressure stall was 75.2%"),
        ];
        let grounded = parse_and_ground(
            r#"{"hypotheses":[{"reason_code":"cpu_spin",
               "statement":"A single runaway process held the CPU",
               "supporting_fact_ids":["f1","f2"],
               "proposed_action":"Inspect the deployment"}]}"#,
            facts,
        )
        .expect("the reply grounds");

        let mut incident = cognitod::Incident {
            id: None,
            timestamp: 1_732_242_135,
            event_type: "circuit_breaker_cpu".to_string(),
            psi_cpu: 75.21,
            psi_memory: 12.34,
            cpu_percent: 96.3,
            load_avg: "26.00,24.20,21.30".to_string(),
            action: "auto_kill".to_string(),
            target_pid: Some(472_693),
            target_name: Some("aggressive-stress.sh".to_string()),
            system_snapshot: None,
            llm_analysis: None,
            llm_analyzed_at: None,
            investigation: None,
            recovery_time_ms: None,
            psi_after: None,
        };
        // The real flow: an incident is recorded first, and the analysis lands
        // afterwards — `insert` deliberately does not write those columns.
        let id = store.insert(&incident).await.unwrap();
        incident.id = Some(id);
        store
            .add_llm_analysis(
                id,
                &cognitod::incidents::AnalysisOutcome {
                    raw_response: "raw model reply".to_string(),
                    investigation: Some(grounded),
                    parse_error: None,
                },
            )
            .await
            .unwrap();

        let app_state = Arc::new(AppState {
            context: Arc::new(ContextStore::new(Duration::from_secs(60), 10, None)),
            metrics: Arc::new(Metrics::new()),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: Some(Arc::clone(&store)),
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
        });

        let response = super::all_routes(app_state)
            .oneshot(
                Request::builder()
                    .uri(format!("/incidents/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Structure, not an escaped string: a client can walk the hypotheses.
        assert!(
            json["investigation"]["hypotheses"][0]["statement"]
                .as_str()
                .unwrap()
                .contains("runaway process"),
            "investigation must be an object, got: {}",
            json["investigation"]
        );

        // And the rendered form, where every citation is the daemon's wording.
        let rendered = json["investigation_rendered"].as_str().unwrap();
        assert!(rendered.contains("cpu_spin"), "{rendered}");
        assert!(
            rendered.contains("CPU pressure stall was 75.2%"),
            "cited facts must be quoted from the daemon: {rendered}"
        );
        assert!(rendered.contains("Inspect the deployment"), "{rendered}");

        // The raw reply is still there, unchanged.
        assert_eq!(json["llm_analysis"], "raw model reply");
    }

    /// An investigation from a newer build must be handed back untouched.
    ///
    /// Serde ignores unknown fields, so it parses cleanly here; re-serialising
    /// it would silently drop what that build knew and render the remainder
    /// with this build's semantics. `IncidentStore::get_investigation` already
    /// refuses those, and both routes have to agree.
    #[tokio::test]
    async fn an_investigation_from_a_newer_build_is_left_alone() {
        let incident = cognitod::Incident {
            id: Some(1),
            timestamp: 1_732_242_135,
            event_type: "circuit_breaker_cpu".to_string(),
            psi_cpu: 75.21,
            psi_memory: 12.34,
            cpu_percent: 96.3,
            load_avg: "26.00,24.20,21.30".to_string(),
            action: "auto_kill".to_string(),
            target_pid: Some(472_693),
            target_name: Some("aggressive-stress.sh".to_string()),
            system_snapshot: None,
            llm_analysis: Some("raw model reply".to_string()),
            llm_analyzed_at: Some(1_732_242_200),
            investigation: Some(
                r#"{"schema_version":99,"hypotheses":[],"discarded":[],
                    "facts":[],"certainty_note":"from the future"}"#
                    .to_string(),
            ),
            recovery_time_ms: None,
            psi_after: None,
        };

        let value = super::with_rendered_investigation(&incident);

        // Present and null, not absent. Null says "this build tried and could
        // not"; an absent key is what an *older* daemon returns, and a client
        // that cannot tell them apart reports a staggered upgrade as a corrupt
        // record.
        assert_eq!(
            value.get("investigation_rendered"),
            Some(&serde_json::Value::Null),
            "a future-version investigation must be refused explicitly, not silently"
        );
        assert!(
            value["investigation"].is_string(),
            "it must be handed back exactly as stored, got: {}",
            value["investigation"]
        );
        assert!(
            value["investigation"]
                .as_str()
                .unwrap()
                .contains("from the future"),
            "nothing may be dropped from it"
        );
    }

    /// An incident with no investigation must not grow empty fields that read
    /// as "analysed, found nothing".
    #[tokio::test]
    async fn an_incident_without_an_investigation_gains_no_rendered_field() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            cognitod::IncidentStore::new(dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );

        let incident = cognitod::Incident {
            id: None,
            timestamp: 1_732_242_135,
            event_type: "circuit_breaker_cpu".to_string(),
            psi_cpu: 75.21,
            psi_memory: 12.34,
            cpu_percent: 96.3,
            load_avg: "26.00,24.20,21.30".to_string(),
            action: "auto_kill".to_string(),
            target_pid: Some(472_693),
            target_name: Some("aggressive-stress.sh".to_string()),
            system_snapshot: None,
            llm_analysis: None,
            llm_analyzed_at: None,
            investigation: None,
            recovery_time_ms: None,
            psi_after: None,
        };
        let id = store.insert(&incident).await.unwrap();

        let app_state = Arc::new(AppState {
            context: Arc::new(ContextStore::new(Duration::from_secs(60), 10, None)),
            metrics: Arc::new(Metrics::new()),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            auth_token: None,
            incident_store: Some(Arc::clone(&store)),
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
        });

        let response = super::all_routes(app_state)
            .oneshot(
                Request::builder()
                    .uri(format!("/incidents/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json.get("investigation_rendered").is_none(),
            "no investigation means no rendered field, not an empty one"
        );
    }

    /// The one intended difference between the two listeners, pinned: same
    /// route, same state, token required over TCP and not over the socket.
    /// The route sets themselves no longer need a test — both listeners build
    /// from `base_router`, so they cannot disagree.
    #[tokio::test]
    async fn the_socket_skips_the_auth_the_tcp_listener_enforces() {
        let ctx = Arc::new(ContextStore::new(Duration::from_secs(60), 10, None));
        let metrics = Arc::new(Metrics::new());
        let app_state = Arc::new(AppState {
            context: Arc::clone(&ctx),
            metrics: Arc::clone(&metrics),
            alerts: None,
            insights: Arc::new(InsightStore::new(16, None)),
            offline: Arc::new(OfflineGuard::new(false)),
            transport: "perf",
            probe_state: ProbeState::disabled(),
            require_kernel_instrumentation: true,
            enforcement: None,
            reasoner: ReasonerConfig::default(),
            prometheus_enabled: false,
            alert_history: Arc::new(AlertHistory::new(16)),
            incident_store: None,
            auth_token: Some("secret123".to_string()),
            k8s: None,
            blame_metrics: Arc::new(cognitod::attribution::BlameMetrics::new("test-node")),
        });

        let unauthenticated = || {
            Request::builder()
                .uri("/processes")
                .body(Body::empty())
                .unwrap()
        };

        let over_tcp = super::all_routes(Arc::clone(&app_state))
            .oneshot(unauthenticated())
            .await
            .unwrap();
        assert_eq!(
            over_tcp.status(),
            StatusCode::UNAUTHORIZED,
            "a configured token must be enforced on the TCP listener"
        );

        let over_socket = super::uds_routes(app_state)
            .oneshot(unauthenticated())
            .await
            .unwrap();
        assert_eq!(
            over_socket.status(),
            StatusCode::OK,
            "the socket is authenticated by SO_PEERCRED, not by the token"
        );
    }
}
