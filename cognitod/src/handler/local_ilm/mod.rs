use super::Handler;
use crate::config::ReasonerConfig;
use crate::insights::InsightStore;
use crate::metrics::Metrics;
use crate::{
    ProcessEvent, context::ContextStore, context::ProcessMemorySummary, types::SystemSnapshot,
};
use async_trait::async_trait;
use client::{ChatMessage, IlmClient};
use linnix_ai_ebpf_common::EventType;
use log::{debug, info, warn};
use schema::{Insight, parse_and_validate};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};

pub mod client;
pub mod rag;
pub mod schema;
pub mod tools;

pub use rag::KbIndex;

const CHANNEL_DEPTH: usize = 512;
const MAX_TOOL_LINES: usize = 32;
const MAX_KB_SNIPPETS: usize = 1;
const KB_SNIPPET_MAX_CHARS: usize = 256;

pub struct LocalIlmHandlerRag {
    tx: mpsc::Sender<ProcessEvent>,
}

impl LocalIlmHandlerRag {
    pub async fn try_new(
        cfg: &ReasonerConfig,
        metrics: Arc<Metrics>,
        kb: Option<KbIndex>,
        context: Arc<ContextStore>,
        insights: Arc<InsightStore>,
    ) -> Option<Self> {
        if !cfg.enabled {
            metrics.set_ilm_enabled(false);
            metrics.set_ilm_disabled_reason(Some("disabled_in_config".to_string()));
            return None;
        }

        let endpoint = cfg.endpoint.trim();
        if endpoint.is_empty() {
            metrics.set_ilm_enabled(false);
            metrics.set_ilm_disabled_reason(Some("empty_endpoint".to_string()));
            warn!("[local-ilm] endpoint empty; disabling handler");
            return None;
        }

        let timeout_ms = cfg.timeout_ms.max(1);
        let timeout = Duration::from_millis(timeout_ms);

        let client = match IlmClient::new(endpoint, timeout) {
            Ok(client) => client,
            Err(err) => {
                metrics.set_ilm_enabled(false);
                metrics.set_ilm_disabled_reason(Some(format!("client_error:{err}")));
                warn!("[local-ilm] failed to build HTTP client: {err}");
                return None;
            }
        };

        if let Err(err) = client.check_health().await {
            metrics.set_ilm_enabled(false);
            metrics.set_ilm_disabled_reason(Some("unreachable".to_string()));
            warn!("[local-ilm] LLM endpoint health check failed: {err}");
            return None;
        }

        metrics.set_ilm_enabled(true);
        metrics.set_ilm_disabled_reason(None);

        let (tx, rx) = mpsc::channel(CHANNEL_DEPTH);
        let handler = Self { tx: tx.clone() };
        let metrics_worker = Arc::clone(&metrics);
        let kb_index = kb.map(Arc::new);
        let cfg_clone = cfg.clone();
        let client_clone = client.clone();
        let context_clone = Arc::clone(&context);
        let insights_worker = Arc::clone(&insights);

        tokio::spawn(async move {
            run_worker(
                rx,
                cfg_clone,
                client_clone,
                metrics_worker,
                kb_index,
                context_clone,
                insights_worker,
            )
            .await;
        });

        Some(handler)
    }
}

#[async_trait]
impl Handler for LocalIlmHandlerRag {
    fn name(&self) -> &'static str {
        "local_ilm"
    }

    async fn on_event(&self, event: &ProcessEvent) {
        if self.tx.send(event.clone()).await.is_err() {
            warn!("[local-ilm] dropping event: channel closed");
        }
    }

    async fn on_snapshot(&self, _snapshot: &SystemSnapshot) {}
}

struct WindowSummary {
    forks: usize,
    execs: usize,
    exits: usize,
    top_comm: Vec<String>,
    primary_pid: Option<u32>,
    primary_comm: Option<String>,
    primary_ppid: Option<u32>,
}

async fn run_worker(
    mut rx: mpsc::Receiver<ProcessEvent>,
    cfg: ReasonerConfig,
    client: IlmClient,
    metrics: Arc<Metrics>,
    kb: Option<Arc<KbIndex>>,
    context: Arc<ContextStore>,
    insights: Arc<InsightStore>,
) {
    let mut buffer: Vec<ProcessEvent> = Vec::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.window_seconds.max(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_error: Option<String> = None;
    let mut last_insight: Option<Insight> = None;

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => buffer.push(event),
                    None => break,
                }
            }
            _ = ticker.tick() => {
                if buffer.is_empty() {
                    continue;
                }

                metrics.inc_ilm_windows();

                if metrics.events_per_sec() < cfg.min_eps_to_enable {
                    buffer.clear();
                    continue;
                }

                let events: Vec<ProcessEvent> = std::mem::take(&mut buffer);
                let summary = summarize_window(&events);
                let query = build_query_string(&summary);
                let kb_snippets = kb
                    .as_ref()
                    .map(|index| {
                        index
                            .query(&query, cfg.topk_kb.max(1))
                            .into_iter()
                            .take(MAX_KB_SNIPPETS)
                            .map(|(_, text)| {
                                text.chars()
                                    .take(KB_SNIPPET_MAX_CHARS)
                                    .collect::<String>()
                            })
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();

                let snippets_joined = if kb_snippets.is_empty() {
                    String::new()
                } else {
                    kb_snippets.join("\n---\n")
                };

                let rss_top = context.top_rss_processes(3);
                let mut telemetry_prompt =
                    build_telemetry_prompt(&cfg, &summary, metrics.events_per_sec(), &rss_top);

                // Lightweight enrichment to help the model (kept additive for backward-compat)
                // - cpu_hot: top process by CPU usage (if available)
                // - load: system load averages
                // - pf: page fault count in window
                // - net_bytes/io_bytes: summed bytes seen in window
                // - blk_io: total block IO events in window (queue/issue/complete)
                // - runq: rough run queue pressure (load1/cores)
                {
                    // System load averages
                    let snap = context.get_system_snapshot();

                    // Top CPU process (best effort from live snapshot)
                    let mut top_cpu: Option<(String, f32)> = None;
                    for proc in context.live_snapshot() {
                        if let Some(cpu) = proc.cpu_percent() {
                            if cpu > 0.0 {
                                let name = {
                                    let nul = proc.comm.iter().position(|b| *b == 0).unwrap_or(proc.comm.len());
                                    let slice = &proc.comm[..nul];
                                    let s = String::from_utf8_lossy(slice).trim().to_string();
                                    if s.is_empty() { "unknown".to_string() } else { s }
                                };
                                match top_cpu {
                                    Some((_, best)) if cpu <= best => {}
                                    _ => top_cpu = Some((name, cpu)),
                                }
                            }
                        }
                    }

                    // Window aggregates from events
                    let mut pf_count: u64 = 0;
                    let mut net_bytes: u64 = 0;
                    let mut io_bytes: u64 = 0;
                    let mut blk_io_count: u64 = 0;
                    for e in &events {
                        match e.event_type {
                            x if x == EventType::PageFault as u32 => pf_count += 1,
                            x if x == EventType::Net as u32 => net_bytes = net_bytes.saturating_add(e.data),
                            x if x == EventType::FileIo as u32 => io_bytes = io_bytes.saturating_add(e.data),
                            x if x == EventType::BlockIo as u32 => { io_bytes = io_bytes.saturating_add(e.data); blk_io_count += 1; },
                            _ => {}
                        }
                    }

                    // Append concise extras
                    if let Some((name, cpu)) = top_cpu {
                        use std::fmt::Write as _;
                        let _ = write!(telemetry_prompt, " cpu_hot={}:{:.1}%", name, cpu);
                    }
                    // Always include load averages for broader context
                    {
                        use std::fmt::Write as _;
                        let _ = write!(telemetry_prompt, " load={:.2},{:.2},{:.2}", snap.load_avg[0], snap.load_avg[1], snap.load_avg[2]);
                    }
                    if pf_count > 0 {
                        use std::fmt::Write as _;
                        let _ = write!(telemetry_prompt, " pf={}", pf_count);
                    }
                    if net_bytes > 0 {
                        use std::fmt::Write as _;
                        let _ = write!(telemetry_prompt, " net_bytes={}", net_bytes);
                    }
                    if io_bytes > 0 {
                        use std::fmt::Write as _;
                        let _ = write!(telemetry_prompt, " io_bytes={}", io_bytes);
                    }
                    if blk_io_count > 0 {
                        use std::fmt::Write as _;
                        let _ = write!(telemetry_prompt, " blk_io={}", blk_io_count);
                    }

                    // Run queue approximation: normalize load1 by CPU cores
                    {
                        use sysinfo::System;
                        let sys = System::new_all();
                        let cores = sys.cpus().len().max(1) as f32;
                        let runq = (snap.load_avg[0] / cores).max(0.0);
                        use std::fmt::Write as _;
                        let _ = write!(telemetry_prompt, " runq={:.2}", runq);
                    }
                }
                let user_prompt = build_user_prompt(&telemetry_prompt, &snippets_joined);
                let system_prompt = build_system_prompt();

                let messages = vec![
                    ChatMessage {
                        role: "system",
                        content: system_prompt.clone(),
                    },
                    ChatMessage {
                        role: "user",
                        content: user_prompt.clone(),
                    },
                ];

                let start = Instant::now();
                match client.chat(&messages).await {
                    Ok(mut response) => {
                        if cfg.tools_enabled {
                            if let Some((tool_name, pid)) = detect_tool_request(&response) {
                                let elapsed = start.elapsed();
                                let timeout = client.timeout();
                                if elapsed < timeout.saturating_sub(Duration::from_millis(20)) {
                                    if let Some(tool_context) = execute_tool(tool_name.as_str(), pid) {
                                        let followup_prompt = build_followup_prompt(
                                            &telemetry_prompt,
                                            &snippets_joined,
                                            tool_name.as_str(),
                                    pid,
                                    &tool_context,
                                    &response,
                                );
                                let followup_messages = vec![
                                    ChatMessage {
                                        role: "system",
                                        content: system_prompt.clone(),
                                    },
                                    ChatMessage {
                                        role: "user",
                                        content: followup_prompt,
                                    },
                                ];
                                match client.chat(&followup_messages).await {
                                    Ok(final_response) => response = final_response,
                                    Err(err) => {
                                        metrics.inc_ilm_timeouts();
                                        metrics.set_ilm_enabled(false);
                                        metrics.set_ilm_disabled_reason(Some(format!(
                                            "followup_failed:{}",
                                            err
                                        )));
                                        log_once(&mut last_error, format!(
                                            "[local-ilm] follow-up request failed: {err}"
                                        ));
                                        continue;
                                    }
                                }
                                    }
                                }
                            }
                        }

                        match parse_and_validate(&response) {
                            Ok(insight) => {
                                debug!("[local-ilm] raw insight response: {}", response);
                                emit_insight(&insight, &metrics, insights.as_ref());
                                last_insight = Some(insight.clone());
                                metrics.set_ilm_enabled(true);
                                metrics.set_ilm_disabled_reason(None);
                                last_error = None;
                            }
                            Err(err) => {
                                let mut parsed_fix: Option<Insight> = None;
                                let mut error_message = format!(
                                    "[local-ilm] invalid insight payload: {err}; raw={response}"
                                );

                                let fix_prompt = build_fix_prompt(&err, &response);
                                let fix_messages = vec![
                                    ChatMessage {
                                        role: "system",
                                        content: system_prompt.clone(),
                                    },
                                    ChatMessage {
                                        role: "user",
                                        content: fix_prompt,
                                    },
                                ];

                                match client.chat(&fix_messages).await {
                                    Ok(fix_response) => {
                                        debug!(
                                            "[local-ilm] fix-up raw response: {}",
                                            fix_response
                                        );
                                        match parse_and_validate(&fix_response) {
                                            Ok(insight) => {
                                                parsed_fix = Some(insight.clone());
                                                emit_insight(&insight, &metrics, insights.as_ref());
                                                last_insight = Some(insight);
                                                metrics.set_ilm_enabled(true);
                                                metrics.set_ilm_disabled_reason(None);
                                                last_error = None;
                                            }
                                            Err(fix_err) => {
                                                error_message = format!(
                                                    "[local-ilm] invalid insight after fix: {fix_err}; original_error={err}; raw_fix={fix_response}"
                                                );
                                            }
                                        }
                                    }
                                    Err(fix_err) => {
                                        error_message = format!(
                                            "[local-ilm] fix-up request failed: {fix_err}; original_error={err}; raw={response}"
                                        );
                                    }
                                }

                                if parsed_fix.is_none() {
                                    metrics.inc_ilm_schema_errors();
                                    if let Some(insight) = last_insight.clone() {
                                        warn!(
                                            "[local-ilm] falling back to last known insight due to parse error"
                                        );
                                        emit_insight(&insight, &metrics, insights.as_ref());
                                        metrics.set_ilm_enabled(true);
                                        metrics
                                            .set_ilm_disabled_reason(Some("fallback_last_insight".to_string()));
                                        log_once(&mut last_error, error_message);
                                    } else {
                                        metrics.set_ilm_enabled(false);
                                        metrics
                                            .set_ilm_disabled_reason(Some("schema_error".to_string()));
                                        log_once(&mut last_error, error_message);
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        metrics.inc_ilm_timeouts();
                        metrics.set_ilm_enabled(false);
                        let is_timeout = err
                            .downcast_ref::<reqwest::Error>()
                            .map(|e| e.is_timeout())
                            .unwrap_or(false);
                        let reason = if is_timeout { "timeout" } else { "request_failed" };
                        metrics.set_ilm_disabled_reason(Some(reason.to_string()));
                        log_once(&mut last_error, format!(
                            "[local-ilm] request failed: {err}"
                        ));
                    }
                }
            }
        }
    }
}

fn summarize_window(events: &[ProcessEvent]) -> WindowSummary {
    let mut forks = 0usize;
    let mut execs = 0usize;
    let mut exits = 0usize;
    let mut comm_counts: HashMap<String, usize> = HashMap::new();
    let mut pid_counts: HashMap<u32, usize> = HashMap::new();
    let mut pid_comm: HashMap<u32, String> = HashMap::new();
    let mut pid_ppid: HashMap<u32, u32> = HashMap::new();

    for event in events {
        match event.event_type {
            x if x == EventType::Fork as u32 => forks += 1,
            x if x == EventType::Exec as u32 => execs += 1,
            x if x == EventType::Exit as u32 => exits += 1,
            _ => {}
        }
        let comm = comm_from_bytes(&event.base.comm);
        *comm_counts.entry(comm.clone()).or_insert(0) += 1;
        *pid_counts.entry(event.base.pid).or_insert(0) += 1;
        pid_comm.entry(event.base.pid).or_insert(comm);
        pid_ppid.entry(event.base.pid).or_insert(event.base.ppid);
    }

    let mut top_comm: Vec<(String, usize)> = comm_counts.into_iter().collect();
    top_comm.sort_by(|a, b| b.1.cmp(&a.1));
    let top_comm_names = top_comm
        .into_iter()
        .take(3)
        .map(|(name, _)| name)
        .collect::<Vec<_>>();

    let primary_pid = pid_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(pid, _)| pid);

    let primary_comm = primary_pid.and_then(|pid| pid_comm.get(&pid).cloned());
    let primary_ppid = primary_pid.and_then(|pid| pid_ppid.get(&pid).copied());

    WindowSummary {
        forks,
        execs,
        exits,
        top_comm: top_comm_names,
        primary_pid,
        primary_comm,
        primary_ppid,
    }
}

fn build_query_string(summary: &WindowSummary) -> String {
    let mut parts = Vec::new();
    if let Some(comm) = &summary.primary_comm {
        parts.push(comm.clone());
    }
    parts.extend(summary.top_comm.clone());
    parts.push(format!("forks:{}", summary.forks));
    parts.push(format!("execs:{}", summary.execs));
    parts.push(format!("exits:{}", summary.exits));
    parts.join(" ")
}

fn build_system_prompt() -> String {
    r#"You are an SRE assistant. Reply with exactly one JSON object and nothing else. Do NOT output arrays, multiple objects, code fences, markdown, or explanatory text. The object must contain the keys "class", "confidence", "primary_process", "why", and "actions". Valid values:
- "class": one of "fork_storm", "short_job_flood", "runaway_tree", "cpu_spin", "io_saturation", "oom_risk", "normal" (lowercase, underscores).
- "confidence": number between 0 and 1 (e.g. 0.45).
- "primary_process": quoted process name or null.
- "why": short sentence (<=120 chars) that references the telemetry.
- "actions": array of up to 3 actionable strings (empty array when none).
Populate them with conclusions drawn from the provided telemetry and knowledge snippets. If a field is unknown, use a sensible null/empty value. Responses that are not a single JSON object will be rejected."#
        .to_string()
}

fn build_user_prompt(telemetry: &str, snippets: &str) -> String {
    let schema = "{class:fork_storm|short_job_flood|runaway_tree|cpu_spin|io_saturation|oom_risk|normal,confidence:0-1,primary_process?:str/null,why<=120,actions<=3}";
    let kb = if snippets.is_empty() {
        "kb:none".to_string()
    } else {
        format!("kb:{}", snippets)
    };
    format!(
        "schema:{schema}\n{kb}\ntelemetry:{telemetry}\nGuidance:\n1. Decide class & confidence based on the telemetry (use the exact class strings listed above).\n2. Choose primary_process name if evident, otherwise null.\n3. Write a human-readable why (<=120 chars) grounded in the telemetry.\n4. Provide up to 3 concrete mitigation actions, or [] if none.\nReturn only ONE JSON object (no array, no trailing commentary). Replace the placeholders below with your final values—do NOT leave tokens like CLASS_VALUE/WHY_TEXT/ACTION_VALUES in the output:\n{{\"class\":\"CLASS_VALUE\",\"confidence\":CONFIDENCE_VALUE,\"primary_process\":PRIMARY_PROCESS_VALUE,\"why\":\"WHY_TEXT\",\"actions\":[ACTION_VALUES]}}\nDouble-check before replying: class is lowercase, confidence is numeric, why is not empty, every action is quoted."
    )
}

fn build_fix_prompt(error: &str, previous_response: &str) -> String {
    format!(
        "Your previous reply was rejected because: {error}.\nPrevious reply:\n{previous_response}\n\nReturn a corrected insight as ONE JSON object with no prefix text. Do not start with words like Response, Schema, or ```.\nUse this exact structure (replace tokens with real values and keep lowercase class names):\n{{\"class\":\"fork_storm|short_job_flood|runaway_tree|cpu_spin|io_saturation|oom_risk|normal\",\"confidence\":0.0-1.0,\"primary_process\":null|\"process_name\",\"why\":\"short sentence <=120 chars\",\"actions\":[\"action 1\",\"action 2\"]}}\nRules:\n- class must be one of the allowed strings (lowercase, underscores)\n- confidence must be a numeric literal between 0 and 1\n- primary_process is either null or a quoted process name\n- why must be a non-empty sentence referencing telemetry (<=120 chars)\n- actions is an array with up to 3 quoted actions (use [] if none)\n- Do NOT add any other keys; only class/confidence/primary_process/why/actions are allowed\n- Every string must be plain text (no placeholders like ACTION_VALUES or WHY_TEXT)\nReply with ONLY the JSON object."
    )
}

fn build_telemetry_prompt(
    cfg: &ReasonerConfig,
    summary: &WindowSummary,
    eps: u64,
    rss_top: &[ProcessMemorySummary],
) -> String {
    let top = if summary.top_comm.is_empty() {
        "none".to_string()
    } else {
        summary.top_comm.join(",")
    };
    let tree = build_tree_summary(summary);
    let rss = if rss_top.is_empty() {
        "none".to_string()
    } else {
        rss_top
            .iter()
            .map(|proc| format!("{}:{}:{:.1}%", proc.pid, proc.comm, proc.mem_percent))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "w={} eps={} frk={} exe={} ext={} top={} rss={} tree={}",
        cfg.window_seconds, eps, summary.forks, summary.execs, summary.exits, top, rss, tree
    )
}

fn build_tree_summary(summary: &WindowSummary) -> String {
    match (
        summary.primary_pid,
        summary.primary_comm.as_ref(),
        summary.primary_ppid,
    ) {
        (Some(pid), Some(comm), Some(ppid)) => format!("pid={} comm={} ppid={}", pid, comm, ppid),
        (Some(pid), Some(comm), None) => format!("pid={} comm={} ppid=?", pid, comm),
        _ => "n/a".to_string(),
    }
}

fn detect_tool_request(response: &str) -> Option<(String, i32)> {
    let first_line = response.lines().next()?.trim();
    let rest = first_line.strip_prefix("TOOL:")?.trim();
    let mut parts = rest.split_whitespace();
    let tool = parts.next()?.to_lowercase();
    let pid: i32 = parts.next()?.parse().ok()?;
    Some((tool, pid))
}

fn execute_tool(tool: &str, pid: i32) -> Option<String> {
    use tools::*;
    match tool {
        "ps_tree" => Some(match ps_tree(pid) {
            Ok(output) => trim_tool_output(output),
            Err(err) => format_tool_error(tool, err),
        }),
        "proc_status" => Some(match proc_status(pid) {
            Ok(output) => trim_tool_output(output),
            Err(err) => format_tool_error(tool, err),
        }),
        "cgroup_cpu" => Some(match cgroup_cpu(pid) {
            Ok(output) => trim_tool_output(output),
            Err(err) => format_tool_error(tool, err),
        }),
        "open_fds" => Some(format_count("open_fds", open_fds(pid))),
        "net_conns" => Some(format_count("net_conns", net_conns(pid))),
        _ => None,
    }
}

fn trim_tool_output(output: String) -> String {
    let mut lines: Vec<&str> = output.lines().collect();
    if lines.len() > MAX_TOOL_LINES {
        lines.truncate(MAX_TOOL_LINES);
    }
    lines.join("\n")
}

fn build_followup_prompt(
    telemetry_prompt: &str,
    snippets: &str,
    tool: &str,
    pid: i32,
    tool_output: &str,
    draft: &str,
) -> String {
    let header = if snippets.is_empty() {
        "Schema: class/confidence/primary_process/why/actions as defined earlier\nKB: <<< >>>"
            .to_string()
    } else {
        format!(
            "Schema: class/confidence/primary_process/why/actions as defined earlier\nKB: <<< {} >>>",
            snippets
        )
    };
    format!(
        "{header}\n{telemetry_prompt}\nTool result ({tool} pid {pid}):\n{tool_output}\nPrior draft: {draft}\nTask: Re-evaluate with tool context and output JSON only."
    )
}

fn emit_insight(insight: &Insight, metrics: &Metrics, store: &InsightStore) {
    let class = insight.class.as_str();
    info!(
        "[local-ilm] insight class={} confidence={:.2} why={} actions={:?}",
        class, insight.confidence, insight.why, insight.actions
    );
    metrics.inc_ilm_insights();
    if insight.class.triggers_alert() {
        metrics.inc_alerts_emitted();
    }
    store.record(insight.clone());
}

fn log_once(last_error: &mut Option<String>, message: String) {
    if last_error.as_ref() != Some(&message) {
        warn!("{message}");
        *last_error = Some(message);
    }
}

fn comm_from_bytes(bytes: &[u8; 16]) -> String {
    let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let slice = &bytes[..nul];
    let text = String::from_utf8_lossy(slice).trim().to_string();
    if text.is_empty() {
        "unknown".to_string()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProcessEventWire;
    use crate::config::ReasonerConfig;
    use crate::context::ContextStore;
    use crate::handler::Handler;
    use crate::metrics::Metrics;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use linnix_ai_ebpf_common::{EventType, PERCENT_MILLI_UNKNOWN};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::time::Duration;

    async fn spawn_mock_server() -> std::net::SocketAddr {
        async fn models_handler() -> impl IntoResponse {
            Json(json!({"data": []}))
        }

        async fn completions_handler() -> impl IntoResponse {
            Json(json!({
                "choices": [
                    {
                        "message": {
                            "content": "{\"class\":\"fork_storm\",\"confidence\":0.82,\"why\":\"forks spiked\",\"actions\":[\"pstree -ap 123\",\"renice 10 123\",\"ionice -c3 123\"]}"
                        }
                    }
                ]
            }))
        }

        let app = Router::new()
            .route("/v1/models", get(models_handler))
            .route("/v1/chat/completions", post(completions_handler));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app.into_make_service()).await {
                eprintln!("mock server error: {err}");
            }
        });
        addr
    }

    fn sample_event(pid: u32, event_type: EventType) -> ProcessEvent {
        let mut comm = [0u8; 16];
        let name = b"forker";
        comm[..name.len()].copy_from_slice(name);
        let base = ProcessEventWire {
            pid,
            ppid: 1,
            uid: 0,
            gid: 0,
            event_type: event_type as u32,
            ts_ns: 0,
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
        ProcessEvent::new(base)
    }

    #[tokio::test]
    async fn emits_insight_for_fork_burst() {
        let addr = spawn_mock_server().await;
        let cfg = ReasonerConfig {
            enabled: true,
            endpoint: format!("http://{addr}/v1/chat/completions"),
            window_seconds: 1,
            timeout_ms: 200,
            min_eps_to_enable: 1,
            topk_kb: 1,
            tools_enabled: false,
            ..ReasonerConfig::default()
        };

        let metrics = Arc::new(Metrics::new());
        let context = Arc::new(ContextStore::new(Duration::from_secs(60), 100));
        let insight_store = Arc::new(InsightStore::new(16, None));
        let handler = LocalIlmHandlerRag::try_new(
            &cfg,
            Arc::clone(&metrics),
            None,
            Arc::clone(&context),
            Arc::clone(&insight_store),
        )
        .await
        .expect("handler should initialize");

        for _ in 0..20 {
            metrics.record_event(u64::MAX, EventType::Fork as u32);
            let event = sample_event(1234, EventType::Fork);
            handler.on_event(&event).await;
        }
        metrics.rollup();

        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(metrics.ilm_insights() > 0, "expected at least one insight");
        assert_eq!(metrics.ilm_schema_errors(), 0);
        assert_eq!(metrics.ilm_timeouts(), 0);
    }
}
