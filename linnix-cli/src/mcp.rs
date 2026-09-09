//! `linnix-cli mcp serve` — cognitod's facts, exposed to any MCP client.
//!
//! The reasoning about an incident is not the scarce thing any more; a
//! frontier model can already form a good hypothesis about why a pod got slow.
//! What it cannot do is look at the machine. This module's whole job is to put
//! what cognitod observed in front of whatever model is asking, and to stop
//! there.
//!
//! Two rules follow from that, and both are load-bearing:
//!
//! 1. **Nothing is analysed here.** Every tool below is a presentation of an
//!    analysis that already exists in this crate — `investigate::summarise`
//!    for contention, `explain::render` for a stored incident. A second
//!    implementation would be free to drift from what `linnix-cli investigate`
//!    prints, and then two Linnix answers about one machine would disagree.
//! 2. **No confidence score is emitted.** What the daemon establishes is
//!    contention attribution, not proven causality: these workloads contended
//!    over a resource while the victim stalled. A float labelled `confidence`
//!    would be read by a consuming model as calibrated, and nothing here
//!    calibrates it. The tools return the evidence — shares, windows, peak CPU
//!    share, the classified signal — and let the model draw the conclusion.

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::error::Error;

use crate::explain::{self, IncidentView};
use crate::investigate::{self, AttributionResponse, Investigation};

/// How much of an answer the caller wants.
///
/// This is the context compiler in one argument. A large context window does
/// not make it free to send an agent every process event on the box, so an
/// answer starts as a sentence and the caller pays for evidence only once it
/// has decided the answer matters.
#[derive(Deserialize, JsonSchema, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    /// One or two sentences: the conclusion and the strongest number behind
    /// it. For triage, when the caller does not yet know if this host matters.
    Summary,
    /// The compiled facts. The default, and what a caller should reason from.
    #[default]
    Evidence,
    /// The daemon's own JSON, for a caller that intends to quote it.
    Raw,
}

/// What `/readyz` said, and the daemon's own reply when it sent one.
struct Readiness {
    /// Kept for the raw tier. `None` when nothing parseable came back.
    body: Option<serde_json::Value>,
    verdict: Verdict,
    /// Whether eBPF probes are attached, read independently of `verdict`.
    /// `verdict` folds in `require_kernel_instrumentation`, so a daemon
    /// deliberately run with that policy off answers `ready:true` even with
    /// probes unattached -- that policy says the operator accepts running
    /// degraded, not that this client should stop saying so.
    probes_attached: Option<bool>,
}

/// Deliberately three-valued. "Not ready" and "could not tell" lead an agent
/// to different next steps, and collapsing either into "ready" is the failure
/// this endpoint is consulted to prevent.
enum Verdict {
    Ready,
    NotReady(String),
    Unknown(String),
}

/// A failed fetch, and whether the daemon simply had no such record.
///
/// The distinction exists for exactly one caller: `explain_process` fetches a
/// process and then its tree, and a process that exits between the two gets a
/// 404 on the second. That race is worth downgrading to a note. A network
/// error, a 5xx or a token that stopped working is not — reported as "the
/// process may have exited", it would have an agent conclude the box is fine
/// when the truth is that we cannot see it.
struct FetchError {
    message: String,
    not_found: bool,
}

impl FetchError {
    fn fatal(message: String) -> Self {
        Self {
            message,
            not_found: false,
        }
    }
}

/// The MCP server. Holds only what it needs to reach a cognitod.
#[derive(Clone)]
pub struct LinnixMcp {
    client: reqwest::Client,
    /// Base URL, already stripped of any trailing slash so paths can be
    /// appended without producing a double slash the daemon would 404.
    base: String,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, JsonSchema, Debug)]
pub struct HealthParams {
    #[serde(default)]
    pub detail: Detail,
}

#[derive(Deserialize, JsonSchema, Debug)]
pub struct ContentionParams {
    /// Kubernetes namespace of the pod that was slow.
    pub namespace: String,
    /// Name of the pod that was slow — the victim, not the suspect.
    pub pod: String,
    /// How far back to look, e.g. `20m`, `1h`, `90s`. Defaults to 15m.
    #[serde(default = "default_since")]
    pub since: String,
    #[serde(default)]
    pub detail: Detail,
}

fn default_since() -> String {
    "15m".to_string()
}

#[derive(Deserialize, JsonSchema, Debug)]
pub struct ProcessParams {
    /// The PID to look up, as reported by `linnix_recent_incidents` or by the
    /// host itself.
    pub pid: u32,
    #[serde(default)]
    pub detail: Detail,
}

#[derive(Deserialize, JsonSchema, Debug)]
pub struct IncidentsParams {
    /// How many incidents to return, newest first. Defaults to 10.
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub detail: Detail,
}

fn default_limit() -> u32 {
    10
}

#[derive(Deserialize, JsonSchema, Debug)]
pub struct IncidentParams {
    /// Incident id, as listed by `linnix_recent_incidents`.
    pub id: i64,
    #[serde(default)]
    pub detail: Detail,
}

/// The daemon's `/status` payload. Mirrors the CLI's own `Status`, kept
/// separate because that one lives in `main.rs` and is not importable.
#[derive(Deserialize, Debug)]
struct Status {
    cpu_pct: f64,
    rss_mb: u64,
    events_per_sec: u64,
    rb_overflows: u64,
    rate_limited: u64,
    /// Events the listener's bounded worker queue dropped specifically under
    /// backpressure -- a third, independent source of loss from
    /// rb_overflows/rate_limited. Deliberately *not* `dropped_events_total`:
    /// that counter also aggregates every rate-limited event and SSE
    /// subscriber-lag drops, so using it here would both double-count
    /// rate-limiting and warn on an unrelated slow subscriber even when
    /// every event actually reached cognitod. Defaulted because a daemon
    /// predating this counter simply won't send it, not because a missing
    /// value should be assumed loss-free.
    #[serde(default)]
    listener_queue_drops: u64,
    /// True when the daemon is running without its event source attached, so
    /// every other number below describes a daemon that is not seeing the
    /// machine. Worth reporting first: it is the difference between "the host
    /// is quiet" and "we are not looking".
    offline: bool,
}

/// The daemon's `/system` payload.
///
/// The PSI fields are the ones worth an agent's attention. `avg10` is the
/// share of the last ten seconds during which at least one task was stalled
/// waiting for that resource — a number that stays near zero on a busy but
/// healthy host, which is exactly what plain utilisation cannot tell you.
#[derive(Deserialize, Debug)]
struct SystemSnapshot {
    cpu_percent: f32,
    mem_percent: f32,
    load_avg: [f32; 3],
    psi_cpu_some_avg10: f32,
    psi_memory_some_avg10: f32,
    psi_memory_full_avg10: f32,
    psi_io_some_avg10: f32,
    psi_io_full_avg10: f32,
}

#[tool_router]
impl LinnixMcp {
    pub fn new(client: reqwest::Client, base: &str) -> Self {
        Self {
            client,
            base: base.trim_end_matches('/').to_string(),
            tool_router: Self::tool_router(),
        }
    }

    /// Fetches and decodes one endpoint.
    ///
    /// The message is a caller-facing sentence, because every failure here
    /// ends up in front of a model that has to decide what to do next and
    /// "connection refused" is not that. An agent's first contact with this
    /// server is very often a laptop with no daemon running, so that case in
    /// particular has to say what to start.
    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, FetchError> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .client
            .get(&url)
            .query(query)
            .send()
            .await
            .map_err(|e| {
                FetchError::fatal(format!(
                    "cannot reach cognitod at {}: {e}. Start the daemon, or point this \
                     server at the right host with `linnix-cli mcp serve --url <URL>`. If the \
                     daemon requires a token, set LINNIX_API_TOKEN in this server's \
                     environment.",
                    self.base
                ))
            })?;

        match resp.status() {
            reqwest::StatusCode::NOT_FOUND => {
                return Err(FetchError {
                    message: format!("cognitod has no record at {path}"),
                    not_found: true,
                });
            }
            // Only the two history routes are backed by the optional incident
            // store. For those, saying so is the difference between "there
            // were no incidents" and "this daemon cannot answer that question"
            // — an agent told the former would wrongly rule the host out. For
            // the live routes, which have no store behind them, a 503 is an
            // ordinary outage, usually a proxy, and claiming a deliberate
            // configuration would send an operator to edit a config that is
            // not the problem.
            reqwest::StatusCode::SERVICE_UNAVAILABLE if store_backed(path) => {
                return Err(FetchError::fatal(format!(
                    "cognitod is running without the store that backs {path}, so no history \
                     exists to query. This is a daemon configuration, not an absence of events."
                )));
            }
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                return Err(FetchError::fatal(format!(
                    "cognitod rejected the request to {path} ({}). It was started with an API \
                     token; set LINNIX_API_TOKEN in the environment this MCP server is \
                     launched with.",
                    resp.status()
                )));
            }
            status if !status.is_success() => {
                return Err(FetchError::fatal(format!(
                    "cognitod returned {status} for {path}"
                )));
            }
            _ => {}
        }

        resp.json::<T>().await.map_err(|e| {
            FetchError::fatal(format!("could not decode cognitod's reply to {path}: {e}"))
        })
    }

    /// The daemon's own answer to "am I actually instrumenting this host?".
    ///
    /// Read separately from `/status` because it is the only authoritative
    /// signal: `events_per_sec` is zero on a quiet healthy host and on a
    /// daemon whose probes never attached, and those two need to reach an
    /// agent as different facts. `/readyz` answers 503 when it is the second,
    /// so the body has to be read past the status code rather than through
    /// `get`, which treats a 503 as a failure.
    ///
    /// A reply this client cannot read is reported as *unknown*, never as
    /// ready. Silence is the one answer that must not be possible here: this
    /// endpoint is the only thing standing between an agent and a blind daemon
    /// that looks healthy, so a proxy 404, a truncated body or a JSON object
    /// with no `ready` key all have to reach the caller as "we could not
    /// establish this" rather than as nothing at all.
    async fn readiness(&self) -> Readiness {
        let resp = match self
            .client
            .get(format!("{}/readyz", self.base))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Readiness {
                    body: None,
                    verdict: Verdict::Unknown(format!("/readyz could not be reached: {e}")),
                    probes_attached: None,
                };
            }
        };

        let status = resp.status();
        let body = match resp.json::<serde_json::Value>().await {
            Ok(body) => body,
            Err(e) => {
                return Readiness {
                    body: None,
                    verdict: Verdict::Unknown(format!(
                        "/readyz answered {status} with something this client could not \
                         parse: {e}"
                    )),
                    probes_attached: None,
                };
            }
        };

        let verdict = match body.get("ready").and_then(|v| v.as_bool()) {
            Some(true) => Verdict::Ready,
            Some(false) => Verdict::NotReady(
                body.get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("cognitod reports that it is not ready.")
                    .to_string(),
            ),
            // Something answered on this URL, and it was not cognitod's
            // readiness endpoint. A proxy error page parses as JSON perfectly
            // well and says nothing about the daemon.
            None => Verdict::Unknown(format!(
                "/readyz answered {status} without a `ready` verdict, so whether cognitod is \
                 instrumenting this host could not be established"
            )),
        };
        // Read independently of `ready`: the daemon folds
        // require_kernel_instrumentation into `ready`, so this must not be
        // inferred from the verdict above.
        let probes_attached = body
            .get("kernel_instrumentation")
            .and_then(|v| v.as_str())
            .map(|s| s == "active");
        Readiness {
            body: Some(body),
            verdict,
            probes_attached,
        }
    }

    /// Everything that can make an attribution result look emptier or
    /// cleaner than it really is: probes never attached, or events the
    /// kernel produced that never reached cognitod. A `/status` fetch
    /// failing here does not fail the tool call, since the attribution
    /// query it qualifies already succeeded or failed on its own terms --
    /// but it must not go silent either: "could not check" is a different
    /// fact from "no loss" and has to reach the caller as such.
    async fn contention_caveats(&self) -> String {
        let mut out = readiness_note(&self.readiness().await);
        match self.get::<Status>("/status", &[]).await {
            Ok(status) => out.push_str(&event_loss_note(&status)),
            Err(e) => out.push_str(&format!(
                "WARNING: event loss unknown -- /status could not be read ({}), so whether \
                 kernel events were dropped before reaching cognitod could not be \
                 established.\n",
                single_line(&e.message)
            )),
        }
        out
    }

    #[tool(
        name = "linnix_system_health",
        description = "Is this Linux host under resource pressure right now? Returns live CPU, \
                       memory and PSI (pressure stall information) for the host cognitod runs \
                       on, plus whether the daemon itself is healthy. PSI avg10 is the share of \
                       the last ten seconds in which at least one task was stalled waiting on \
                       that resource; it stays near zero on a busy but healthy host, which is \
                       what plain utilisation cannot tell you. Warns first if cognitod's kernel \
                       probes are not attached, since a daemon in that state still serves \
                       plausible host readings while attributing nothing to any process. Call \
                       this first when triaging a host you know nothing about."
    )]
    async fn system_health(
        &self,
        Parameters(params): Parameters<HealthParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // Fetched undecoded and decoded afterwards, so the raw tier can hand
        // back what cognitod actually sent. Rebuilding the JSON from the
        // structs below would drop every field this crate does not declare —
        // the byte and timestamp counters `/system` carries among them —
        // while still calling itself raw.
        let status_json: serde_json::Value = match self.get("/status", &[]).await {
            Ok(v) => v,
            Err(e) => return Ok(tool_error(e.message)),
        };
        let system_json: serde_json::Value = match self.get("/system", &[]).await {
            Ok(v) => v,
            Err(e) => return Ok(tool_error(e.message)),
        };

        let status: Status = match serde_json::from_value(status_json.clone()) {
            Ok(s) => s,
            Err(e) => return Ok(tool_error(format!("could not decode /status: {e}"))),
        };
        let system: SystemSnapshot = match serde_json::from_value(system_json.clone()) {
            Ok(s) => s,
            Err(e) => return Ok(tool_error(format!("could not decode /system: {e}"))),
        };

        let readiness = self.readiness().await;
        let mut out = render_health(&status, &system, &readiness, params.detail);
        if params.detail == Detail::Raw {
            if let Some(body) = &readiness.body {
                out.push_str("\n/readyz, as the daemon sent it:\n");
                out.push_str(&pretty_json(body));
                out.push('\n');
            }
            out.push_str("\n/status, as the daemon sent it:\n");
            out.push_str(&pretty_json(&status_json));
            out.push_str("\n\n/system, as the daemon sent it:\n");
            out.push_str(&pretty_json(&system_json));
            out.push('\n');
        }
        Ok(text(out))
    }

    #[tool(
        name = "linnix_investigate_contention",
        description = "Which other workloads contended with this pod while it stalled, and on \
                       what evidence? Give the namespace and name of the pod that was SLOW (the \
                       victim), not of a suspect. Returns each neighbouring pod that cognitod \
                       attributed part of the victim's stall to, its share, how many detection \
                       windows it appeared in, its peak CPU share and the signal that dominated \
                       (CPU noisy neighbour, fork storm, short-job churn). IMPORTANT: this is \
                       contention attribution, not proven causality — it establishes that these \
                       workloads contended over a resource while the victim stalled, not that \
                       removing them would have prevented the stall. An empty result rules \
                       neighbours out, not the pod's own limits, throttling or workload."
    )]
    async fn investigate_contention(
        &self,
        Parameters(params): Parameters<ContentionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if params.namespace.trim().is_empty() || params.pod.trim().is_empty() {
            return Ok(tool_error(
                "namespace and pod are both required, and name the pod that was slow".to_string(),
            ));
        }
        let window = match investigate::parse_since_minutes(&params.since) {
            Ok(w) => w,
            Err(msg) => return Ok(tool_error(msg)),
        };
        let query = [
            ("pod", params.pod.clone()),
            ("namespace", params.namespace.clone()),
            ("window", window.to_string()),
        ];

        // The raw tier promises the daemon's own words, so it has to be the
        // daemon's own bytes. Decoding into `AttributionResponse` first would
        // silently drop every field cognitod sends that this crate does not
        // declare — `blame_score` and the top-level `victim` and
        // `window_minutes` among them — while still calling itself raw. A
        // caller quoting a filtered view believing it complete is worse off
        // than one who asked for prose.
        if params.detail == Detail::Raw {
            let mut raw: serde_json::Value = match self.get("/attribution", &query).await {
                Ok(v) => v,
                Err(e) => return Ok(tool_error(e.message)),
            };
            // The window slides, so these rows stop being reachable by the
            // same question within minutes. The link is evidence, not
            // garnish -- but it has to stay inside the JSON, not appended as
            // trailing prose, or a caller parsing this tier's documented
            // payload gets a parse error on an otherwise-healthy response.
            if let Some(path) = raw.get("permalink").and_then(|v| v.as_str()) {
                let absolute = format!("{}{}", self.base, path);
                raw["permalink"] = serde_json::Value::String(absolute);
            }
            let out = pretty_json(&raw);
            // The raw tier can hand back an empty attributions array just as
            // legitimately-but-misleadingly as summary/evidence can, so it
            // needs the same warnings, not just the same bytes.
            let out = format!("{}{out}", self.contention_caveats().await);
            return Ok(text(out));
        }

        let body: AttributionResponse = match self.get("/attribution", &query).await {
            Ok(b) => b,
            Err(e) => return Ok(tool_error(e.message)),
        };

        let investigation = investigate::summarise(&body.attributions);

        // The daemon returns a path; only the caller knows which host it
        // reached, so the absolute link can only be assembled here.
        let permalink = body
            .permalink
            .as_ref()
            .map(|path| format!("{}{}", self.base, path));

        let mut out = match params.detail {
            Detail::Summary => contention_headline(
                &investigation,
                &params.namespace,
                &params.pod,
                &params.since,
            ),
            // Reusing the CLI's renderer is the point: a caller comparing this
            // answer against `linnix-cli investigate` output sees the same words.
            Detail::Evidence | Detail::Raw => investigate::render(
                &investigation,
                &params.namespace,
                &params.pod,
                &params.since,
                false,
                permalink.as_deref(),
            ),
        };

        // A daemon running userspace-only, or one that dropped events to an
        // overflow or the rate limiter, produces no (or incomplete)
        // per-process attribution -- claims this tool must not conflate with
        // "genuinely no contention", same as linnix_system_health.
        out = format!("{}{out}", self.contention_caveats().await);

        Ok(text(out))
    }

    #[tool(
        name = "linnix_explain_process",
        description = "What is this PID: what is it running, how long has it been alive, how \
                       much CPU and memory is it using, and which Kubernetes pod does it belong \
                       to? At detail=evidence or above it also returns the process tree around \
                       it — ancestors and descendants — which is what identifies a fork storm or \
                       a runaway child that a single process row does not show."
    )]
    async fn explain_process(
        &self,
        Parameters(params): Parameters<ProcessParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc: serde_json::Value =
            match self.get(&format!("/processes/{}", params.pid), &[]).await {
                Ok(p) => p,
                Err(e) => return Ok(tool_error(e.message)),
            };

        if params.detail == Detail::Summary {
            return Ok(text(process_headline(params.pid, &proc)));
        }

        // A live process always has a graph, but a process that exited between
        // the two requests does not. That race is worth absorbing; nothing
        // else is. Reporting a 5xx or an expired token as "the process may
        // have exited" would tell an agent the tree is empty when the truth is
        // that we could not read it.
        let graph: Option<serde_json::Value> =
            match self.get(&format!("/graph/{}", params.pid), &[]).await {
                Ok(graph) => Some(graph),
                Err(e) if e.not_found => None,
                Err(e) => return Ok(tool_error(e.message)),
            };

        let mut out = process_headline(params.pid, &proc);
        if params.detail == Detail::Raw {
            out.push('\n');
            out.push_str(&pretty_json(&proc));
            out.push('\n');
        }
        match &graph {
            Some(graph) => {
                out.push_str("\nProcess tree around this PID:\n");
                out.push_str(&match params.detail {
                    Detail::Raw => pretty_json(graph),
                    _ => render_tree(graph),
                });
            }
            None => {
                out.push_str("\nThe process tree could not be read; the process may have exited.\n")
            }
        }
        Ok(text(out))
    }

    #[tool(
        name = "linnix_recent_incidents",
        description = "What has cognitod flagged on this host recently? Returns stored incidents \
                       newest first: when, what kind, what the daemon did about it, and the CPU \
                       and PSI readings that triggered it. Use this to find an incident id, then \
                       call linnix_explain_incident for the reasoning and evidence behind one."
    )]
    async fn recent_incidents(
        &self,
        Parameters(params): Parameters<IncidentsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let incidents: Vec<serde_json::Value> = match self
            .get("/incidents", &[("limit", params.limit.to_string())])
            .await
        {
            Ok(i) => i,
            Err(e) => return Ok(tool_error(e.message)),
        };

        // The raw tier's promise is the daemon's own bytes, and `[]` is a
        // perfectly valid one -- prose here would break a caller parsing
        // this as JSON in exactly the case that is easiest to hit, a quiet
        // host. The substitution only makes sense for the tiers that were
        // already prose.
        if incidents.is_empty() && params.detail != Detail::Raw {
            return Ok(text(
                "cognitod has recorded no incidents on this host in its retained history.\n"
                    .to_string(),
            ));
        }

        let out = match params.detail {
            Detail::Raw => pretty_json(&incidents),
            _ => {
                let mut lines = format!("{} recent incident(s), newest first:\n", incidents.len());
                for incident in &incidents {
                    lines.push_str(&incident_line(incident, params.detail));
                }
                lines
            }
        };
        Ok(text(out))
    }

    #[tool(
        name = "linnix_explain_incident",
        description = "What was concluded about one incident, and on what evidence? Returns the \
                       daemon's own stored rendering of the investigation: the hypotheses it \
                       kept and the observations supporting each. The wording is the daemon's \
                       verbatim, so a hypothesis shown here was grounded against facts the \
                       daemon supplied rather than restated by this server."
    )]
    async fn explain_incident(
        &self,
        Parameters(params): Parameters<IncidentParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if params.detail == Detail::Raw {
            let raw: serde_json::Value =
                match self.get(&format!("/incidents/{}", params.id), &[]).await {
                    Ok(v) => v,
                    Err(e) => return Ok(tool_error(e.message)),
                };
            return Ok(text(pretty_json(&raw)));
        }

        let view: IncidentView = match self.get(&format!("/incidents/{}", params.id), &[]).await {
            Ok(v) => v,
            Err(e) => return Ok(tool_error(e.message)),
        };

        // `sanitized` strips terminal controls from every string that came
        // from the daemon, several of which — `target_name` is `proc.comm` —
        // were chosen by whoever started the process. An MCP client is not a
        // terminal, but the same strings are what a model will quote back into
        // one, so the boundary is still the right place to clean them.
        let view = view.sanitized();

        // A stored investigation runs to hundreds of tokens. A caller told to
        // start at `summary` must not be charged for one just to find out
        // whether this incident is the one it is looking for.
        if params.detail == Detail::Summary {
            return Ok(text(incident_headline(&view, params.id)));
        }

        Ok(text(explain::render(&view, params.id, false)))
    }
}

// `router = self.tool_router` points the generated `call_tool` at the router
// built once in `new`. Without it the macro rebuilds the whole router, schemas
// included, on every single tool call.
#[tool_handler(router = self.tool_router)]
impl ServerHandler for LinnixMcp {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` is `#[non_exhaustive]`, so it has to be built by
        // mutation rather than a struct literal — a literal stops compiling
        // the moment rmcp adds a field for a newer protocol revision.
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info.name = "linnix".to_string();
        info.server_info.version = env!("CARGO_PKG_VERSION").to_string();
        info.instructions = Some(
            "Linnix reports what the Linux kernel observed on one host: which process or \
             pod actually caused resource contention, rather than which one merely showed \
             high utilisation.\n\n\
             Every tool takes a `detail` argument — `summary` for triage, `evidence` (the \
             default) to reason from, `raw` to quote. Start at `summary` and go deeper only \
             once you have decided the host matters.\n\n\
             What these tools establish is contention attribution, not proven causality: \
             that two workloads contended over a resource while one stalled. Confirming a \
             cause means changing something and watching the stall fall, which Linnix does \
             not do for you. Say so when you report a finding rather than presenting an \
             attribution as a root cause."
                .to_string(),
        );
        info
    }
}

/// Wraps a caller-facing failure.
///
/// A tool-level error rather than a JSON-RPC one: the request was well-formed
/// and reached the tool, and the message is something the calling model should
/// read and act on — usually by starting a daemon or fixing a URL.
/// Whether a route is served from the optional incident store.
///
/// These two are the only routes cognitod answers with a 503 when it was
/// started without that store; the live routes have nothing behind them that
/// can be configured away.
fn store_backed(path: &str) -> bool {
    path.starts_with("/incidents") || path.starts_with("/attribution")
}

fn tool_error(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

fn text(body: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(body)])
}

fn pretty_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value)
        .unwrap_or_else(|e| format!("(could not serialise cognitod's reply: {e})"))
}

/// Reported before anything else built from live data. A daemon whose probes
/// never attached still serves plausible readings — host stats in
/// `render_health`'s case, a genuinely empty result in
/// `investigate_contention`'s — so a caller shown only those concludes the
/// box is fine, or the neighbours are cleared, when the truth is that
/// nothing was observed. The daemon writes its own explanation, including
/// what to check, so it is quoted rather than restated.
fn readiness_note(readiness: &Readiness) -> String {
    match &readiness.verdict {
        Verdict::Ready => {
            // `ready:true` can mean the operator turned off
            // require_kernel_instrumentation, not that probes are attached.
            // That policy says degraded operation is accepted; it does not
            // mean this warning should go silent.
            if readiness.probes_attached == Some(false) {
                "WARNING: eBPF probes are not attached; running userspace-only, so no \
                 per-process stall attribution is being produced. cognitod is configured to \
                 report ready anyway (require_kernel_instrumentation is off).\n"
                    .to_string()
            } else {
                String::new()
            }
        }
        Verdict::NotReady(reason) => format!("WARNING: {}\n", single_line(reason)),
        Verdict::Unknown(why) => format!(
            "WARNING: {}. Treat the readings below as unconfirmed: a daemon whose probes \
             never attached serves plausible host numbers while attributing nothing to any \
             process.\n",
            single_line(why)
        ),
    }
}

/// `/readyz` only says whether kernel instrumentation is attached, not
/// whether every event it produced actually reached cognitod. A perf-buffer
/// overflow or the rate limiter dropping events can also leave a window
/// with no attribution rows, and an agent reading that as "ruled out"
/// would be as wrong as reading a detached probe that way.
fn event_loss_note(status: &Status) -> String {
    if status.rb_overflows == 0 && status.rate_limited == 0 && status.listener_queue_drops == 0 {
        return String::new();
    }
    // rb_overflows/rate_limited/listener_queue_drops are lifetime counters
    // since cognitod started, not scoped to any particular query's window --
    // a single overflow from days ago would otherwise make every later query
    // claim *its* result may be incomplete, which the counters cannot
    // support. listener_queue_drops covers a third loss path the other two
    // don't: the listener's bounded worker queue filling under backpressure.
    format!(
        "WARNING: {} ring-buffer overflow(s), {} rate-limited event(s), and {} queue-dropped \
         event(s) since cognitod started (lifetime totals, not scoped to this query's window): \
         some kernel events have been dropped before reaching cognitod, so a result may be \
         incomplete if loss happened to occur during the queried window.\n",
        status.rb_overflows, status.rate_limited, status.listener_queue_drops
    )
}

fn render_health(
    status: &Status,
    system: &SystemSnapshot,
    readiness: &Readiness,
    detail: Detail,
) -> String {
    // Rate-limited events are discarded before reaching the context store
    // just as overflowed ones are, so both belong in the same warning --
    // gating it on rb_overflows alone silently dropped the rate_limited-only
    // case, at every tier including summary.
    let readiness_note = format!("{}{}", readiness_note(readiness), event_loss_note(status));

    // `/status.offline` is `runtime.offline`, which gates *outbound* sinks —
    // it is what stops telemetry leaving the host. It says nothing about
    // whether the daemon is ingesting events, and it defaults to true, so
    // reading it as "not observing this host" would put a false alarm on the
    // top line of every default health call. Whether the daemon is actually
    // seeing the machine is `events_per_sec`, reported below.
    let offline_note = if status.offline {
        "Note: cognitod is in offline mode, so nothing is sent to external sinks. Local \
         observation and attribution are unaffected.\n"
    } else {
        ""
    };

    let headline = format!(
        "Host: CPU {:.1}%, memory {:.1}%. Stalled time over the last 10s (PSI avg10): \
         cpu {:.1}%, memory {:.1}%, io {:.1}%.\n",
        system.cpu_percent,
        system.mem_percent,
        system.psi_cpu_some_avg10,
        system.psi_memory_some_avg10,
        system.psi_io_some_avg10,
    );

    if detail == Detail::Summary {
        return format!("{readiness_note}{offline_note}{headline}");
    }

    let mut out = format!("{readiness_note}{offline_note}{headline}");
    out.push_str(&format!(
        "Load average: {:.2}, {:.2}, {:.2}\n",
        system.load_avg[0], system.load_avg[1], system.load_avg[2]
    ));
    // `full` is the share of time *every* runnable task was stalled, so a
    // non-zero value means the host made no progress at all on that resource.
    // Distinguishing it from `some` is the difference between "contended" and
    // "wedged", which is not a distinction utilisation can express.
    out.push_str(&format!(
        "PSI full avg10 (share of time ALL tasks were stalled — nonzero means no \
         forward progress): memory {:.1}%, io {:.1}%\n",
        system.psi_memory_full_avg10, system.psi_io_full_avg10
    ));
    out.push_str(&format!(
        "Daemon: {:.1}% CPU, {} MB RSS, {} events/s, {} ring-buffer overflows, \
         {} events rate-limited, {} events queue-dropped, offline={}\n",
        status.cpu_pct,
        status.rss_mb,
        status.events_per_sec,
        status.rb_overflows,
        status.rate_limited,
        status.listener_queue_drops,
        status.offline,
    ));
    // The warning itself already led via readiness_note above (event_loss_note
    // covers all three counters, at every tier); this is just the raw numbers.

    out
}

/// The one-sentence form of an investigation.
///
/// Deliberately names the denominator. The share is a fraction of the stall
/// that could be pinned on a neighbour, which is usually less than the
/// victim's whole stall, and a percentage quoted without that reads as a much
/// stronger claim than the data supports.
fn contention_headline(
    investigation: &Investigation,
    namespace: &str,
    pod: &str,
    since: &str,
) -> String {
    let Some(primary) = investigation.offenders.first() else {
        // The result that most strongly rules workloads out is exactly the
        // one that most needs the causality qualification attached.
        return format!(
            "No contention was attributed to any neighbour of {namespace}/{pod} in the last \
             {since}. That rules out other workloads on the node; it does not rule out the \
             pod's own limits, throttling or workload.\n{}",
            investigate::CAUSALITY_CAVEAT
        );
    };

    // When no offender in the window carries a per-offender split, `summarise`
    // has nothing to order by and falls back to sorting by name for
    // reproducibility. Calling the first of those the "largest contender"
    // would invent a ranking out of alphabetical order — the same mistake as
    // rendering an unknown share as 0%, which the CLI already refuses to do,
    // pointed the other way. share.is_none() alone misses an offender with
    // both a split row and an unsplit one: its share is knowable from the
    // split row, but the unsplit row could still hide more, so it must count
    // as unmeasured here too (see investigate::render's identical partition).
    if investigation
        .offenders
        .iter()
        .any(|offender| offender.share.is_none() || offender.unsplit_rows > 0)
    {
        let names = investigation
            .offenders
            .iter()
            .map(|offender| format!("{}/{}", offender.namespace, offender.pod))
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "{namespace}/{pod} stalled across {} detection window(s) in the last {since}. \
             {} contended with it — {names} — but at least one carries only rows that \
             predate per-offender attribution, so its contribution is unknown and could \
             exceed the others'. No offender can be named while that is true. Ask for \
             detail=evidence to see which are measured. This is contention attribution, \
             not proven cause.\n",
            investigation.windows,
            if investigation.offenders.len() == 1 {
                "One workload".to_string()
            } else {
                format!("{} workloads", investigation.offenders.len())
            },
        );
    }

    let share = match primary.share {
        Some(share) => format!(
            "{:.0}% of the stall attributed to neighbours",
            share * 100.0
        ),
        // An offender whose own rows all predate the split contributed an
        // unknown amount, not zero, and must not be rendered as a percentage
        // that reads like an exoneration. Reachable here only when some other
        // offender *did* carry a split, which is what makes the order real.
        None => "an unrecorded share of the attributed stall".to_string(),
    };

    format!(
        "{namespace}/{pod} stalled across {} detection window(s) in the last {since}. The \
         largest contender was {}/{} with {}, dominant signal: {}. This is contention \
         attribution, not proven cause.\n",
        investigation.windows,
        primary.namespace,
        primary.pod,
        share,
        primary.reason.as_deref().unwrap_or("unclassified"),
    )
}

fn process_headline(pid: u32, proc: &serde_json::Value) -> String {
    let field = |key: &str| proc.get(key).cloned().unwrap_or(serde_json::Value::Null);
    let comm = field("comm");
    let comm = comm.as_str().unwrap_or("?");
    let k8s = proc.get("k8s");
    let pod = k8s.and_then(|k| k.get("pod_name")).and_then(|p| p.as_str());
    let namespace = k8s
        .and_then(|k| k.get("namespace"))
        .and_then(|n| n.as_str());

    let mut line = format!("PID {pid} is `{}`", single_line(comm));
    if let Some(pod) = pod {
        // Two namespaces can run same-named pods, so the pod name alone does
        // not identify the workload.
        match namespace {
            Some(ns) => line.push_str(&format!(" in pod {}/{}", single_line(ns), single_line(pod))),
            None => line.push_str(&format!(" in pod {}", single_line(pod))),
        }
    }
    if let Some(cpu) = field("cpu_pct").as_f64() {
        line.push_str(&format!(", {cpu:.1}% CPU"));
    }
    if let Some(mem) = field("mem_pct").as_f64() {
        line.push_str(&format!(", {mem:.1}% memory"));
    }
    if let Some(age) = field("age_sec").as_u64() {
        line.push_str(&format!(", alive {age}s"));
    }
    line.push_str(".\n");
    line
}

/// One line naming an incident: enough to decide whether to ask for it in
/// full, and nothing more.
fn incident_headline(view: &IncidentView, id: i64) -> String {
    let mut line = format!("Incident #{id}: {} → {}", view.event_type, view.action);
    match (&view.target_name, view.target_pid) {
        (Some(target), Some(pid)) => line.push_str(&format!(" on `{target}` (pid {pid})")),
        (Some(target), None) => line.push_str(&format!(" on `{target}`")),
        (None, Some(pid)) => line.push_str(&format!(" on pid {pid}")),
        (None, None) => {}
    }
    line.push_str(&format!(
        ", cpu {:.1}%, psi_cpu {:.1}%, at epoch {}.",
        view.cpu_percent, view.psi_cpu, view.timestamp
    ));
    // Whether the daemon reached a conclusion at all decides whether asking
    // for the full rendering is worth anything, so it belongs in the one line
    // that decides that.
    match &view.investigation_rendered {
        Some(Some(_)) => line.push_str(" A stored investigation exists; ask for detail=evidence."),
        Some(None) => line.push_str(" The stored investigation could not be read by this daemon."),
        None => line.push_str(" No stored investigation."),
    }
    line.push('\n');
    line
}

/// The process tree as one line per process rather than as JSON.
///
/// This is the whole difference between the evidence and raw tiers here: a
/// fork storm is visible in twenty short lines and buried in the same twenty
/// nodes rendered as objects.
fn render_tree(graph: &serde_json::Value) -> String {
    // `/graph/{pid}` answers with `{"root": <pid>, "nodes": [...]}`. Reading
    // the envelope as the array would silently fall back to dumping JSON at
    // the tier whose whole purpose is to be shorter than JSON.
    let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) else {
        return pretty_json(graph);
    };
    if nodes.is_empty() {
        return "  (no related processes)\n".to_string();
    }

    // Levels are signed and relative to the queried process: ancestors are
    // negative, descendants positive. Indenting by absolute value would put an
    // ancestor and a descendant at the same depth, which inverts half the
    // tree, so the shallowest level becomes column zero.
    let shallowest = nodes
        .iter()
        .filter_map(|node| node.get("level").and_then(|v| v.as_i64()))
        .min()
        .unwrap_or(0);

    // `get_graph` emits, in this order: the queried process at level 0, its
    // ancestors from the immediate parent outward, any siblings (also level
    // 0), then descendants depth-first. Rendering that array as-is gets two
    // things wrong and one thing right, so this moves exactly two groups.
    //
    // Ancestors arrive -1, -2, -3 and read correctly as -3, -2, -1.
    //
    // Siblings arrive *between* the queried process and its own children.
    // Since a sibling shares the queried process's indent, every one of those
    // children then appears to hang off the sibling — a tree that contradicts
    // the `ppid` in the same rows. They move ahead of the queried process,
    // where a tree renderer puts them: all of one parent's children, then the
    // subtree under the one being asked about.
    //
    // Descendants are already right. `collect_descendants` recurses the moment
    // it pushes a child, so they arrive child, grandchild, sibling — which is
    // the order a tree is drawn in. Sorting the whole array by level was the
    // first attempt at the ancestor fix and broke exactly this, separating a
    // grandchild from its parent and reparenting it under the next branch.
    let level_of =
        |node: &serde_json::Value| node.get("level").and_then(|v| v.as_i64()).unwrap_or(0);
    let is_sibling = |node: &serde_json::Value| {
        node.get("relationship").and_then(|v| v.as_str()) == Some("sibling")
    };

    let mut ancestors: Vec<&serde_json::Value> =
        nodes.iter().filter(|node| level_of(node) < 0).collect();
    ancestors.reverse();
    let nodes: Vec<&serde_json::Value> = ancestors
        .into_iter()
        .chain(nodes.iter().filter(|node| is_sibling(node)))
        .chain(
            nodes
                .iter()
                .filter(|node| level_of(node) >= 0 && !is_sibling(node)),
        )
        .collect();

    let mut out = String::new();
    for node in nodes {
        let level = node.get("level").and_then(|v| v.as_i64()).unwrap_or(0);
        let relationship = node
            .get("relationship")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let comm = node.get("comm").and_then(|v| v.as_str()).unwrap_or("?");
        let pid = node.get("pid").and_then(|v| v.as_i64()).unwrap_or(-1);
        let ppid = node.get("ppid").and_then(|v| v.as_i64()).unwrap_or(-1);
        // Clamped: a deep chain must not push the text off the right of a
        // transcript, and the `[relationship]` tag still says which way it ran.
        let depth = level.saturating_sub(shallowest).unsigned_abs() as usize;
        let indent = "  ".repeat(depth.min(8) + 1);
        out.push_str(&format!(
            "{indent}[{relationship}] pid {pid} `{}` (parent {ppid})\n",
            single_line(comm)
        ));
    }
    out
}

fn incident_line(incident: &serde_json::Value, detail: Detail) -> String {
    let get_str = |key: &str| {
        incident
            .get(key)
            .and_then(|v| v.as_str())
            .map(single_line)
            .unwrap_or_else(|| "?".to_string())
    };
    let id = incident
        .get("id")
        .and_then(|v| v.as_i64())
        .map(|id| id.to_string())
        .unwrap_or_else(|| "-".to_string());

    let mut line = format!(
        "  #{id}  {}  action={}",
        get_str("event_type"),
        get_str("action"),
    );
    if detail == Detail::Summary {
        line.push('\n');
        return line;
    }

    if let Some(target) = incident.get("target_name").and_then(|v| v.as_str()) {
        line.push_str(&format!("  target={}", single_line(target)));
    }
    if let Some(pid) = incident.get("target_pid").and_then(|v| v.as_i64()) {
        line.push_str(&format!(" (pid {pid})"));
    }
    if let Some(psi) = incident.get("psi_cpu").and_then(|v| v.as_f64()) {
        line.push_str(&format!("  psi_cpu={psi:.1}%"));
    }
    if let Some(cpu) = incident.get("cpu_percent").and_then(|v| v.as_f64()) {
        line.push_str(&format!("  cpu={cpu:.1}%"));
    }
    if let Some(ts) = incident.get("timestamp").and_then(|v| v.as_i64()) {
        line.push_str(&format!("  at epoch {ts}"));
    }
    line.push('\n');
    line
}

/// Collapses a daemon-supplied string onto one line.
///
/// Names like `proc.comm` are chosen by whoever started the process. These are
/// interpolated into single-line rows, so a newline in one forges a row the
/// daemon never wrote — the same reasoning `explain.rs` applies, and the reason
/// it applies here too is that a model reading a forged row will repeat it.
fn single_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Serves MCP over stdio until the client disconnects.
///
/// stdout is the transport, so nothing may be printed to it. Anything this
/// server has to say goes to stderr, where the MCP client collects it as
/// server logs.
pub async fn serve(client: &reqwest::Client, base: &str) -> Result<(), Box<dyn Error>> {
    eprintln!("linnix mcp: serving over stdio against {base}");
    let service = LinnixMcp::new(client.clone(), base)
        .serve(rmcp::transport::stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}
