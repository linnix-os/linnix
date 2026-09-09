//! Drives `linnix mcp serve` the way a real MCP client does: spawn it, speak
//! newline-delimited JSON-RPC over its stdin and stdout, and read what comes
//! back.
//!
//! A unit test over the renderers cannot fail the way this integration
//! actually breaks. The failures that matter here — a handshake the client
//! rejects, a tool schema that never reaches `tools/list`, a panic on a field
//! the daemon did not send — all live in the wiring between the transport and
//! the tools, and only show up when something drives the whole process.

use httpmock::prelude::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A running `linnix mcp serve`, with the handshake already done.
struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl McpClient {
    fn spawn(url: &str) -> Self {
        let mut child = Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
            .args(["--url", url, "mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Inherited so a panic in the server shows up in test output
            // rather than being swallowed by a pipe nobody reads.
            .stderr(Stdio::inherit())
            .spawn()
            .expect("linnix-cli should start");

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout was piped"));
        let mut client = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        };

        let init = client.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "linnix-test", "version": "0"},
            }),
        );
        let result = &init["result"];
        assert!(
            result["capabilities"]["tools"].is_object(),
            "server must advertise tool support: {init}"
        );
        assert_eq!(result["serverInfo"]["name"], "linnix", "{init}");
        assert!(
            result["protocolVersion"].is_string(),
            "server must negotiate a protocol version: {init}"
        );

        client.notify("notifications/initialized");
        client
    }

    fn send(&mut self, message: &Value) {
        writeln!(self.stdin, "{message}").expect("server should accept a request");
        self.stdin.flush().expect("flush");
    }

    fn read_response(&mut self) -> Value {
        let mut line = String::new();
        loop {
            line.clear();
            let read = self.stdout.read_line(&mut line).expect("read a reply");
            assert!(read > 0, "server closed stdout before replying");
            if line.trim().is_empty() {
                continue;
            }
            let value: Value =
                serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON: {line} ({e})"));
            // Notifications the server sends on its own carry no id; a caller
            // waiting on a response has to skip past them rather than mistake
            // the first line it sees for its answer.
            if value.get("id").is_some() {
                return value;
            }
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        let response = self.read_response();
        assert_eq!(response["id"], id, "reply must match the request id");
        assert_eq!(response["jsonrpc"], "2.0", "{response}");
        response
    }

    fn notify(&mut self, method: &str) {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": {}}));
    }

    /// The text a tool call produced, plus whether it was flagged as an error.
    fn call_tool(&mut self, name: &str, arguments: Value) -> (String, bool) {
        let response = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        assert!(
            response.get("error").is_none(),
            "a tool failure must come back as a tool result, not a JSON-RPC error: {response}"
        );
        let result = &response["result"];
        let text = result["content"]
            .as_array()
            .expect("content array")
            .iter()
            .filter_map(|block| block["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n");
        (text, result["isError"].as_bool().unwrap_or(false))
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `blame_score` is here on purpose: the CLI's `Attribution` struct does not
/// declare it, so it is exactly the kind of field a raw tier that re-serialises
/// a decoded struct would silently drop.
fn attribution_body() -> &'static str {
    r#"{
        "victim": {"pod": "payment-api", "namespace": "payments"},
        "window_minutes": 15,
        "permalink": "/attribution?pod=payment-api&namespace=payments&window=15",
        "attributions": [
            {"offender_pod":"image-resizer","offender_namespace":"media",
             "stall_us":1000000,"attributed_stall_us":700000,"blame_score":2.0,
             "timestamp":100,"cpu_share":0.62,"fork_count":186,
             "short_job_count":42,"reason":"noisy_neighbor","event_id":"e1"},
            {"offender_pod":"etl-runner","offender_namespace":"batch",
             "stall_us":1000000,"attributed_stall_us":300000,"blame_score":1.0,
             "timestamp":100,"cpu_share":0.20,"fork_count":4,
             "short_job_count":2,"reason":"fork_storm","event_id":"e1"}
        ]
    }"#
}

/// A cognitod with an answer for every route the tools reach, so one test can
/// exercise all five without five fixtures.
fn full_daemon() -> MockServer {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":1.2,"rss_mb":41,"events_per_sec":900,
                    "rb_overflows":0,"rate_limited":0,"offline":false}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":true,"kernel_instrumentation":"active","transport":"ringbuf",
                    "btf_available":true,"rss_probe":"attached","reason":null}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/system");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"timestamp":100,"cpu_percent":81.5,"mem_percent":62.0,
                    "load_avg":[4.1,3.2,2.0],"disk_read_bytes":0,"disk_write_bytes":0,
                    "net_rx_bytes":0,"net_tx_bytes":0,
                    "psi_cpu_some_avg10":51.0,"psi_memory_some_avg10":0.2,
                    "psi_memory_full_avg10":0.0,"psi_io_some_avg10":1.1,
                    "psi_io_full_avg10":0.0}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(attribution_body());
    });
    server.mock(|when, then| {
        when.method(GET).path("/processes/4242");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"pid":4242,"ppid":1,"uid":0,"gid":0,"comm":"feature-builder",
                    "event_type":"exec","cpu_pct":97.5,"mem_pct":12.0,"age_sec":31,
                    "state":"running","k8s":null}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/graph/4242");
        then.status(200)
            .header("content-type", "application/json")
            // Emission order and relationship strings copied from
            // `get_graph` in cognitod/src/api/mod.rs, not guessed: the queried
            // process is appended first with relationship "self", then
            // ancestors from the immediate parent outward, then descendants.
            // A fixture in tidy ancestor-first order cannot catch a renderer
            // that trusts the array order.
            .body(
                r#"{"root":4242,"nodes":[
                    {"pid":4242,"ppid":1,"comm":"feature-builder","uid":0,"gid":0,
                     "event_type":"exec","relationship":"self","level":0},
                    {"pid":1,"ppid":0,"comm":"systemd","uid":0,"gid":0,
                     "event_type":"exec","relationship":"ancestor","level":-1},
                    {"pid":4301,"ppid":4242,"comm":"python","uid":0,"gid":0,
                     "event_type":"exec","relationship":"descendant","level":1}]}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/incidents");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"[{"id":7,"timestamp":1732242135,"event_type":"circuit_breaker_cpu",
                     "psi_cpu":75.2,"psi_memory":0.0,"cpu_percent":96.3,
                     "load_avg":"4.1,3.2,2.0","action":"auto_kill",
                     "target_pid":472693,"target_name":"aggressive-stress.sh"}]"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/incidents/7");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"id":7,"timestamp":1732242135,"event_type":"circuit_breaker_cpu",
                    "action":"auto_kill","target_name":"aggressive-stress.sh",
                    "target_pid":472693,"psi_cpu":75.2,"cpu_percent":96.3,
                    "investigation_rendered":"1. [cpu_spin] A runaway loop\n   supports:    CPU usage was 96.3%\n",
                    "investigation":{"hypotheses":[]},"llm_analysis":"...",
                    "psi_after":null,"recovery_time_ms":null}"#,
            );
    });
    server
}

#[test]
fn the_handshake_completes_and_every_tool_is_listed_with_a_schema() {
    // No daemon is mocked: `tools/list` describes the server, and must work
    // whether or not anything is running behind it.
    let mut client = McpClient::spawn("http://127.0.0.1:1");
    let listed = client.request("tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().expect("tools array");

    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for expected in [
        "linnix_system_health",
        "linnix_investigate_contention",
        "linnix_explain_process",
        "linnix_recent_incidents",
        "linnix_explain_incident",
    ] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }

    // A tool a model cannot see the arguments of is a tool it will not call
    // correctly, so the schema reaching the client is part of the contract.
    let contention = tools
        .iter()
        .find(|tool| tool["name"] == "linnix_investigate_contention")
        .expect("contention tool");
    let properties = &contention["inputSchema"]["properties"];
    for field in ["namespace", "pod", "since", "detail"] {
        assert!(
            properties.get(field).is_some(),
            "schema is missing {field}: {contention}"
        );
    }

    // The causality caveat has to be in the description, because that is what
    // a model reads before deciding what this answer means.
    let description = contention["description"].as_str().unwrap_or_default();
    assert!(
        description.contains("not proven causality"),
        "description must not let an attribution read as a root cause: {description}"
    );
}

#[test]
fn an_unreachable_daemon_is_a_tool_error_that_says_what_to_do() {
    // The most common first contact: an agent calls a tool on a machine where
    // nothing is running. Port 1 refuses immediately.
    let mut client = McpClient::spawn("http://127.0.0.1:1");
    let (text, is_error) = client.call_tool("linnix_system_health", json!({}));

    assert!(is_error, "an unreachable daemon must be flagged: {text}");
    assert!(text.contains("cannot reach cognitod"), "{text}");
    assert!(
        text.contains("LINNIX_API_TOKEN"),
        "the message must name the two things that fix this: {text}"
    );
}

#[test]
fn every_tool_has_three_tiers_that_actually_differ() {
    // The server's own instructions tell a model to "start at `summary` and go
    // deeper only once you have decided the host matters". A tool whose
    // summary is its evidence charges a caller that obeys that instruction the
    // full price for a triage call — and the failure is silent, which is why
    // this loops over every tool rather than checking one.
    let server = full_daemon();
    let mut client = McpClient::spawn(&server.base_url());

    let cases: [(&str, Value); 5] = [
        ("linnix_system_health", json!({})),
        (
            "linnix_investigate_contention",
            json!({"namespace": "payments", "pod": "payment-api"}),
        ),
        ("linnix_explain_process", json!({"pid": 4242})),
        ("linnix_recent_incidents", json!({})),
        ("linnix_explain_incident", json!({"id": 7})),
    ];

    for (tool, base_args) in cases {
        let with_detail = |detail: &str| {
            let mut args = base_args.clone();
            args["detail"] = json!(detail);
            args
        };

        let (summary, summary_error) = client.call_tool(tool, with_detail("summary"));
        let (evidence, evidence_error) = client.call_tool(tool, with_detail("evidence"));
        let (raw, raw_error) = client.call_tool(tool, with_detail("raw"));

        assert!(
            !summary_error && !evidence_error && !raw_error,
            "{tool} should have answered from the mocked daemon: {summary}"
        );
        assert!(
            summary.len() < evidence.len(),
            "{tool}: summary ({}) must cost less than evidence ({})",
            summary.len(),
            evidence.len()
        );
        assert_ne!(
            evidence.trim(),
            raw.trim(),
            "{tool}: raw must carry something evidence does not"
        );
    }
}

#[test]
fn detail_raw_hands_back_what_the_daemon_actually_sent() {
    // The raw tier is what a caller quotes. Decoding into this crate's structs
    // and re-serialising drops every field cognitod sends that the CLI does
    // not declare, while still calling itself raw — so each case below names a
    // field that no struct in this crate declares, which is the only kind of
    // field that catches the mistake.
    let server = full_daemon();
    let mut client = McpClient::spawn(&server.base_url());

    let cases: [(&str, Value, &[&str]); 4] = [
        (
            "linnix_system_health",
            json!({}),
            &["disk_read_bytes", "net_rx_bytes"],
        ),
        (
            "linnix_investigate_contention",
            json!({"namespace": "payments", "pod": "payment-api"}),
            &["blame_score", "window_minutes"],
        ),
        ("linnix_explain_process", json!({"pid": 4242}), &["gid"]),
        ("linnix_recent_incidents", json!({}), &["load_avg"]),
    ];

    for (tool, base_args, undeclared) in cases {
        let mut args = base_args;
        args["detail"] = json!("raw");
        let (raw, _) = client.call_tool(tool, args);
        for field in undeclared {
            assert!(
                raw.contains(&format!("\"{field}\"")),
                "{tool} dropped {field} from its raw tier: {raw}"
            );
        }
    }

    // The permalink is part of the evidence, not garnish: the window slides,
    // so these rows stop being reachable by the same question within minutes.
    let (raw, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api", "detail": "raw"}),
    );
    assert!(raw.contains("\"attributed_stall_us\": 700000"), "{raw}");
    assert!(
        raw.contains(&format!(
            "{}/attribution?pod=payment-api",
            server.base_url()
        )),
        "raw must carry an absolute permalink: {raw}"
    );

    // A healthy daemon with no loss warnings leaves nothing to prepend, so
    // this is exactly the case where the raw tier's promise -- the daemon's
    // own parseable bytes -- has to actually hold. Trailing prose appended
    // after the serialized object (e.g. a "these exact rows: <link>" line)
    // would make this fail even though nothing here looks wrong by eye.
    serde_json::from_str::<Value>(&raw)
        .unwrap_or_else(|e| panic!("raw tier must be valid JSON on a healthy daemon: {e}\n{raw}"));
}

#[test]
fn the_contention_tiers_say_progressively_more() {
    let server = full_daemon();
    let mut client = McpClient::spawn(&server.base_url());
    let args =
        |detail: &str| json!({"namespace": "payments", "pod": "payment-api", "detail": detail});

    let (summary, _) = client.call_tool("linnix_investigate_contention", args("summary"));
    let (evidence, _) = client.call_tool("linnix_investigate_contention", args("evidence"));

    // Summary names the loudest offender and refuses to call it the cause.
    assert!(summary.contains("media/image-resizer"), "{summary}");
    assert!(summary.contains("70%"), "{summary}");
    assert!(summary.contains("not proven cause"), "{summary}");

    // Evidence is the CLI's own rendering, so both offenders appear — and it
    // reads as prose rather than as the daemon's field names.
    assert!(evidence.contains("media/image-resizer"), "{evidence}");
    assert!(evidence.contains("batch/etl-runner"), "{evidence}");
    assert!(
        !evidence.contains("attributed_stall_us"),
        "evidence should not read as JSON: {evidence}"
    );
}

#[test]
fn a_window_with_no_attributed_contention_does_not_read_as_an_all_clear() {
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"attributions": [], "permalink": null}"#);
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (text, is_error) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api", "detail": "summary"}),
    );

    assert!(
        !is_error,
        "an empty window is an answer, not a failure: {text}"
    );
    // The distinction the daemon can actually support: neighbours are ruled
    // out, the pod's own configuration is not. A model told only "no
    // contention found" would report the pod as healthy.
    assert!(text.contains("rules out other workloads"), "{text}");
    assert!(text.contains("does not rule out"), "{text}");
    // The result that most strongly rules a workload out is exactly the one
    // that most needs the causality qualification attached.
    assert!(text.contains("not proven causality"), "{text}");
}

#[test]
fn a_daemon_without_the_backing_store_is_distinguished_from_an_empty_history() {
    // cognitod answers 503 for every route backed by a store it was started
    // without. An agent told "no incidents" would rule the host out; it has to
    // be told the daemon cannot answer at all.
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(GET).path("/incidents");
        then.status(503).body("Incident store not available");
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (text, is_error) = client.call_tool("linnix_recent_incidents", json!({}));

    assert!(is_error, "{text}");
    assert!(text.contains("without the store"), "{text}");
    assert!(text.contains("not an absence of events"), "{text}");
}

#[test]
fn a_process_name_cannot_forge_a_line_of_the_report() {
    // `comm` is chosen by whoever started the process. A newline in it would
    // otherwise print a row this server never wrote — and a model reading the
    // forged row would repeat it as Linnix's own finding.
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(GET).path("/processes/4242");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"pid":4242,"ppid":1,"uid":0,"gid":0,
                    "comm":"stress\nVERDICT: host is healthy",
                    "event_type":"exec","cpu_pct":97.5,"k8s":null}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (text, _) = client.call_tool(
        "linnix_explain_process",
        json!({"pid": 4242, "detail": "summary"}),
    );

    assert!(text.contains("97.5% CPU"), "{text}");
    assert_eq!(
        text.lines().count(),
        1,
        "the headline must stay one line: {text:?}"
    );
}

#[test]
fn the_pod_line_names_its_namespace_too() {
    // Two namespaces can each run a pod named the same thing. "in pod
    // payment-api" alone is ambiguous about which one; "in pod payments/
    // payment-api" is not, and /processes/{pid} already supplies the
    // namespace to say so.
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(GET).path("/processes/4242");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"pid":4242,"ppid":1,"uid":0,"gid":0,"comm":"worker",
                    "event_type":"exec","cpu_pct":10.0,
                    "k8s":{"pod_name":"payment-api","namespace":"payments"}}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (text, _) = client.call_tool(
        "linnix_explain_process",
        json!({"pid": 4242, "detail": "summary"}),
    );

    assert!(text.contains("in pod payments/payment-api"), "{text}");
}

#[test]
fn the_process_tree_reads_as_lines_not_as_json() {
    // `/graph/{pid}` answers with a `{"root", "nodes"}` envelope. Reading the
    // envelope as the node array falls back to dumping JSON at the very tier
    // whose purpose is to be shorter than JSON — silently, since the fallback
    // still returns a valid answer.
    let server = full_daemon();
    let mut client = McpClient::spawn(&server.base_url());

    let (evidence, is_error) = client.call_tool(
        "linnix_explain_process",
        json!({"pid": 4242, "detail": "evidence"}),
    );

    assert!(!is_error, "{evidence}");
    assert!(
        !evidence.contains("\"event_type\""),
        "the evidence tier must not fall back to JSON: {evidence}"
    );
    assert!(
        evidence.contains("[ancestor] pid 1 `systemd`"),
        "{evidence}"
    );
    assert!(
        evidence.contains("[descendant] pid 4301 `python`"),
        "{evidence}"
    );

    // Ancestors are at negative levels and descendants at positive ones, so
    // indenting by absolute depth would draw them in the same column and
    // invert half the tree.
    let indent = |needle: &str| {
        evidence
            .lines()
            .find(|line| line.contains(needle))
            .map(|line| line.len() - line.trim_start().len())
            .unwrap_or_else(|| panic!("no line for {needle}: {evidence}"))
    };
    // Matched on the `[relationship]` tag, not the process name: the headline
    // above the tree names the queried process too, and it sits at column 0.
    // Matched on the `[relationship]` tag, not the process name: the headline
    // above the tree names the queried process too, and it sits at column 0.
    assert!(
        indent("[ancestor] pid 1") < indent("[self] pid 4242"),
        "an ancestor must sit shallower than the queried process: {evidence}"
    );
    assert!(
        indent("[self] pid 4242") < indent("[descendant] pid 4301"),
        "a descendant must sit deeper than the queried process: {evidence}"
    );

    // The daemon sends the queried process ahead of its own parents, so a
    // renderer that trusts the array order draws the tree upside down: the
    // deepest indent first, then a chain that un-indents.
    let line_of = |needle: &str| {
        evidence
            .lines()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no line for {needle}: {evidence}"))
    };
    assert!(
        line_of("[ancestor] pid 1") < line_of("[self] pid 4242"),
        "ancestors must be printed before the process they lead to: {evidence}"
    );
}

#[test]
fn an_unreadable_process_tree_is_not_reported_as_an_exited_process() {
    // A process that exits between the two requests 404s on the second, and
    // absorbing that race is worth it. Absorbing a 5xx is not: told "the
    // process may have exited", an agent concludes the tree is empty when the
    // truth is that we could not read it.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/processes/4242");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"pid":4242,"ppid":1,"uid":0,"gid":0,"comm":"x","event_type":"exec","k8s":null}"#);
    });
    server.mock(|when, then| {
        when.method(GET).path("/graph/4242");
        then.status(500).body("boom");
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (text, is_error) = client.call_tool("linnix_explain_process", json!({"pid": 4242}));

    assert!(is_error, "a 5xx on the tree must stay an error: {text}");
    assert!(text.contains("500"), "{text}");
    assert!(
        !text.contains("may have exited"),
        "a server error must not be reported as an exit: {text}"
    );
}

#[test]
fn url_is_accepted_on_either_side_of_the_subcommand() {
    // `claude mcp add linnix -- linnix-cli mcp serve --url ...` is the order
    // anyone configuring an MCP client writes. A flag clap rejects there fails
    // inside a client that shows the operator nothing but a dead server.
    let server = full_daemon();
    for args in [
        vec!["mcp", "serve", "--url", &server.base_url()],
        vec!["--url", &server.base_url(), "mcp", "serve"],
    ] {
        let mut child = Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(
            stdin,
            "{}",
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "t", "version": "0"}},
            })
        )
        .expect("write");
        stdin.flush().expect("flush");

        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("read");
        let _ = child.kill();
        let _ = child.wait();

        let reply: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("{args:?} did not start the server: {line} ({e})"));
        assert_eq!(reply["result"]["serverInfo"]["name"], "linnix", "{args:?}");
    }
}

#[test]
fn offline_mode_is_not_reported_as_a_detached_event_source() {
    // `/status.offline` is `runtime.offline`, which gates outbound sinks and
    // defaults to TRUE. Reading it as "cognitod is not watching this host"
    // would put a false alarm on the top line of every default health call —
    // the one sentence in this tool an agent is most likely to act on.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":1.2,"rss_mb":41,"events_per_sec":900,
                    "rb_overflows":0,"rate_limited":0,"offline":true}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/system");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"timestamp":100,"cpu_percent":10.0,"mem_percent":20.0,
                    "load_avg":[0.1,0.2,0.3],"disk_read_bytes":0,"disk_write_bytes":0,
                    "net_rx_bytes":0,"net_tx_bytes":0,
                    "psi_cpu_some_avg10":0.0,"psi_memory_some_avg10":0.0,
                    "psi_memory_full_avg10":0.0,"psi_io_some_avg10":0.0,
                    "psi_io_full_avg10":0.0}"#,
            );
    });

    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"ready":true,"reason":null}"#);
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (text, _) = client.call_tool("linnix_system_health", json!({"detail": "summary"}));

    assert!(
        !text.contains("not currently observing")
            && !text.contains("no process attribution is being recorded"),
        "offline mode must not read as a detached event source: {text}"
    );
    assert!(
        text.contains("external sinks"),
        "what offline actually means should still be said: {text}"
    );
}

#[test]
fn a_503_on_a_live_route_is_not_blamed_on_a_missing_store() {
    // Only /incidents and /attribution are backed by the optional incident
    // store. A 503 from a proxy in front of /system is an ordinary outage, and
    // calling it a deliberate daemon configuration sends an operator to edit a
    // config that is not the problem.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":1.0,"rss_mb":40,"events_per_sec":1,
                    "rb_overflows":0,"rate_limited":0,"offline":false}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/system");
        then.status(503).body("upstream unavailable");
    });

    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"ready":true,"reason":null}"#);
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (text, is_error) = client.call_tool("linnix_system_health", json!({}));

    assert!(is_error, "{text}");
    assert!(
        !text.contains("without the store"),
        "/system has no store behind it: {text}"
    );
    assert!(text.contains("503"), "{text}");
}

#[test]
fn a_grandchild_is_not_reparented_onto_its_parents_sibling() {
    // `collect_descendants` recurses as soon as it pushes a child, so the
    // daemon emits child A, grandchild A, child B — already tree order.
    // Sorting the whole array by level (the first fix for the ancestor
    // ordering) turns that into child A, child B, grandchild A, and the
    // indentation then says the grandchild belongs to B. That is not a
    // cosmetic defect: it reports a process tree that never existed, and a
    // fork storm is exactly the thing an agent reads this tree to find.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/processes/100");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"pid":100,"ppid":50,"uid":0,"gid":0,"comm":"parent","event_type":"exec","k8s":null}"#);
    });
    server.mock(|when, then| {
        when.method(GET).path("/graph/100");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"root":100,"nodes":[
                    {"pid":100,"ppid":50,"comm":"parent","uid":0,"gid":0,
                     "event_type":"exec","relationship":"self","level":0},
                    {"pid":50,"ppid":10,"comm":"grandparent","uid":0,"gid":0,
                     "event_type":"exec","relationship":"ancestor","level":-1},
                    {"pid":10,"ppid":0,"comm":"init","uid":0,"gid":0,
                     "event_type":"exec","relationship":"ancestor","level":-2},
                    {"pid":200,"ppid":100,"comm":"child-a","uid":0,"gid":0,
                     "event_type":"exec","relationship":"descendant","level":1},
                    {"pid":300,"ppid":200,"comm":"grandchild-a","uid":0,"gid":0,
                     "event_type":"exec","relationship":"descendant","level":2},
                    {"pid":400,"ppid":100,"comm":"child-b","uid":0,"gid":0,
                     "event_type":"exec","relationship":"descendant","level":1}]}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (evidence, is_error) = client.call_tool("linnix_explain_process", json!({"pid": 100}));
    assert!(!is_error, "{evidence}");

    let tree: Vec<&str> = evidence
        .lines()
        .filter(|line| line.contains("] pid "))
        .collect();

    // Ancestors read outermost-first; descendants keep the daemon's
    // depth-first order, so the grandchild stays adjacent to its own parent.
    let names: Vec<&str> = tree
        .iter()
        .map(|line| line.split('`').nth(1).expect("comm in backticks"))
        .collect();
    assert_eq!(
        names,
        vec![
            "init",
            "grandparent",
            "parent",
            "child-a",
            "grandchild-a",
            "child-b"
        ],
        "{evidence}"
    );

    let indent = |needle: &str| {
        tree.iter()
            .find(|line| line.contains(needle))
            .map(|line| line.len() - line.trim_start().len())
            .unwrap_or_else(|| panic!("no line for {needle}: {evidence}"))
    };
    assert_eq!(indent("`init`"), 2, "the outermost ancestor is column zero");
    assert!(indent("`grandparent`") < indent("`parent`"), "{evidence}");
    assert_eq!(
        indent("`child-a`"),
        indent("`child-b`"),
        "siblings must share a column: {evidence}"
    );
    assert!(indent("`child-a`") < indent("`grandchild-a`"), "{evidence}");
}

#[test]
fn a_sibling_does_not_adopt_the_queried_processs_children() {
    // `get_graph` emits self, ancestors, siblings, descendants — so a sibling
    // arrives between the queried process and its own children. A sibling
    // shares the queried process's indent, so leaving it there makes every one
    // of those children appear to hang off the sibling, a tree that
    // contradicts the `ppid` printed on the same rows.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/processes/100");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"pid":100,"ppid":50,"uid":0,"gid":0,"comm":"parent","event_type":"exec","k8s":null}"#);
    });
    server.mock(|when, then| {
        when.method(GET).path("/graph/100");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"root":100,"nodes":[
                    {"pid":100,"ppid":50,"comm":"queried","uid":0,"gid":0,
                     "event_type":"exec","relationship":"self","level":0},
                    {"pid":50,"ppid":0,"comm":"shared-parent","uid":0,"gid":0,
                     "event_type":"exec","relationship":"ancestor","level":-1},
                    {"pid":60,"ppid":50,"comm":"the-sibling","uid":0,"gid":0,
                     "event_type":"exec","relationship":"sibling","level":0},
                    {"pid":200,"ppid":100,"comm":"my-child","uid":0,"gid":0,
                     "event_type":"exec","relationship":"descendant","level":1}]}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (evidence, _) = client.call_tool("linnix_explain_process", json!({"pid": 100}));

    let names: Vec<&str> = evidence
        .lines()
        .filter(|line| line.contains("] pid "))
        .map(|line| line.split('`').nth(1).expect("comm in backticks"))
        .collect();
    assert_eq!(
        names,
        vec!["shared-parent", "the-sibling", "queried", "my-child"],
        "the queried process must be adjacent to its own subtree: {evidence}"
    );
}

#[test]
fn offenders_with_no_comparable_attribution_are_not_ranked() {
    // Rows predating `attributed_stall_us` leave every offender at zero, so
    // `summarise` falls back to sorting by name for reproducibility. Calling
    // the first of those the "largest contender" invents a ranking out of
    // alphabetical order — the same mistake as rendering an unknown share as
    // 0%, which the CLI already refuses to make, pointed the other way.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"permalink":null,"attributions":[
                    {"offender_pod":"aardvark","offender_namespace":"a",
                     "stall_us":1000000,"attributed_stall_us":null,
                     "timestamp":100,"cpu_share":0.10,"fork_count":1,
                     "short_job_count":0,"reason":"noisy_neighbor","event_id":"e1"},
                    {"offender_pod":"zebra","offender_namespace":"z",
                     "stall_us":1000000,"attributed_stall_us":null,
                     "timestamp":100,"cpu_share":0.90,"fork_count":9,
                     "short_job_count":0,"reason":"fork_storm","event_id":"e1"}]}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api", "detail": "summary"}),
    );

    assert!(
        !summary.contains("largest contender"),
        "alphabetical order is not a ranking: {summary}"
    );
    assert!(summary.contains("No offender can be named"), "{summary}");
    // Both are still named — they are evidence of contention, just not of
    // which one contended more.
    assert!(
        summary.contains("a/aardvark") && summary.contains("z/zebra"),
        "{summary}"
    );
}

#[test]
fn a_daemon_with_no_probes_attached_is_not_presented_as_healthy() {
    // The degraded userspace-only state serves entirely plausible host
    // readings while attributing nothing to any process, and `events_per_sec`
    // is zero on a quiet healthy host too — so it cannot carry this. `/readyz`
    // is the authoritative signal and answers 503 when it fires, which is why
    // its body has to be read past the status code.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":0.4,"rss_mb":30,"events_per_sec":0,
                    "rb_overflows":0,"rate_limited":0,"offline":true}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/system");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"timestamp":100,"cpu_percent":9.0,"mem_percent":11.0,
                    "load_avg":[0.0,0.0,0.0],"disk_read_bytes":0,"disk_write_bytes":0,
                    "net_rx_bytes":0,"net_tx_bytes":0,
                    "psi_cpu_some_avg10":0.0,"psi_memory_some_avg10":0.0,
                    "psi_memory_full_avg10":0.0,"psi_io_some_avg10":0.0,
                    "psi_io_full_avg10":0.0}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(503)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":false,"kernel_instrumentation":"unavailable",
                    "transport":"userspace","btf_available":false,"rss_probe":"disabled",
                    "reason":"eBPF probes are not attached; running userspace-only, so no per-process stall attribution is being produced."}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool("linnix_system_health", json!({"detail": "summary"}));

    // Quoted from the daemon, not restated: it knows what to check.
    assert!(
        summary.starts_with("WARNING: eBPF probes are not attached"),
        "readiness must lead: {summary}"
    );
    assert!(
        summary.contains("no per-process stall attribution is being produced"),
        "{summary}"
    );
}

#[test]
fn a_daemon_not_requiring_probes_still_warns_when_they_are_unattached() {
    // With require_kernel_instrumentation=false, cognitod answers `ready:true`
    // by policy even when its probes never attached -- that policy exists so
    // an operator can run degraded on purpose, not so this warning goes
    // silent. The client must inspect kernel_instrumentation independently of
    // the policy-gated `ready` verdict.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":0.4,"rss_mb":30,"events_per_sec":0,
                    "rb_overflows":0,"rate_limited":0,"offline":true}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/system");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"timestamp":100,"cpu_percent":9.0,"mem_percent":11.0,
                    "load_avg":[0.0,0.0,0.0],"disk_read_bytes":0,"disk_write_bytes":0,
                    "net_rx_bytes":0,"net_tx_bytes":0,
                    "psi_cpu_some_avg10":0.0,"psi_memory_some_avg10":0.0,
                    "psi_memory_full_avg10":0.0,"psi_io_some_avg10":0.0,
                    "psi_io_full_avg10":0.0}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        // 200, ready:true -- require_kernel_instrumentation=false -- but the
        // probes are still unattached.
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":true,"kernel_instrumentation":"unavailable",
                    "transport":"userspace","btf_available":false,"rss_probe":"disabled",
                    "reason":null}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool("linnix_system_health", json!({"detail": "summary"}));

    assert!(
        summary.starts_with("WARNING:"),
        "policy-gated readiness must not suppress the probe warning: {summary}"
    );
    assert!(summary.contains("not attached"), "{summary}");
}

#[test]
fn the_evidence_tier_does_not_rank_what_the_summary_refuses_to_rank() {
    // The default tier is `evidence`, so fixing only the summary would leave
    // the invented ranking in the answer most callers actually get.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"permalink":null,"attributions":[
                    {"offender_pod":"aardvark","offender_namespace":"a",
                     "stall_us":1000000,"attributed_stall_us":null,
                     "timestamp":100,"cpu_share":0.10,"fork_count":1,
                     "short_job_count":0,"reason":"noisy_neighbor","event_id":"e1"},
                    {"offender_pod":"zebra","offender_namespace":"z",
                     "stall_us":1000000,"attributed_stall_us":null,
                     "timestamp":100,"cpu_share":0.90,"fork_count":9,
                     "short_job_count":0,"reason":"fork_storm","event_id":"e1"}]}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (evidence, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api"}),
    );

    assert!(
        !evidence.contains("Likely offender"),
        "alphabetical order is not a ranking: {evidence}"
    );
    assert!(
        evidence.contains("may exceed any figure above"),
        "{evidence}"
    );
    assert!(
        evidence.contains("a/aardvark") && evidence.contains("z/zebra"),
        "{evidence}"
    );
}

#[test]
fn one_unmeasurable_contender_stops_the_whole_window_being_ranked() {
    // The mixed case: one offender carries a per-offender split and another
    // carries only rows that predate it. Ranking on the measured one alone
    // would relegate a contender whose contribution is unknown and could be
    // the larger of the two.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"permalink":null,"attributions":[
                    {"offender_pod":"measured","offender_namespace":"m",
                     "stall_us":1000000,"attributed_stall_us":300000,
                     "timestamp":100,"cpu_share":0.30,"fork_count":1,
                     "short_job_count":0,"reason":"noisy_neighbor","event_id":"e1"},
                    {"offender_pod":"legacy","offender_namespace":"l",
                     "stall_us":1000000,"attributed_stall_us":null,
                     "timestamp":100,"cpu_share":0.90,"fork_count":9,
                     "short_job_count":0,"reason":"fork_storm","event_id":"e1"}]}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (evidence, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api"}),
    );

    assert!(!evidence.contains("Likely offender"), "{evidence}");
    // The measured share is still reported — it is real, just not enough to
    // rank the window.
    assert!(evidence.contains("m/measured"), "{evidence}");
    assert!(evidence.contains("100%"), "{evidence}");
    assert!(evidence.contains("l/legacy"), "{evidence}");
    assert!(
        evidence.contains("may exceed any figure above"),
        "{evidence}"
    );
    assert!(
        evidence.contains("not proven causality"),
        "the caveat must survive every exit path: {evidence}"
    );
}

#[test]
fn a_partially_split_offender_is_not_named_the_largest_contender_in_the_summary() {
    // One offender, two rows: one carries a split, one predates it. Its share
    // is knowable from the split row alone, but the unsplit row could still
    // be hiding more, so the summary must not call it "the largest
    // contender" -- that requires the whole window to be measured, and it
    // isn't. The evidence tier already refuses to rank this window (see
    // one_unmeasurable_contender_stops_the_whole_window_being_ranked); the
    // summary tier must agree.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"permalink":null,"attributions":[
                    {"offender_pod":"mixed","offender_namespace":"m",
                     "stall_us":1000000,"attributed_stall_us":300000,
                     "timestamp":100,"cpu_share":0.30,"fork_count":1,
                     "short_job_count":0,"reason":"noisy_neighbor","event_id":"e1"},
                    {"offender_pod":"mixed","offender_namespace":"m",
                     "stall_us":1000000,"attributed_stall_us":null,
                     "timestamp":200,"cpu_share":0.30,"fork_count":1,
                     "short_job_count":0,"reason":"noisy_neighbor","event_id":"e2"}]}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api", "detail": "summary"}),
    );

    assert!(
        !summary.contains("largest contender"),
        "a partially split offender must not be ranked as fully measured: {summary}"
    );
    assert!(summary.contains("m/mixed"), "{summary}");
}

#[test]
fn an_empty_investigation_with_probes_detached_is_not_presented_as_all_clear() {
    // cognitod running userspace-only legitimately returns zero /attribution
    // rows -- it produces no per-process attribution in that state. Without
    // checking /readyz, an empty result reads as "neighbours ruled out",
    // which claims the collector looked and found nothing rather than that
    // it never looked at all.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"attributions": [], "permalink": null}"#);
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(503)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":false,"kernel_instrumentation":"unavailable",
                    "transport":"userspace","btf_available":false,"rss_probe":"disabled",
                    "reason":"eBPF probes are not attached; running userspace-only, so no per-process stall attribution is being produced."}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api", "detail": "summary"}),
    );

    assert!(
        summary.starts_with("WARNING: eBPF probes are not attached"),
        "readiness must lead, same as linnix_system_health: {summary}"
    );
}

#[test]
fn the_raw_tier_of_contention_also_carries_the_readiness_warning() {
    // The summary/evidence fix reads /readyz after building the report, but
    // detail=raw returns before that point, so it kept handing back an
    // apparently authoritative empty attributions array with no warning that
    // nothing was actually collected.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"attributions": [], "permalink": null}"#);
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(503)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":false,"kernel_instrumentation":"unavailable",
                    "transport":"userspace","btf_available":false,"rss_probe":"disabled",
                    "reason":"eBPF probes are not attached; running userspace-only, so no per-process stall attribution is being produced."}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (raw, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api", "detail": "raw"}),
    );

    assert!(
        raw.starts_with("WARNING: eBPF probes are not attached"),
        "the raw tier must carry the readiness warning too: {raw}"
    );
}

#[test]
fn dropped_events_qualify_an_empty_contention_result_even_with_probes_attached() {
    // /readyz only reports whether kernel instrumentation is attached, not
    // whether every event it produced actually reached cognitod. A ring
    // buffer overflow or the rate-limiter dropping events can also leave a
    // window with no attribution rows, and that must not read as "ruled
    // out" either.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"attributions": [], "permalink": null}"#);
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":true,"kernel_instrumentation":"active","transport":"ringbuf",
                    "btf_available":true,"rss_probe":"attached","reason":null}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":1.2,"rss_mb":41,"events_per_sec":900,
                    "rb_overflows":7,"rate_limited":0,"offline":false}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api", "detail": "summary"}),
    );

    assert!(
        summary.contains("ring-buffer overflow"),
        "an empty result with dropped events must not read as ruled-out: {summary}"
    );
}

#[test]
fn an_unreadable_status_endpoint_says_so_rather_than_going_silent_on_loss() {
    // If /status 5xxs or comes back malformed, silently skipping the
    // event-loss check would let an empty result claim contention is ruled
    // out when the tool actually has no idea whether events were dropped.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"attributions": [], "permalink": null}"#);
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":true,"kernel_instrumentation":"active","transport":"ringbuf",
                    "btf_available":true,"rss_probe":"attached","reason":null}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(500);
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api", "detail": "summary"}),
    );

    assert!(
        summary.contains("event loss") && summary.to_lowercase().contains("unknown"),
        "an unreadable /status must not read as zero loss: {summary}"
    );
}

#[test]
fn the_loss_warning_does_not_claim_lifetime_counters_describe_this_window() {
    // rb_overflows/rate_limited are cumulative since cognitod started, not
    // scoped to the queried window. A single overflow last week must not
    // make every later query claim *this* result may be incomplete.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/attribution");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"attributions": [], "permalink": null}"#);
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":true,"kernel_instrumentation":"active","transport":"ringbuf",
                    "btf_available":true,"rss_probe":"attached","reason":null}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":1.2,"rss_mb":41,"events_per_sec":900,
                    "rb_overflows":7,"rate_limited":0,"offline":false}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool(
        "linnix_investigate_contention",
        json!({"namespace": "payments", "pod": "payment-api", "detail": "summary"}),
    );

    assert!(
        summary.contains("since cognitod started") || summary.contains("lifetime"),
        "the warning must not imply the lifetime counters describe this query's window: \
         {summary}"
    );
}

#[test]
fn an_empty_incident_history_still_serialises_as_json_in_the_raw_tier() {
    // The raw tier's promise is the daemon's own bytes. Substituting prose
    // for [] in the empty case breaks a caller parsing this as JSON, in
    // exactly the case that is valid and easy to hit -- a quiet host.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/incidents");
        then.status(200)
            .header("content-type", "application/json")
            .body("[]");
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (raw, _) = client.call_tool("linnix_recent_incidents", json!({"detail": "raw"}));

    assert_eq!(raw.trim(), "[]", "{raw}");
}

#[test]
fn system_health_warns_on_rate_limiting_even_without_ring_buffer_overflows() {
    // Rate-limited events are discarded before reaching the context store
    // just as overflowed ones are. Gating the warning on rb_overflows alone
    // let a purely rate_limited daemon report as loss-free.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":1.2,"rss_mb":41,"events_per_sec":900,
                    "rb_overflows":0,"rate_limited":50,"offline":false}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":true,"kernel_instrumentation":"active","transport":"ringbuf",
                    "btf_available":true,"rss_probe":"attached","reason":null}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/system");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"timestamp":100,"cpu_percent":9.0,"mem_percent":11.0,
                    "load_avg":[0.0,0.0,0.0],"disk_read_bytes":0,"disk_write_bytes":0,
                    "net_rx_bytes":0,"net_tx_bytes":0,
                    "psi_cpu_some_avg10":0.0,"psi_memory_some_avg10":0.0,
                    "psi_memory_full_avg10":0.0,"psi_io_some_avg10":0.0,
                    "psi_io_full_avg10":0.0}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool("linnix_system_health", json!({"detail": "summary"}));

    assert!(
        summary.starts_with("WARNING:") && summary.contains("rate-limited"),
        "rate limiting alone must still warn, at the summary tier: {summary}"
    );
}

#[test]
fn system_health_warns_on_queue_backpressure_drops_alone() {
    // The listener's bounded worker queue can drop events under backpressure
    // even when nothing overflowed the ring buffer and the rate limiter
    // never engaged -- a third, independent loss path counted separately by
    // the daemon as dropped_events_total. Gating the warning on the other
    // two counters let a purely queue-dropping daemon report as loss-free.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":1.2,"rss_mb":41,"events_per_sec":900,
                    "rb_overflows":0,"rate_limited":0,"dropped_events_total":12,
                    "offline":false}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"ready":true,"kernel_instrumentation":"active","transport":"ringbuf",
                    "btf_available":true,"rss_probe":"attached","reason":null}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/system");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"timestamp":100,"cpu_percent":9.0,"mem_percent":11.0,
                    "load_avg":[0.0,0.0,0.0],"disk_read_bytes":0,"disk_write_bytes":0,
                    "net_rx_bytes":0,"net_tx_bytes":0,
                    "psi_cpu_some_avg10":0.0,"psi_memory_some_avg10":0.0,
                    "psi_memory_full_avg10":0.0,"psi_io_some_avg10":0.0,
                    "psi_io_full_avg10":0.0}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool("linnix_system_health", json!({"detail": "summary"}));

    assert!(
        summary.starts_with("WARNING:") && summary.contains("queue-dropped"),
        "queue backpressure drops alone must still warn, at the summary tier: {summary}"
    );
}

#[test]
fn a_readiness_endpoint_that_cannot_be_read_is_not_silence() {
    // A proxy error page parses as JSON perfectly well and says nothing about
    // the daemon. Treating that as "no warning" would put this tool right back
    // where the false-offline fix found it: presenting a possibly blind daemon
    // as healthy, only now without even the wrong warning to give it away.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/status");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"cpu_pct":0.4,"rss_mb":30,"events_per_sec":0,
                    "rb_overflows":0,"rate_limited":0,"offline":false}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/system");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"timestamp":100,"cpu_percent":9.0,"mem_percent":11.0,
                    "load_avg":[0.0,0.0,0.0],"disk_read_bytes":0,"disk_write_bytes":0,
                    "net_rx_bytes":0,"net_tx_bytes":0,
                    "psi_cpu_some_avg10":0.0,"psi_memory_some_avg10":0.0,
                    "psi_memory_full_avg10":0.0,"psi_io_some_avg10":0.0,
                    "psi_io_full_avg10":0.0}"#,
            );
    });
    server.mock(|when, then| {
        when.method(GET).path("/readyz");
        then.status(502)
            .header("content-type", "application/json")
            .body(r#"{"error":"bad gateway"}"#);
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (summary, _) = client.call_tool("linnix_system_health", json!({"detail": "summary"}));

    assert!(summary.starts_with("WARNING:"), "{summary}");
    assert!(summary.contains("without a `ready` verdict"), "{summary}");
    assert!(summary.contains("unconfirmed"), "{summary}");
}

#[test]
fn a_pid_only_incident_target_is_not_dropped_from_the_headline() {
    // `target_name` and `target_pid` are independently optional on the
    // daemon's incident record. An incident circuit-breaker can act on a pid
    // before `comm` is resolved, leaving target_name null. The headline must
    // still say which process was acted on, the way the evidence tier already
    // does with a bare "pid <n>".
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/incidents/9");
        then.status(200)
            .header("content-type", "application/json")
            .body(
                r#"{"id":9,"timestamp":1732242135,"event_type":"circuit_breaker_cpu",
                    "action":"auto_kill","target_name":null,"target_pid":472693,
                    "psi_cpu":75.2,"cpu_percent":96.3,
                    "investigation":null,"llm_analysis":null,
                    "psi_after":null,"recovery_time_ms":null}"#,
            );
    });

    let mut client = McpClient::spawn(&server.base_url());
    let (headline, _) = client.call_tool(
        "linnix_explain_incident",
        json!({"id": 9, "detail": "summary"}),
    );

    assert!(
        headline.contains("472693"),
        "a pid-only target must not vanish from the headline: {headline}"
    );
}
