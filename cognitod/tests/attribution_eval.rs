//! Eval suite for the stall-attribution emit seam.
//!
//! These are not assertions about internal helpers. Each case describes a
//! cluster situation an SRE would recognise — a CPU hog next door, a fork bomb,
//! a stall too small to care about — and checks the three things a user
//! actually observes when it happens: the JSON log event, the alert, and the
//! Prometheus counters.
//!
//! Scenarios live in one table so adding a case is a data change, not a code
//! change, and so a regression names the situation it broke rather than a
//! function.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cognitod::attribution::{AlertOutput, AttributionSink, BlameMetrics};
use cognitod::collectors::psi::{CpuConsumer, StallEvent, calculate_blame_attributions};
use cognitod::metrics::Metrics;
use cognitod::schema::InsightReason;

/// What an offender is expected to look like in the emitted output.
struct ExpectedOffender {
    pod: &'static str,
    reason: InsightReason,
    /// Inclusive bounds on the stall credited to this offender, in
    /// milliseconds. A range rather than a point because the split is
    /// proportional to a heuristic score we expect to keep tuning.
    stall_ms: (u64, u64),
}

struct Scenario {
    /// What is happening in the cluster, in the words a user would use.
    name: &'static str,
    victim_stall_us: u64,
    consumers: &'static [(&'static str, f32)],
    forks: &'static [(&'static str, u64)],
    short_jobs: &'static [(&'static str, u64)],
    /// Offenders expected to produce a JSON event and an alert, in rank order.
    expect_reported: &'static [ExpectedOffender],
    /// Offenders expected to be counted but stay below the reporting bar.
    expect_counted_only: &'static [&'static str],
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "a single CPU hog monopolises the node and stalls the payment API",
        victim_stall_us: 800_000,
        consumers: &[("image-resize-worker", 90.0), ("sidecar-proxy", 1.0)],
        forks: &[],
        short_jobs: &[],
        expect_reported: &[ExpectedOffender {
            pod: "image-resize-worker",
            reason: InsightReason::NoisyNeighbor,
            stall_ms: (700, 800),
        }],
        expect_counted_only: &["sidecar-proxy"],
    },
    Scenario {
        name: "a fork bomb is blamed even though its CPU share looks modest",
        victim_stall_us: 1_000_000,
        consumers: &[("fork-bomb", 10.0), ("steady-worker", 20.0)],
        forks: &[("prod/fork-bomb", 400)],
        short_jobs: &[],
        expect_reported: &[
            ExpectedOffender {
                pod: "fork-bomb",
                reason: InsightReason::ForkStorm,
                stall_ms: (600, 900),
            },
            ExpectedOffender {
                pod: "steady-worker",
                reason: InsightReason::NoisyNeighbor,
                stall_ms: (100, 400),
            },
        ],
        expect_counted_only: &[],
    },
    Scenario {
        name: "a CI runner churning short-lived jobs is named as the offender",
        victim_stall_us: 600_000,
        consumers: &[],
        forks: &[],
        short_jobs: &[("prod/ci-runner", 120)],
        expect_reported: &[ExpectedOffender {
            pod: "ci-runner",
            reason: InsightReason::ShortJobChurn,
            stall_ms: (500, 600),
        }],
        expect_counted_only: &[],
    },
    Scenario {
        name: "a CPU-bound victim is never blamed for stalling itself",
        victim_stall_us: 900_000,
        // The victim burns more CPU than anyone: it is busy *because* it is
        // being starved. Blaming it would both mis-name the culprit and eat
        // most of the stall budget.
        consumers: &[("payment-api", 70.0), ("image-resize-worker", 30.0)],
        forks: &[("prod/payment-api", 300)],
        short_jobs: &[],
        expect_reported: &[ExpectedOffender {
            pod: "image-resize-worker",
            reason: InsightReason::NoisyNeighbor,
            stall_ms: (890, 900),
        }],
        expect_counted_only: &[],
    },
    Scenario {
        name: "a pod busy across many processes is credited for all of them",
        victim_stall_us: 1_000_000,
        // Consumers arrive per process: the worker has four busy processes at
        // 20% each, the single-process neighbour has one at 30%. The worker is
        // the bigger consumer and must rank first.
        consumers: &[
            ("multi-proc-worker", 20.0),
            ("multi-proc-worker", 20.0),
            ("multi-proc-worker", 20.0),
            ("multi-proc-worker", 20.0),
            ("single-proc-neighbour", 30.0),
        ],
        forks: &[],
        short_jobs: &[],
        expect_reported: &[
            ExpectedOffender {
                pod: "multi-proc-worker",
                reason: InsightReason::NoisyNeighbor,
                stall_ms: (700, 730),
            },
            ExpectedOffender {
                pod: "single-proc-neighbour",
                reason: InsightReason::NoisyNeighbor,
                stall_ms: (260, 280),
            },
        ],
        expect_counted_only: &[],
    },
    Scenario {
        name: "a stall split thinly across many neighbours reports nobody",
        victim_stall_us: 300_000,
        consumers: &[
            ("neighbour-a", 25.0),
            ("neighbour-b", 25.0),
            ("neighbour-c", 25.0),
            ("neighbour-d", 25.0),
        ],
        forks: &[],
        short_jobs: &[],
        // 300ms over four equal neighbours is 75ms each: real, but not a noisy
        // neighbour worth waking anyone for.
        expect_reported: &[],
        expect_counted_only: &["neighbour-a", "neighbour-b", "neighbour-c", "neighbour-d"],
    },
];

const VICTIM_POD: &str = "payment-api";
const VICTIM_NS: &str = "prod";

fn build_stall_event(scenario: &Scenario) -> StallEvent {
    StallEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        victim_pod: VICTIM_POD.to_string(),
        victim_namespace: VICTIM_NS.to_string(),
        stall_delta_us: scenario.victim_stall_us,
        timestamp: Instant::now(),
        concurrent_consumers: scenario
            .consumers
            .iter()
            .map(|(pod, cpu)| CpuConsumer {
                pod: (*pod).to_string(),
                namespace: VICTIM_NS.to_string(),
                cpu_percent: *cpu,
            })
            .collect(),
        memory_stall_delta_us: 0,
        io_stall_delta_us: 0,
        memory_bytes: 0,
        io_bytes: 0,
        fork_counts: scenario
            .forks
            .iter()
            .map(|(key, count)| ((*key).to_string(), *count))
            .collect(),
        short_job_counts: scenario
            .short_jobs
            .iter()
            .map(|(key, count)| ((*key).to_string(), *count))
            .collect(),
    }
}

#[test]
fn scenarios_produce_the_expected_events_alerts_and_metrics() {
    for scenario in SCENARIOS {
        let metrics = Arc::new(BlameMetrics::new("node-1"));
        let (alert_tx, mut alert_rx) = tokio::sync::broadcast::channel(64);
        let daemon_metrics = Arc::new(Metrics::new());
        let sink = AttributionSink::new(
            metrics.clone(),
            Some(AlertOutput::new(alert_tx, daemon_metrics.clone())),
            "node-1",
        );

        let event = build_stall_event(scenario);
        let attributions = calculate_blame_attributions(&event);
        let emitted = sink.emit(&attributions);

        // The split must never invent stall time that the kernel did not report.
        let total_attributed: u64 = attributions.iter().map(|a| a.attributed_stall_us).sum();
        assert!(
            total_attributed <= scenario.victim_stall_us,
            "[{}] attributed {}us exceeds the observed stall of {}us",
            scenario.name,
            total_attributed,
            scenario.victim_stall_us
        );

        assert_eq!(
            emitted.len(),
            scenario.expect_reported.len(),
            "[{}] expected {} reported offender(s), got {:?}",
            scenario.name,
            scenario.expect_reported.len(),
            emitted
                .iter()
                .map(|e| e.offender.pod.as_str())
                .collect::<Vec<_>>()
        );

        for (expected, actual) in scenario.expect_reported.iter().zip(emitted.iter()) {
            assert_eq!(
                actual.offender.pod, expected.pod,
                "[{}] wrong offender ranked",
                scenario.name
            );
            assert_eq!(
                actual.offender.reason, expected.reason,
                "[{}] wrong reason for {}",
                scenario.name, expected.pod
            );
            assert!(
                actual.stall_ms >= expected.stall_ms.0 && actual.stall_ms <= expected.stall_ms.1,
                "[{}] {} credited {}ms, expected {}..={}ms",
                scenario.name,
                expected.pod,
                actual.stall_ms,
                expected.stall_ms.0,
                expected.stall_ms.1
            );

            // The victim must be identifiable, otherwise the event is useless
            // for the person being paged.
            assert_eq!(actual.victim.pod, VICTIM_POD);
            assert_eq!(actual.victim.namespace, VICTIM_NS);
            assert_eq!(actual.event_type, "linnix.stall_attribution");
        }

        // Every reported offender produces exactly one alert on the same
        // channel the rest of the daemon already uses.
        let mut alerts = Vec::new();
        while let Ok(alert) = alert_rx.try_recv() {
            alerts.push(alert);
        }
        assert_eq!(
            alerts.len(),
            scenario.expect_reported.len(),
            "[{}] alert count did not match reported offenders",
            scenario.name
        );
        // ...and each of those alerts is counted, so alert-volume monitoring
        // built on /metrics sees attribution alerts rather than silently
        // missing them.
        assert_eq!(
            daemon_metrics.alerts_emitted(),
            alerts.len() as u64,
            "[{}] linnix_alerts_emitted_total did not count the attribution alerts",
            scenario.name
        );
        for (alert, expected) in alerts.iter().zip(scenario.expect_reported.iter()) {
            assert_eq!(alert.rule, "stall_attribution");
            assert!(
                alert.message.contains(expected.pod) && alert.message.contains(VICTIM_POD),
                "[{}] alert should name both parties, got: {}",
                scenario.name,
                alert.message
            );
        }

        // Offenders below the reporting bar are still counted — the dashboard
        // shows the full picture even when nothing was worth alerting on.
        let mut body = String::new();
        metrics.render_prometheus(&mut body);

        // No scenario has the victim genuinely stalling itself, so it must
        // never appear as its own offender in any output.
        assert!(
            !body.contains(&format!("offender_pod=\"{}\"", VICTIM_POD)),
            "[{}] the victim was blamed for its own stall:\n{}",
            scenario.name,
            body
        );
        for pod in scenario.expect_counted_only {
            assert!(
                body.contains(&format!("offender_pod=\"{}\"", pod)),
                "[{}] {} should still appear in the counters:\n{}",
                scenario.name,
                pod,
                body
            );
        }
    }
}

#[test]
fn json_event_matches_the_documented_schema() {
    let metrics = Arc::new(BlameMetrics::new("node-1"));
    let sink = AttributionSink::new(metrics, None, "node-1");

    let event = build_stall_event(&SCENARIOS[0]);
    let emitted = sink.emit(&calculate_blame_attributions(&event));
    let json: serde_json::Value = serde_json::to_value(&emitted[0]).unwrap();

    // Log pipelines facet on these paths; renaming one is a breaking change for
    // every saved Datadog/Splunk query.
    assert_eq!(json["event_type"], "linnix.stall_attribution");
    assert_eq!(json["severity"], "warn");
    assert!(json["stall_ms"].is_u64());
    assert_eq!(json["victim"]["pod"], VICTIM_POD);
    assert_eq!(json["victim"]["namespace"], VICTIM_NS);
    assert_eq!(json["offender"]["pod"], "image-resize-worker");
    assert_eq!(json["offender"]["namespace"], VICTIM_NS);
    assert_eq!(json["offender"]["reason"], "noisy_neighbor");
}

#[test]
fn repeated_stalls_accumulate_monotonically() {
    let metrics = Arc::new(BlameMetrics::new("node-1"));
    let sink = AttributionSink::new(metrics.clone(), None, "node-1");

    let event = build_stall_event(&SCENARIOS[0]);
    let attributions = calculate_blame_attributions(&event);

    let mut previous = 0.0_f64;
    for round in 1..=5 {
        sink.emit(&attributions);
        let value = scrape_pair_seconds(&metrics, "image-resize-worker", VICTIM_POD);
        assert!(
            value > previous,
            "round {}: counter went from {} to {}, which reads as a reset",
            round,
            previous,
            value
        );
        previous = value;
    }
}

#[test]
fn a_flood_of_distinct_offenders_stays_bounded() {
    const CAP: usize = 32;
    let metrics = Arc::new(BlameMetrics::with_cap("node-1", CAP));
    let sink = AttributionSink::new(metrics.clone(), None, "node-1");

    // A cluster-wide event where hundreds of pods each take a sliver of blame
    // must not let the metrics endpoint grow without limit.
    for batch in 0..200 {
        let consumers: Vec<CpuConsumer> = (0..5)
            .map(|i| CpuConsumer {
                pod: format!("batch-{}-pod-{}", batch, i),
                namespace: VICTIM_NS.to_string(),
                cpu_percent: 10.0,
            })
            .collect();

        let event = StallEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            victim_pod: format!("victim-{}", batch),
            victim_namespace: VICTIM_NS.to_string(),
            stall_delta_us: 500_000,
            timestamp: Instant::now(),
            concurrent_consumers: consumers,
            memory_stall_delta_us: 0,
            io_stall_delta_us: 0,
            memory_bytes: 0,
            io_bytes: 0,
            fork_counts: HashMap::new(),
            short_job_counts: HashMap::new(),
        };
        sink.emit(&calculate_blame_attributions(&event));
    }

    assert!(
        metrics.pair_series() <= CAP,
        "pair series grew to {}, above the cap of {}",
        metrics.pair_series(),
        CAP
    );
    assert!(
        metrics.evictions() > 0,
        "eviction should be recorded so an operator can tell the cap was hit"
    );

    let mut body = String::new();
    metrics.render_prometheus(&mut body);
    assert!(body.contains("linnix_blame_series_evicted_total"));
}

#[test]
fn sustained_pressure_reports_once_then_goes_quiet() {
    let metrics = Arc::new(BlameMetrics::new("node-1"));
    let (alert_tx, mut alert_rx) = tokio::sync::broadcast::channel(64);
    let daemon_metrics = Arc::new(Metrics::new());
    let sink = AttributionSink::new(
        metrics.clone(),
        Some(AlertOutput::new(alert_tx, daemon_metrics.clone())),
        "node-1",
    )
    .with_cooldown(Duration::from_secs(300));

    let attributions = calculate_blame_attributions(&build_stall_event(&SCENARIOS[0]));

    // A noisy neighbour that keeps going is detected once per detection window.
    // Reporting all twelve would page someone twelve times for one incident.
    let mut reported = 0;
    for _ in 0..12 {
        reported += sink.emit(&attributions).len();
    }

    assert_eq!(reported, 1, "one incident should report once");
    let mut alerts = 0;
    while alert_rx.try_recv().is_ok() {
        alerts += 1;
    }
    assert_eq!(alerts, 1, "one incident should page once");
    assert_eq!(
        daemon_metrics.alerts_emitted(),
        1,
        "the suppressed repeats must not be counted either"
    );

    // The counters are the continuous signal and must keep climbing while
    // reporting is suppressed, otherwise the dashboard would show the problem
    // ending when it merely stopped being announced.
    assert!(
        scrape_pair_seconds(&metrics, "image-resize-worker", VICTIM_POD) > 8.0,
        "counters should reflect all twelve windows, not just the reported one"
    );
}

#[test]
fn a_second_offender_is_not_silenced_by_the_first() {
    let metrics = Arc::new(BlameMetrics::new("node-1"));
    let (alert_tx, mut alert_rx) = tokio::sync::broadcast::channel(64);
    let sink = AttributionSink::new(
        metrics,
        Some(AlertOutput::new(alert_tx, Arc::new(Metrics::new()))),
        "node-1",
    )
    .with_cooldown(Duration::from_secs(300));

    // The image resizer is already being reported on.
    sink.emit(&calculate_blame_attributions(&build_stall_event(
        &SCENARIOS[0],
    )));
    while alert_rx.try_recv().is_ok() {}

    // A different offender starts hurting the same victim. This is new
    // information: suppressing it because an unrelated pair is in cooldown
    // would hide the second half of a spreading incident.
    let second = StallEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        victim_pod: VICTIM_POD.to_string(),
        victim_namespace: VICTIM_NS.to_string(),
        stall_delta_us: 800_000,
        timestamp: Instant::now(),
        concurrent_consumers: vec![CpuConsumer {
            pod: "batch-etl".to_string(),
            namespace: VICTIM_NS.to_string(),
            cpu_percent: 95.0,
        }],
        memory_stall_delta_us: 0,
        io_stall_delta_us: 0,
        memory_bytes: 0,
        io_bytes: 0,
        fork_counts: HashMap::new(),
        short_job_counts: HashMap::new(),
    };

    let emitted = sink.emit(&calculate_blame_attributions(&second));
    assert_eq!(emitted.len(), 1, "a new offender must still be reported");
    assert_eq!(emitted[0].offender.pod, "batch-etl");
    assert!(
        alert_rx.try_recv().is_ok(),
        "a new offender must still page"
    );
}

#[test]
fn an_ongoing_offender_reports_again_once_the_cooldown_lapses() {
    let metrics = Arc::new(BlameMetrics::new("node-1"));
    let sink =
        AttributionSink::new(metrics, None, "node-1").with_cooldown(Duration::from_millis(150));

    let attributions = calculate_blame_attributions(&build_stall_event(&SCENARIOS[0]));

    assert_eq!(sink.emit(&attributions).len(), 1);
    assert_eq!(sink.emit(&attributions).len(), 0, "still within cooldown");

    // A problem that is still happening after the quiet period re-announces
    // itself, rather than being silenced permanently by its first report.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        sink.emit(&attributions).len(),
        1,
        "an ongoing problem should re-announce after the cooldown"
    );
}

#[test]
fn a_zero_cooldown_reports_every_occurrence() {
    let metrics = Arc::new(BlameMetrics::new("node-1"));
    let sink = AttributionSink::new(metrics, None, "node-1").with_cooldown(Duration::from_secs(0));

    let attributions = calculate_blame_attributions(&build_stall_event(&SCENARIOS[0]));
    let reported: usize = (0..5).map(|_| sink.emit(&attributions).len()).sum();

    assert_eq!(
        reported, 5,
        "opting out of throttling should report each time"
    );
}

#[test]
fn a_crashlooping_pod_keeps_accumulating_across_restarts() {
    let metrics = BlameMetrics::new("node-1");

    // The container stalls, then is OOMKilled and replaced. The new cgroup's
    // counter starts from zero, but the pod's series must keep climbing —
    // freezing it would make a crashlooping pod look healthy.
    metrics.record_victim_pressure("prod", "checkout-api", "container-a", 900_000);
    metrics.record_victim_pressure("prod", "checkout-api", "container-b", 150_000);
    metrics.record_victim_pressure("prod", "checkout-api", "container-b", 400_000);

    assert_eq!(
        scrape_victim_us(&metrics, "checkout-api"),
        1_300_000,
        "restarts should add to the pod counter, not reset or freeze it"
    );
}

#[test]
fn every_container_in_a_pod_counts_towards_its_pressure() {
    let metrics = BlameMetrics::new("node-1");

    // A pod with a sidecar has one cgroup per container. Reporting only the
    // noisiest one would undercount every meshed workload in the cluster.
    metrics.record_victim_pressure("prod", "checkout-api", "app-container", 600_000);
    metrics.record_victim_pressure("prod", "checkout-api", "proxy-sidecar", 250_000);

    assert_eq!(scrape_victim_us(&metrics, "checkout-api"), 850_000);
}

/// Reads one victim counter back out of the Prometheus exposition.
fn scrape_victim_us(metrics: &BlameMetrics, pod: &str) -> u64 {
    let mut body = String::new();
    metrics.render_prometheus(&mut body);

    let needle = format!("victim_pod=\"{}\"", pod);
    body.lines()
        .find(|line| line.starts_with("linnix_pod_psi_pressure_total{") && line.contains(&needle))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("no pressure counter for {} in:\n{}", pod, body))
}

/// Reads one pair counter back out of the Prometheus exposition, which is the
/// only view of it a user ever gets.
fn scrape_pair_seconds(metrics: &BlameMetrics, offender: &str, victim: &str) -> f64 {
    try_scrape_pair_seconds(metrics, offender, victim).unwrap_or_else(|| {
        let mut body = String::new();
        metrics.render_prometheus(&mut body);
        panic!("no counter for {} -> {} in:\n{}", offender, victim, body);
    })
}

fn try_scrape_pair_seconds(metrics: &BlameMetrics, offender: &str, victim: &str) -> Option<f64> {
    let mut body = String::new();
    metrics.render_prometheus(&mut body);

    let needle_offender = format!("offender_pod=\"{}\"", offender);
    let needle_victim = format!("victim_pod=\"{}\"", victim);

    body.lines()
        .find(|line| {
            line.starts_with("linnix_stall_induced_seconds_total{")
                && line.contains(&needle_offender)
                && line.contains(&needle_victim)
        })
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
}

// --- Full loop: fixture cgroup tree through PsiMonitor -----------------------

/// Drives the real scan loop against a fake cgroup hierarchy and checks that a
/// stalling pod shows up on the metrics endpoint. This covers the path from
/// "the kernel wrote a number into cpu.pressure" to "an SRE can see it", which
/// the scenario table above deliberately does not touch.
///
/// Offender attribution needs a populated live-process map that the loop builds
/// from eBPF events, so this test asserts the victim half only; the offender
/// half is covered by the scenarios above.
#[tokio::test]
async fn scan_loop_surfaces_a_stalling_pod_on_the_metrics_endpoint() {
    use cognitod::collectors::psi::PsiMonitor;
    use cognitod::context::ContextStore;
    use cognitod::k8s::{K8sContext, K8sMetadata, Priority};

    // K8sContext::new reads its endpoint from the environment; the watcher is
    // never started, so nothing is actually dialled.
    unsafe {
        std::env::set_var("K8S_API_URL", "http://127.0.0.1:1");
        std::env::set_var("K8S_TOKEN", "dummy");
    }
    let k8s_ctx = K8sContext::new().expect("K8sContext should build from env");

    let container_id = "a".repeat(64);
    k8s_ctx.insert_metadata(
        container_id.clone(),
        K8sMetadata {
            pod_name: "checkout-api".to_string(),
            namespace: "prod".to_string(),
            container_name: "server".to_string(),
            owner_kind: None,
            owner_name: None,
            priority: Priority::default(),
            slo_tier: None,
        },
    );

    let tmp = tempfile::tempdir().unwrap();
    let cgroup_dir = tmp.path().join("kubepods.slice").join(format!(
        "kubepods-burstable-pod1.slice/cri-containerd-{}.scope",
        container_id
    ));
    std::fs::create_dir_all(&cgroup_dir).unwrap();
    let pressure_file = cgroup_dir.join("cpu.pressure");

    let write_pressure = |total: u64| {
        std::fs::write(
            &pressure_file,
            format!(
                "some avg10=10.00 avg60=5.00 avg300=1.00 total={}\n\
                 full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                total
            ),
        )
        .unwrap();
    };
    write_pressure(1_000_000);

    let metrics = Arc::new(BlameMetrics::new("node-1"));
    let sink = Arc::new(AttributionSink::new(metrics.clone(), None, "node-1"));
    let context = Arc::new(ContextStore::new(
        Duration::from_secs(60),
        1000,
        Some(k8s_ctx.clone()),
    ));

    // Generous iteration budget: the loop is stopped by aborting the task once
    // the expected reading lands, so a slow runner delays the test rather than
    // ending the scan before the assertion can be made.
    let monitor = PsiMonitor::new(k8s_ctx, context, None, 0, sink)
        .with_cgroup_root(tmp.path())
        .with_max_iterations(60);
    let handle = tokio::spawn(monitor.run());

    // The pod keeps stalling while the monitor scans.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    write_pressure(2_500_000);

    // Wait for the second reading to be picked up rather than assuming a scan
    // landed within a fixed window.
    let line = poll_until(Duration::from_secs(30), || {
        let mut body = String::new();
        metrics.render_prometheus(&mut body);
        body.lines()
            .find(|l| l.starts_with("linnix_pod_psi_pressure_total{") && l.ends_with(" 2500000"))
            .map(str::to_string)
    })
    .await
    .expect("victim pressure never reached the second reading");
    handle.abort();

    // victim_-prefixed, not pod/namespace: Prometheus' kubernetes-pods job
    // attaches target labels of those plain names and would rename the
    // metric's own, leaving queries grouped by the agent pod instead.
    assert!(
        line.contains(r#"victim_pod="checkout-api""#),
        "line was: {}",
        line
    );
    assert!(
        line.contains(r#"victim_namespace="prod""#),
        "line was: {}",
        line
    );
    assert!(
        !line.contains(r#",pod=""#) && !line.starts_with("linnix_pod_psi_pressure_total{pod="),
        "a bare pod label collides with the scrape target's own: {}",
        line
    );
    assert!(line.contains(r#"node="node-1""#), "line was: {}", line);
}

#[tokio::test]
async fn scan_loop_sums_container_psi_deltas_before_thresholding_a_pod() {
    use cognitod::context::ContextStore;
    use cognitod::k8s::{K8sContext, K8sMetadata, Priority};
    use cognitod::{PERCENT_MILLI_UNKNOWN, ProcessEvent, ProcessEventWire};

    unsafe {
        std::env::set_var("K8S_API_URL", "http://127.0.0.1:1");
        std::env::set_var("K8S_TOKEN", "dummy");
    }
    let k8s_ctx = K8sContext::new().expect("K8sContext should build from env");

    let container_a = "a".repeat(64);
    let container_b = "b".repeat(64);
    for (container_id, container_name) in [
        (container_a.clone(), "server"),
        (container_b.clone(), "sidecar"),
    ] {
        k8s_ctx.insert_metadata(
            container_id,
            K8sMetadata {
                pod_name: "checkout-api".to_string(),
                namespace: "prod".to_string(),
                container_name: container_name.to_string(),
                owner_kind: None,
                owner_name: None,
                priority: Priority::default(),
                slo_tier: None,
            },
        );
    }

    let tmp = tempfile::tempdir().unwrap();
    let pressure_file = |container_id: &str| {
        let cgroup_dir = tmp.path().join("kubepods.slice").join(format!(
            "kubepods-burstable-pod1.slice/cri-containerd-{}.scope",
            container_id
        ));
        std::fs::create_dir_all(&cgroup_dir).unwrap();
        cgroup_dir.join("cpu.pressure")
    };
    let pressure_a = pressure_file(&container_a);
    let pressure_b = pressure_file(&container_b);

    let write_pressure = |path: &std::path::Path, total: u64| {
        std::fs::write(
            path,
            format!(
                "some avg10=10.00 avg60=5.00 avg300=1.00 total={}\n\
                 full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                total
            ),
        )
        .unwrap();
    };
    write_pressure(&pressure_a, 1_000_000);
    write_pressure(&pressure_b, 1_000_000);

    let metrics = Arc::new(BlameMetrics::new("node-1"));
    let sink = Arc::new(AttributionSink::new(metrics.clone(), None, "node-1"));
    let context = Arc::new(ContextStore::new(
        Duration::from_secs(60),
        1000,
        Some(k8s_ctx.clone()),
    ));

    let mut offender = ProcessEvent::new(ProcessEventWire {
        pid: 4242,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        event_type: 0,
        ts_ns: 1,
        seq: 1,
        comm: [0; 16],
        exit_time_ns: 0,
        cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
        mem_pct_milli: PERCENT_MILLI_UNKNOWN,
        data: 0,
        data2: 0,
        aux: 0,
        aux2: 0,
    });
    offender.set_cpu_percent(Some(90.0));
    context.get_live_map().insert(
        4242,
        (
            offender,
            Some(Arc::new(K8sMetadata {
                pod_name: "cpu-hog".to_string(),
                namespace: "prod".to_string(),
                container_name: "worker".to_string(),
                owner_kind: None,
                owner_name: None,
                priority: Priority::default(),
                slo_tier: None,
            })),
        ),
    );

    let monitor = cognitod::collectors::psi::PsiMonitor::new(k8s_ctx, context, None, 0, sink)
        .with_cgroup_root(tmp.path())
        .with_max_iterations(60);
    let handle = tokio::spawn(monitor.run());

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    write_pressure(&pressure_a, 1_070_000);
    write_pressure(&pressure_b, 1_080_000);

    let seconds = poll_until(Duration::from_secs(30), || {
        try_scrape_pair_seconds(&metrics, "cpu-hog", "checkout-api")
    })
    .await
    .expect("pod-level attribution was not emitted for summed container PSI deltas");
    handle.abort();

    assert!(
        (seconds - 0.150).abs() < 0.000_001,
        "expected 150ms of attributed stall from the two containers, got {seconds:.6}s"
    );
}

/// Retries `check` on a short interval until it yields a value or the deadline
/// passes, so timing-sensitive assertions do not depend on a scan landing
/// inside a fixed sleep.
async fn poll_until<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = check() {
            return Some(value);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
