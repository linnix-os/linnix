// cognitod/src/claw_metrics.rs — Linnix-Claw Prometheus SLO metrics (§10.5)
//
// Tracks mandate lifecycle, receipt signing, settlement finality, and
// reconciliation runs. All fields are lock-free atomics suitable for the
// hot path.
//
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Linnix-Commercial

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

// ── Histogram bucket boundaries (nanoseconds for latency, seconds for finality) ──

/// Mandate creation latency histogram buckets (nanoseconds).
/// Covers 50µs → 500ms in exponential-ish steps.
const MANDATE_LATENCY_BUCKETS_NS: &[u64] = &[
    50_000,      // 50µs
    100_000,     // 100µs
    250_000,     // 250µs
    500_000,     // 500µs
    1_000_000,   // 1ms
    2_500_000,   // 2.5ms
    5_000_000,   // 5ms
    10_000_000,  // 10ms
    25_000_000,  // 25ms
    50_000_000,  // 50ms
    100_000_000, // 100ms
    500_000_000, // 500ms
];

/// Receipt signing latency histogram buckets (nanoseconds).
/// Covers 10µs → 100ms — signing should be fast (Ed25519 + secp256k1).
const RECEIPT_SIGN_LATENCY_BUCKETS_NS: &[u64] = &[
    10_000,      // 10µs
    25_000,      // 25µs
    50_000,      // 50µs
    100_000,     // 100µs
    250_000,     // 250µs
    500_000,     // 500µs
    1_000_000,   // 1ms
    5_000_000,   // 5ms
    10_000_000,  // 10ms
    50_000_000,  // 50ms
    100_000_000, // 100ms
];

/// Settlement finality histogram buckets (seconds).
/// From 1s to 1h — covers L2 fast finality through L1 confirmation.
const SETTLEMENT_FINALITY_BUCKETS_S: &[u64] = &[
    1,    // 1s
    2,    // 2s
    5,    // 5s
    10,   // 10s
    30,   // 30s
    60,   // 1min
    120,  // 2min
    300,  // 5min
    600,  // 10min
    1800, // 30min
    3600, // 1h
];

// ── Lock-free histogram ─────────────────────────────────────────────────────

/// A fixed-bucket histogram using atomic counters.
///
/// Each bucket counts observations ≤ the bucket boundary. An extra `+Inf`
/// bucket captures all observations. Thread-safe via `AtomicU64`.
pub struct AtomicHistogram {
    /// Upper-bound of each bucket (exclusive of next).
    boundaries: &'static [u64],
    /// One counter per boundary, plus a +Inf counter at the end.
    buckets: Vec<AtomicU64>,
    /// Running sum of all observed values.
    sum: AtomicU64,
    /// Total observation count.
    count: AtomicU64,
}

impl AtomicHistogram {
    pub fn new(boundaries: &'static [u64]) -> Self {
        let mut buckets = Vec::with_capacity(boundaries.len() + 1);
        for _ in 0..=boundaries.len() {
            buckets.push(AtomicU64::new(0));
        }
        Self {
            boundaries,
            buckets,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record a single observation.
    pub fn observe(&self, value: u64) {
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Increment all buckets whose boundary ≥ value (cumulative).
        for (i, &bound) in self.boundaries.iter().enumerate() {
            if value <= bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // Always increment +Inf bucket.
        self.buckets[self.boundaries.len()].fetch_add(1, Ordering::Relaxed);
    }

    /// Render as Prometheus exposition format lines into `buf`.
    pub fn render(&self, buf: &mut String, name: &str, help: &str, unit: &str) {
        let _ = writeln!(buf, "# HELP {} {}", name, help);
        let _ = writeln!(buf, "# TYPE {} histogram", name);

        for (i, &bound) in self.boundaries.iter().enumerate() {
            let count = self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(buf, "{}_bucket{{le=\"{}{}\"}} {}", name, bound, unit, count);
        }
        let inf_count = self.buckets[self.boundaries.len()].load(Ordering::Relaxed);
        let _ = writeln!(buf, "{}_bucket{{le=\"+Inf\"}} {}", name, inf_count);

        let sum = self.sum.load(Ordering::Relaxed);
        let count = self.count.load(Ordering::Relaxed);
        let _ = writeln!(buf, "{}_sum {}", name, sum);
        let _ = writeln!(buf, "{}_count {}", name, count);
    }

    /// Total observations.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Sum of all observations.
    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    /// Snapshot bucket cumulative counts. Length = boundaries.len() + 1 (+Inf).
    pub fn bucket_counts(&self) -> Vec<u64> {
        self.buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect()
    }
}

// ── Claw SLO Metrics ────────────────────────────────────────────────────────

/// Linnix-Claw SLO metrics (§10.5).
///
/// Exposed at `/metrics/prometheus` alongside existing linnix_* gauges.
pub struct ClawMetrics {
    // Counters — mandate lifecycle
    pub mandates_created: AtomicU64,
    pub mandates_rejected: AtomicU64,
    pub mandates_revoked: AtomicU64,
    pub mandates_expired: AtomicU64,
    pub mandates_executed: AtomicU64,

    // Gauge — current active mandates
    pub mandates_active: AtomicU64,

    // Histograms
    pub mandate_latency: AtomicHistogram,
    pub receipt_sign_latency: AtomicHistogram,
    pub settlement_finality: AtomicHistogram,

    // Counter — reconciliation runs
    pub reconciliation_runs: AtomicU64,

    // Commerce policy rejections
    pub commerce_rejections: AtomicU64,
}

impl ClawMetrics {
    pub fn new() -> Self {
        Self {
            mandates_created: AtomicU64::new(0),
            mandates_rejected: AtomicU64::new(0),
            mandates_revoked: AtomicU64::new(0),
            mandates_expired: AtomicU64::new(0),
            mandates_executed: AtomicU64::new(0),
            mandates_active: AtomicU64::new(0),
            mandate_latency: AtomicHistogram::new(MANDATE_LATENCY_BUCKETS_NS),
            receipt_sign_latency: AtomicHistogram::new(RECEIPT_SIGN_LATENCY_BUCKETS_NS),
            settlement_finality: AtomicHistogram::new(SETTLEMENT_FINALITY_BUCKETS_S),
            reconciliation_runs: AtomicU64::new(0),
            commerce_rejections: AtomicU64::new(0),
        }
    }

    // ── Counter helpers ──────────────────────────────────────────────────

    pub fn inc_created(&self) {
        self.mandates_created.fetch_add(1, Ordering::Relaxed);
        self.mandates_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rejected(&self) {
        self.mandates_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_revoked(&self) {
        self.mandates_revoked.fetch_add(1, Ordering::Relaxed);
        self.mandates_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_expired(&self) {
        self.mandates_expired.fetch_add(1, Ordering::Relaxed);
        self.mandates_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_executed(&self) {
        self.mandates_executed.fetch_add(1, Ordering::Relaxed);
        self.mandates_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_reconciliation(&self) {
        self.reconciliation_runs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_commerce_rejection(&self) {
        self.commerce_rejections.fetch_add(1, Ordering::Relaxed);
    }

    // ── Histogram observation helpers ────────────────────────────────────

    /// Record mandate creation latency in nanoseconds.
    pub fn observe_mandate_latency_ns(&self, ns: u64) {
        self.mandate_latency.observe(ns);
    }

    /// Record receipt signing latency in nanoseconds.
    pub fn observe_receipt_sign_latency_ns(&self, ns: u64) {
        self.receipt_sign_latency.observe(ns);
    }

    /// Record settlement finality in seconds.
    pub fn observe_settlement_finality_s(&self, seconds: u64) {
        self.settlement_finality.observe(seconds);
    }

    // ── Prometheus rendering ─────────────────────────────────────────────

    /// Render all Claw SLO metrics in Prometheus exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut buf = String::with_capacity(4096);

        // Counters: linnix_mandates_total{result="..."}
        let _ = writeln!(
            buf,
            "# HELP linnix_mandates_total Total mandate operations by result."
        );
        let _ = writeln!(buf, "# TYPE linnix_mandates_total counter");
        let _ = writeln!(
            buf,
            "linnix_mandates_total{{result=\"created\"}} {}",
            self.mandates_created.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            buf,
            "linnix_mandates_total{{result=\"rejected\"}} {}",
            self.mandates_rejected.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            buf,
            "linnix_mandates_total{{result=\"revoked\"}} {}",
            self.mandates_revoked.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            buf,
            "linnix_mandates_total{{result=\"expired\"}} {}",
            self.mandates_expired.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            buf,
            "linnix_mandates_total{{result=\"executed\"}} {}",
            self.mandates_executed.load(Ordering::Relaxed)
        );

        // Gauge: linnix_mandates_active
        let _ = writeln!(
            buf,
            "# HELP linnix_mandates_active Currently active mandates."
        );
        let _ = writeln!(buf, "# TYPE linnix_mandates_active gauge");
        let _ = writeln!(
            buf,
            "linnix_mandates_active {}",
            self.mandates_active.load(Ordering::Relaxed)
        );

        // Histogram: linnix_mandate_latency_ns
        self.mandate_latency.render(
            &mut buf,
            "linnix_mandate_latency_ns",
            "Mandate creation latency in nanoseconds.",
            "",
        );

        // Histogram: linnix_receipt_sign_latency_ns
        self.receipt_sign_latency.render(
            &mut buf,
            "linnix_receipt_sign_latency_ns",
            "Receipt signing latency in nanoseconds.",
            "",
        );

        // Histogram: linnix_settlement_finality_seconds
        self.settlement_finality.render(
            &mut buf,
            "linnix_settlement_finality_seconds",
            "Time to settlement finality in seconds.",
            "",
        );

        // Counter: linnix_mandate_reconciliation_runs_total
        let _ = writeln!(
            buf,
            "# HELP linnix_mandate_reconciliation_runs_total Total mandate reconciliation sweeps."
        );
        let _ = writeln!(
            buf,
            "# TYPE linnix_mandate_reconciliation_runs_total counter"
        );
        let _ = writeln!(
            buf,
            "linnix_mandate_reconciliation_runs_total {}",
            self.reconciliation_runs.load(Ordering::Relaxed)
        );

        // Counter: linnix_commerce_rejections_total
        let _ = writeln!(
            buf,
            "# HELP linnix_commerce_rejections_total Commerce requests rejected by policy."
        );
        let _ = writeln!(buf, "# TYPE linnix_commerce_rejections_total counter");
        let _ = writeln!(
            buf,
            "linnix_commerce_rejections_total {}",
            self.commerce_rejections.load(Ordering::Relaxed)
        );

        buf
    }
}

impl Default for ClawMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_observe_and_cumulative_buckets() {
        let h = AtomicHistogram::new(&[10, 50, 100]);
        h.observe(5); // fits in bucket 10, 50, 100, +Inf
        h.observe(25); // fits in bucket 50, 100, +Inf
        h.observe(75); // fits in bucket 100, +Inf
        h.observe(200); // fits only in +Inf

        let counts = h.bucket_counts();
        assert_eq!(counts.len(), 4); // 3 boundaries + Inf
        assert_eq!(counts[0], 1); // le=10: only value 5
        assert_eq!(counts[1], 2); // le=50: values 5, 25
        assert_eq!(counts[2], 3); // le=100: values 5, 25, 75
        assert_eq!(counts[3], 4); // +Inf: all 4

        assert_eq!(h.count(), 4);
        assert_eq!(h.sum(), 5 + 25 + 75 + 200);
    }

    #[test]
    fn histogram_render_prometheus_format() {
        let h = AtomicHistogram::new(&[100, 500]);
        h.observe(50);
        h.observe(300);
        h.observe(1000);

        let mut buf = String::new();
        h.render(&mut buf, "test_metric", "A test histogram.", "");

        assert!(buf.contains("# HELP test_metric A test histogram."));
        assert!(buf.contains("# TYPE test_metric histogram"));
        assert!(buf.contains("test_metric_bucket{le=\"100\"} 1"));
        assert!(buf.contains("test_metric_bucket{le=\"500\"} 2"));
        assert!(buf.contains("test_metric_bucket{le=\"+Inf\"} 3"));
        assert!(buf.contains("test_metric_sum 1350"));
        assert!(buf.contains("test_metric_count 3"));
    }

    #[test]
    fn claw_metrics_mandate_counters() {
        let m = ClawMetrics::new();

        m.inc_created();
        m.inc_created();
        m.inc_created();
        assert_eq!(m.mandates_created.load(Ordering::Relaxed), 3);
        assert_eq!(m.mandates_active.load(Ordering::Relaxed), 3);

        m.inc_revoked();
        assert_eq!(m.mandates_revoked.load(Ordering::Relaxed), 1);
        assert_eq!(m.mandates_active.load(Ordering::Relaxed), 2);

        m.inc_executed();
        assert_eq!(m.mandates_executed.load(Ordering::Relaxed), 1);
        assert_eq!(m.mandates_active.load(Ordering::Relaxed), 1);

        m.inc_expired();
        assert_eq!(m.mandates_expired.load(Ordering::Relaxed), 1);
        assert_eq!(m.mandates_active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn claw_metrics_rejected_counter() {
        let m = ClawMetrics::new();
        m.inc_rejected();
        m.inc_rejected();
        assert_eq!(m.mandates_rejected.load(Ordering::Relaxed), 2);
        // Rejections don't affect active gauge
        assert_eq!(m.mandates_active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn claw_metrics_histograms() {
        let m = ClawMetrics::new();

        m.observe_mandate_latency_ns(500_000); // 0.5ms
        m.observe_mandate_latency_ns(2_000_000); // 2ms
        assert_eq!(m.mandate_latency.count(), 2);

        m.observe_receipt_sign_latency_ns(100_000); // 100µs
        assert_eq!(m.receipt_sign_latency.count(), 1);

        m.observe_settlement_finality_s(15);
        assert_eq!(m.settlement_finality.count(), 1);
    }

    #[test]
    fn claw_metrics_reconciliation_and_commerce() {
        let m = ClawMetrics::new();

        m.inc_reconciliation();
        m.inc_reconciliation();
        assert_eq!(m.reconciliation_runs.load(Ordering::Relaxed), 2);

        m.inc_commerce_rejection();
        assert_eq!(m.commerce_rejections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn full_prometheus_render_contains_all_families() {
        let m = ClawMetrics::new();
        m.inc_created();
        m.observe_mandate_latency_ns(1_000_000);
        m.observe_receipt_sign_latency_ns(50_000);
        m.observe_settlement_finality_s(10);
        m.inc_reconciliation();
        m.inc_commerce_rejection();

        let output = m.render_prometheus();

        // Verify all metric families are present
        assert!(output.contains("linnix_mandates_total{result=\"created\"} 1"));
        assert!(output.contains("linnix_mandates_active 1"));
        assert!(output.contains("linnix_mandate_latency_ns_bucket"));
        assert!(output.contains("linnix_mandate_latency_ns_count 1"));
        assert!(output.contains("linnix_receipt_sign_latency_ns_bucket"));
        assert!(output.contains("linnix_receipt_sign_latency_ns_count 1"));
        assert!(output.contains("linnix_settlement_finality_seconds_bucket"));
        assert!(output.contains("linnix_settlement_finality_seconds_count 1"));
        assert!(output.contains("linnix_mandate_reconciliation_runs_total 1"));
        assert!(output.contains("linnix_commerce_rejections_total 1"));
    }

    #[test]
    fn default_trait() {
        let m = ClawMetrics::default();
        assert_eq!(m.mandates_created.load(Ordering::Relaxed), 0);
        assert_eq!(m.mandate_latency.count(), 0);
    }
}
