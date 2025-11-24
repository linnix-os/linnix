use std::sync::RwLock;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::SystemTime;

const EVENT_TYPE_SLOTS: usize = 8;

/// Global metrics for the cognition daemon.
///
/// Counters are updated from the hot path so all fields are atomic.
pub struct Metrics {
    pub events_total: AtomicU64,
    pub alerts_active: AtomicUsize,
    #[allow(dead_code)]
    pub tag_failures_total: AtomicU64,
    pub dropped_events_total: AtomicU64,
    pub subscribers: AtomicUsize,
    pub start_time: SystemTime,
    // Per-second tracking
    events_this_sec: AtomicU64,
    events_per_sec: AtomicU64,
    rb_overflows: AtomicU64,
    rate_limited_events: AtomicU64,
    lineage_hits: AtomicU64,
    lineage_misses: AtomicU64,
    drops_by_type: [AtomicU64; EVENT_TYPE_SLOTS],
    alerts_emitted_total: AtomicU64,
    perf_poll_errors: AtomicU64,
    active_rules: AtomicUsize,
    rss_probe_mode: AtomicU8,
    kernel_btf_available: AtomicBool,
    ilm_windows: AtomicU64,
    ilm_timeouts: AtomicU64,
    ilm_insights: AtomicU64,
    ilm_schema_errors: AtomicU64,
    ilm_enabled: AtomicBool,
    ilm_disabled_reason: RwLock<String>,
    // PSI (Pressure Stall Information) gauges - stored as f32 * 100 to use AtomicU32
    psi_cpu_some_avg10: AtomicU32, // CPU pressure (0-10000 = 0.00%-100.00%)
    psi_memory_some_avg10: AtomicU32, // Memory pressure
    psi_memory_full_avg10: AtomicU32, // Memory thrashing (all tasks stalled)
    psi_io_some_avg10: AtomicU32,  // I/O pressure
    psi_io_full_avg10: AtomicU32,  // I/O saturation
    // Circuit breaker counters
    circuit_breaker_cpu_trips: AtomicU64, // Times CPU+PSI threshold exceeded
    circuit_breaker_memory_trips: AtomicU64, // Times memory PSI threshold exceeded
    circuit_breaker_io_trips: AtomicU64,  // Times I/O PSI threshold exceeded
    circuit_breaker_auto_kills: AtomicU64, // Automatic kills executed
    circuit_breaker_safety_vetoes: AtomicU64, // Kills blocked by safety checks
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            events_total: AtomicU64::new(0),
            alerts_active: AtomicUsize::new(0),
            tag_failures_total: AtomicU64::new(0),
            dropped_events_total: AtomicU64::new(0),
            subscribers: AtomicUsize::new(0),
            start_time: SystemTime::now(),
            events_this_sec: AtomicU64::new(0),
            events_per_sec: AtomicU64::new(0),
            rb_overflows: AtomicU64::new(0),
            rate_limited_events: AtomicU64::new(0),
            lineage_hits: AtomicU64::new(0),
            lineage_misses: AtomicU64::new(0),
            drops_by_type: std::array::from_fn(|_| AtomicU64::new(0)),
            alerts_emitted_total: AtomicU64::new(0),
            perf_poll_errors: AtomicU64::new(0),
            active_rules: AtomicUsize::new(0),
            rss_probe_mode: AtomicU8::new(0),
            kernel_btf_available: AtomicBool::new(false),
            ilm_windows: AtomicU64::new(0),
            ilm_timeouts: AtomicU64::new(0),
            ilm_insights: AtomicU64::new(0),
            ilm_schema_errors: AtomicU64::new(0),
            ilm_enabled: AtomicBool::new(false),
            ilm_disabled_reason: RwLock::new(String::new()),
            psi_cpu_some_avg10: AtomicU32::new(0),
            psi_memory_some_avg10: AtomicU32::new(0),
            psi_memory_full_avg10: AtomicU32::new(0),
            psi_io_some_avg10: AtomicU32::new(0),
            psi_io_full_avg10: AtomicU32::new(0),
            circuit_breaker_cpu_trips: AtomicU64::new(0),
            circuit_breaker_memory_trips: AtomicU64::new(0),
            circuit_breaker_io_trips: AtomicU64::new(0),
            circuit_breaker_auto_kills: AtomicU64::new(0),
            circuit_breaker_safety_vetoes: AtomicU64::new(0),
        }
    }

    /// Record an incoming event. Returns true if the event should be
    /// processed, false if it should be sampled out according to the
    /// provided cap.
    #[allow(clippy::manual_is_multiple_of)] // is_multiple_of not stable in nightly-2024-12-10
    pub fn record_event(&self, cap: u64, event_type: u32) -> bool {
        const SAMPLE_N: u64 = 10; // keep 1 in N events for critical events
        let count = self.events_this_sec.fetch_add(1, Ordering::Relaxed) + 1;
        self.events_total.fetch_add(1, Ordering::Relaxed);
        if cap > 0 && count > cap {
            if event_type > 2 {
                self.record_drop(event_type);
                return false;
            }
            if count % SAMPLE_N != 0 {
                self.record_drop(event_type);
                return false;
            }
        }
        true
    }

    /// Called periodically to refresh the events-per-second metric.
    pub fn rollup(&self) {
        let per_sec = self.events_this_sec.swap(0, Ordering::Relaxed);
        self.events_per_sec.store(per_sec, Ordering::Relaxed);
    }

    pub fn events_per_sec(&self) -> u64 {
        self.events_per_sec.load(Ordering::Relaxed)
    }

    pub fn rb_overflows(&self) -> u64 {
        self.rb_overflows.load(Ordering::Relaxed)
    }

    pub fn inc_rb_overflow(&self) {
        self.rb_overflows.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limited_events(&self) -> u64 {
        self.rate_limited_events.load(Ordering::Relaxed)
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0)
    }

    pub fn inc_lineage_hit(&self) {
        self.lineage_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_lineage_miss(&self) {
        self.lineage_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn lineage_hits(&self) -> u64 {
        self.lineage_hits.load(Ordering::Relaxed)
    }

    pub fn lineage_misses(&self) -> u64 {
        self.lineage_misses.load(Ordering::Relaxed)
    }

    pub fn drops_by_type(&self) -> Vec<(u32, u64)> {
        (0..self.drops_by_type.len())
            .map(|idx| (idx as u32, self.drops_by_type[idx].load(Ordering::Relaxed)))
            .collect()
    }

    pub fn inc_alerts_emitted(&self) {
        self.alerts_emitted_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn alerts_emitted(&self) -> u64 {
        self.alerts_emitted_total.load(Ordering::Relaxed)
    }

    pub fn inc_perf_poll_error(&self) {
        self.perf_poll_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn perf_poll_errors(&self) -> u64 {
        self.perf_poll_errors.load(Ordering::Relaxed)
    }

    pub fn add_active_rules(&self, count: usize) {
        self.active_rules.fetch_add(count, Ordering::Relaxed);
    }

    pub fn active_rules(&self) -> usize {
        self.active_rules.load(Ordering::Relaxed)
    }

    pub fn set_rss_probe_mode(&self, mode: u8) {
        self.rss_probe_mode.store(mode, Ordering::Relaxed);
    }

    pub fn rss_probe_mode(&self) -> u8 {
        self.rss_probe_mode.load(Ordering::Relaxed)
    }

    pub fn set_kernel_btf_available(&self, available: bool) {
        self.kernel_btf_available
            .store(available, Ordering::Relaxed);
    }

    pub fn kernel_btf_available(&self) -> bool {
        self.kernel_btf_available.load(Ordering::Relaxed)
    }

    fn record_drop(&self, event_type: u32) {
        let idx = Self::event_index(event_type);
        self.drops_by_type[idx].fetch_add(1, Ordering::Relaxed);
        self.dropped_events_total.fetch_add(1, Ordering::Relaxed);
        self.rate_limited_events.fetch_add(1, Ordering::Relaxed);
    }

    fn event_index(event_type: u32) -> usize {
        let max = self::EVENT_TYPE_SLOTS as u32 - 1;
        std::cmp::min(event_type, max) as usize
    }

    pub fn inc_ilm_windows(&self) {
        self.ilm_windows.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ilm_windows(&self) -> u64 {
        self.ilm_windows.load(Ordering::Relaxed)
    }

    pub fn inc_ilm_timeouts(&self) {
        self.ilm_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ilm_timeouts(&self) -> u64 {
        self.ilm_timeouts.load(Ordering::Relaxed)
    }

    pub fn inc_ilm_insights(&self) {
        self.ilm_insights.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ilm_insights(&self) -> u64 {
        self.ilm_insights.load(Ordering::Relaxed)
    }

    pub fn inc_ilm_schema_errors(&self) {
        self.ilm_schema_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ilm_schema_errors(&self) -> u64 {
        self.ilm_schema_errors.load(Ordering::Relaxed)
    }

    pub fn set_ilm_enabled(&self, enabled: bool) {
        self.ilm_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn ilm_enabled(&self) -> bool {
        self.ilm_enabled.load(Ordering::Relaxed)
    }

    pub fn set_ilm_disabled_reason(&self, reason: Option<String>) {
        let value = reason.unwrap_or_default();
        if let Ok(mut slot) = self.ilm_disabled_reason.write() {
            *slot = value;
        }
    }

    pub fn ilm_disabled_reason(&self) -> Option<String> {
        self.ilm_disabled_reason
            .read()
            .ok()
            .and_then(|v| if v.is_empty() { None } else { Some(v.clone()) })
    }

    // PSI gauge setters/getters (stored as f32 * 100)
    pub fn set_psi_cpu(&self, value: f32) {
        self.psi_cpu_some_avg10
            .store((value * 100.0) as u32, Ordering::Relaxed);
    }

    pub fn psi_cpu(&self) -> f32 {
        self.psi_cpu_some_avg10.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn set_psi_memory_some(&self, value: f32) {
        self.psi_memory_some_avg10
            .store((value * 100.0) as u32, Ordering::Relaxed);
    }

    pub fn psi_memory_some(&self) -> f32 {
        self.psi_memory_some_avg10.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn set_psi_memory_full(&self, value: f32) {
        self.psi_memory_full_avg10
            .store((value * 100.0) as u32, Ordering::Relaxed);
    }

    pub fn psi_memory_full(&self) -> f32 {
        self.psi_memory_full_avg10.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn set_psi_io_some(&self, value: f32) {
        self.psi_io_some_avg10
            .store((value * 100.0) as u32, Ordering::Relaxed);
    }

    pub fn psi_io_some(&self) -> f32 {
        self.psi_io_some_avg10.load(Ordering::Relaxed) as f32 / 100.0
    }

    pub fn set_psi_io_full(&self, value: f32) {
        self.psi_io_full_avg10
            .store((value * 100.0) as u32, Ordering::Relaxed);
    }

    pub fn psi_io_full(&self) -> f32 {
        self.psi_io_full_avg10.load(Ordering::Relaxed) as f32 / 100.0
    }

    // Circuit breaker counters
    pub fn inc_circuit_breaker_cpu_trip(&self) {
        self.circuit_breaker_cpu_trips
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn circuit_breaker_cpu_trips(&self) -> u64 {
        self.circuit_breaker_cpu_trips.load(Ordering::Relaxed)
    }

    pub fn inc_circuit_breaker_memory_trip(&self) {
        self.circuit_breaker_memory_trips
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn circuit_breaker_memory_trips(&self) -> u64 {
        self.circuit_breaker_memory_trips.load(Ordering::Relaxed)
    }

    pub fn inc_circuit_breaker_io_trip(&self) {
        self.circuit_breaker_io_trips
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn circuit_breaker_io_trips(&self) -> u64 {
        self.circuit_breaker_io_trips.load(Ordering::Relaxed)
    }

    pub fn inc_circuit_breaker_auto_kill(&self) {
        self.circuit_breaker_auto_kills
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn circuit_breaker_auto_kills(&self) -> u64 {
        self.circuit_breaker_auto_kills.load(Ordering::Relaxed)
    }

    pub fn inc_circuit_breaker_safety_veto(&self) {
        self.circuit_breaker_safety_vetoes
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn circuit_breaker_safety_vetoes(&self) -> u64 {
        self.circuit_breaker_safety_vetoes.load(Ordering::Relaxed)
    }
}
impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_events_trigger_sampling() {
        let m = Metrics::new();
        let cap = 5;
        let mut processed = 0;
        for _ in 0..100 {
            if m.record_event(cap, 3) {
                processed += 1;
            }
        }
        assert!(m.rate_limited_events() > 0);
        assert!(processed < 100);
        let drop_summary = m.drops_by_type();
        let low_value_drops = drop_summary
            .iter()
            .find(|(event_type, _)| *event_type == 3)
            .map(|(_, drops)| *drops)
            .unwrap_or(0);
        assert!(low_value_drops > 0);
    }
}
