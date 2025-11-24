//! PSI (Pressure Stall Information) parser
//!
//! PSI measures resource contention, not just usage.
//! Key insight: "100% CPU" doesn't mean your system is stressed.
//!              High PSI means tasks are STALLING waiting for resources.
//!
//! Format from /proc/pressure/{cpu,memory,io}:
//!   some avg10=5.23 avg60=3.45 avg300=2.11 total=123456
//!   full avg10=0.12 avg60=0.08 avg300=0.05 total=78901
//!
//! - "some" = at least one task stalled (maps to tail latency/P99)
//! - "full" = ALL runnable tasks stalled (maps to throughput loss)
//! - "avg10" = 10-second average (best for circuit breaker responsiveness)

use std::fs;
use std::io;
use std::path::Path;

use std::env;

fn get_psi_path(metric: &str) -> String {
    env::var(format!("LINNIX_PSI_{}_PATH", metric.to_uppercase()))
        .unwrap_or_else(|_| format!("/proc/pressure/{}", metric))
}

/// PSI metrics for the entire system
#[derive(Debug, Clone, Default)]
pub struct PsiMetrics {
    /// CPU pressure: % time at least one task stalled waiting for CPU (10s avg)
    pub cpu_some_avg10: f32,

    /// Memory pressure: % time at least one task stalled waiting for memory
    pub memory_some_avg10: f32,

    /// Memory thrashing: % time ALL tasks stalled (complete memory pressure)
    pub memory_full_avg10: f32,

    /// I/O pressure: % time at least one task stalled on I/O
    pub io_some_avg10: f32,

    /// I/O saturation: % time ALL tasks stalled on I/O
    pub io_full_avg10: f32,
}

impl PsiMetrics {
    /// Read PSI metrics from /proc/pressure/*
    ///
    /// Returns default (all zeros) if PSI not available (kernel < 4.20)
    pub fn read() -> io::Result<Self> {
        let mut metrics = PsiMetrics::default();

        // CPU pressure (only has "some", no "full")
        let cpu_path = get_psi_path("cpu");
        let cpu_path = get_psi_path("cpu");
        if let Ok(content) = fs::read_to_string(&cpu_path) {
            log::info!("Reading PSI from {}: {}", cpu_path, content.trim());
            if let Some(value) = parse_avg10(&content, "some") {
                metrics.cpu_some_avg10 = value;
            }
        } else {
            log::warn!("Failed to read PSI from {}", cpu_path);
        }

        // Memory pressure (has both "some" and "full")
        if let Ok(content) = fs::read_to_string(get_psi_path("memory")) {
            if let Some(value) = parse_avg10(&content, "some") {
                metrics.memory_some_avg10 = value;
            }
            if let Some(value) = parse_avg10(&content, "full") {
                metrics.memory_full_avg10 = value;
            }
        }

        // I/O pressure (has both "some" and "full")
        if let Ok(content) = fs::read_to_string(get_psi_path("io")) {
            if let Some(value) = parse_avg10(&content, "some") {
                metrics.io_some_avg10 = value;
            }
            if let Some(value) = parse_avg10(&content, "full") {
                metrics.io_full_avg10 = value;
            }
        }

        Ok(metrics)
    }

    /// Check if PSI is available on this kernel
    pub fn is_available() -> bool {
        Path::new(&get_psi_path("cpu")).exists()
    }

    /// Human-readable summary for logging
    pub fn summary(&self) -> String {
        format!(
            "cpu={:.1}% mem_some={:.1}% mem_full={:.1}% io_some={:.1}% io_full={:.1}%",
            self.cpu_some_avg10,
            self.memory_some_avg10,
            self.memory_full_avg10,
            self.io_some_avg10,
            self.io_full_avg10
        )
    }
}

/// Parse avg10 value from a PSI line
///
/// Input: "some avg10=5.23 avg60=3.45 avg300=2.11 total=123456"
/// Output: Some(5.23)
fn parse_avg10(content: &str, line_prefix: &str) -> Option<f32> {
    for line in content.lines() {
        if line.starts_with(line_prefix) {
            // Line format: "some avg10=5.23 avg60=..."
            for part in line.split_whitespace() {
                if part.starts_with("avg10=") {
                    let value_str = part.strip_prefix("avg10=")?;
                    return value_str.parse::<f32>().ok();
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_avg10_some() {
        let content = "some avg10=5.23 avg60=3.45 avg300=2.11 total=123456\n";
        assert_eq!(parse_avg10(content, "some"), Some(5.23));
    }

    #[test]
    fn test_parse_avg10_full() {
        let content = "full avg10=0.12 avg60=0.08 avg300=0.05 total=78901\n";
        assert_eq!(parse_avg10(content, "full"), Some(0.12));
    }

    #[test]
    fn test_parse_avg10_multiline() {
        let content = "some avg10=10.50 avg60=8.30 avg300=5.20 total=999999\n\
                       full avg10=2.34 avg60=1.56 avg300=0.78 total=111111\n";
        assert_eq!(parse_avg10(content, "some"), Some(10.50));
        assert_eq!(parse_avg10(content, "full"), Some(2.34));
    }

    #[test]
    fn test_parse_avg10_missing() {
        let content = "some avg60=3.45 avg300=2.11 total=123456\n";
        assert_eq!(parse_avg10(content, "some"), None);
    }

    #[test]
    fn test_parse_avg10_invalid_float() {
        let content = "some avg10=invalid avg60=3.45 avg300=2.11 total=123456\n";
        assert_eq!(parse_avg10(content, "some"), None);
    }

    #[test]
    fn test_psi_metrics_default() {
        let metrics = PsiMetrics::default();
        assert_eq!(metrics.cpu_some_avg10, 0.0);
        assert_eq!(metrics.memory_some_avg10, 0.0);
        assert_eq!(metrics.memory_full_avg10, 0.0);
        assert_eq!(metrics.io_some_avg10, 0.0);
        assert_eq!(metrics.io_full_avg10, 0.0);
    }

    #[test]
    fn test_psi_metrics_summary() {
        let metrics = PsiMetrics {
            cpu_some_avg10: 12.5,
            memory_some_avg10: 8.3,
            memory_full_avg10: 2.1,
            io_some_avg10: 15.7,
            io_full_avg10: 0.5,
        };
        let summary = metrics.summary();
        assert!(summary.contains("cpu=12.5%"));
        assert!(summary.contains("mem_full=2.1%"));
    }
}
