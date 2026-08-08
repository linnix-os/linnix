// let_chains stabilized in Rust 1.82 (Jan 2025)
// Both local stable and Docker stable support it without feature flags

pub mod agent_card;
pub mod alerts;
pub mod bpf_config;
pub mod claw_metrics;
pub mod collectors;
pub mod commerce;
pub mod compliance;
pub mod config;
pub mod context;
pub mod enforcement;
pub mod handler;
pub mod identity;
pub mod incidents;
pub mod insights;
pub mod k8s;
pub mod mandate;
pub mod metrics;
pub mod notifications;
pub mod onchain;
pub mod payment;
pub mod privacy;
pub mod receipt;
pub mod runtime;
pub mod schema;
pub mod spend;
pub mod types;
pub mod ui;
pub mod utils;

pub use config::{Config, LoggingConfig, OfflineGuard, OutputConfig, RuntimeConfig};
pub use incidents::{Incident, IncidentAnalyzer, IncidentStats, IncidentStore};
pub use metrics::Metrics;

pub use linnix_ai_ebpf_common::PERCENT_MILLI_UNKNOWN;
pub use linnix_ai_ebpf_common::ProcessEvent as ProcessEventWire;
pub use linnix_ai_ebpf_common::ProcessEventExt as ProcessEvent;
