use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub timestamp: u64,
    pub cpu_percent: f32,
    pub mem_percent: f32,
    pub load_avg: [f32; 3],
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    // PSI (Pressure Stall Information) - measures STALL TIME not just usage
    // Key insight: 100% CPU with 5% PSI = efficient. 40% CPU with 60% PSI = disaster.
    pub psi_cpu_some_avg10: f32, // % time tasks stalled waiting for CPU (10s avg)
    pub psi_memory_some_avg10: f32, // % time tasks stalled waiting for memory
    pub psi_memory_full_avg10: f32, // % time ALL tasks stalled (complete thrashing)
    pub psi_io_some_avg10: f32,  // % time tasks stalled on I/O
    pub psi_io_full_avg10: f32,  // % time ALL tasks stalled on I/O
}

#[derive(Debug, Serialize, Clone)]
pub struct ProcessAlert {
    pub pid: u32,
    pub comm: String,
    pub cpu_percent: Option<f32>,
    pub mem_percent: Option<f32>,
    pub event_type: u32,
    pub reason: String,
}
