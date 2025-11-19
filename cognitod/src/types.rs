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
