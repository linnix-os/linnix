use linnix_ai_ebpf_common::PERCENT_MILLI_UNKNOWN;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    #[allow(dead_code)]
    pub uid: u32,
    #[allow(dead_code)]
    pub gid: u32,
    pub comm: String,
    pub event_type: u32,
    #[allow(dead_code)]
    pub ts_ns: u64,
    #[allow(dead_code)]
    pub seq: u64,
    pub exit_time_ns: u64,
    #[allow(dead_code)]
    pub cpu_pct_milli: u16,
    #[allow(dead_code)]
    pub mem_pct_milli: u16,
    #[serde(default)]
    #[allow(dead_code)]
    pub data: u64,
    #[serde(default)]
    #[allow(dead_code)]
    pub data2: u64,
    #[serde(default)]
    pub aux: u32,
    #[serde(default)]
    pub aux2: u32,
    pub tags: Vec<String>,
}

impl ProcessEvent {
    pub fn exit_time(&self) -> Option<u64> {
        if self.exit_time_ns == 0 {
            None
        } else {
            Some(self.exit_time_ns)
        }
    }

    #[allow(dead_code)]
    pub fn cpu_percent(&self) -> Option<f32> {
        if self.cpu_pct_milli == PERCENT_MILLI_UNKNOWN {
            None
        } else {
            Some(self.cpu_pct_milli as f32 / 1000.0)
        }
    }

    #[allow(dead_code)]
    pub fn mem_percent(&self) -> Option<f32> {
        if self.mem_pct_milli == PERCENT_MILLI_UNKNOWN {
            None
        } else {
            Some(self.mem_pct_milli as f32 / 1000.0)
        }
    }
}
