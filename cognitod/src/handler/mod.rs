pub mod local_ilm;

pub use local_ilm::LocalIlmHandlerRag;

#[cfg(test)]
use crate::ProcessEventWire;
use crate::{ProcessEvent, types::SystemSnapshot};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[async_trait]
pub trait Handler: Send + Sync {
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
    async fn on_event(&self, event: &ProcessEvent);
    async fn on_snapshot(&self, snapshot: &SystemSnapshot);
}

pub struct HandlerList {
    handlers: Vec<Arc<dyn Handler>>,
}

impl Default for HandlerList {
    fn default() -> Self {
        Self::new()
    }
}

impl HandlerList {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    pub fn register<H: Handler + 'static>(&mut self, handler: H) {
        self.handlers.push(Arc::new(handler));
    }

    pub async fn on_event(&self, event: &ProcessEvent) {
        for h in &self.handlers {
            h.on_event(event).await;
        }
    }

    pub async fn on_snapshot(&self, snapshot: &SystemSnapshot) {
        for h in &self.handlers {
            h.on_snapshot(snapshot).await;
        }
    }
}

pub struct JsonlHandler {
    file: Arc<Mutex<tokio::fs::File>>,
}

impl JsonlHandler {
    pub async fn new(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }
}

#[async_trait]
impl Handler for JsonlHandler {
    fn name(&self) -> &'static str {
        "jsonl"
    }

    async fn on_event(&self, event: &ProcessEvent) {
        if let Ok(json) = serde_json::to_string(event) {
            let mut f = self.file.lock().await;
            let _ = f.write_all(json.as_bytes()).await;
            let _ = f.write_all(b"\n").await;
        }
    }

    async fn on_snapshot(&self, snapshot: &SystemSnapshot) {
        if let Ok(json) = serde_json::to_string(snapshot) {
            let mut f = self.file.lock().await;
            let _ = f.write_all(json.as_bytes()).await;
            let _ = f.write_all(b"\n").await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PERCENT_MILLI_UNKNOWN;

    #[tokio::test]
    async fn jsonl_writes_lines() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let handler = JsonlHandler::new(file.path().to_str().unwrap())
            .await
            .unwrap();
        let base = ProcessEventWire {
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            event_type: 0,
            ts_ns: 0,
            seq: 0,
            comm: [0; 16],
            exit_time_ns: 0,
            cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
            mem_pct_milli: PERCENT_MILLI_UNKNOWN,
            data: 0,
            data2: 0,
            aux: 0,
            aux2: 0,
        };
        let event = ProcessEvent::new(base);
        handler.on_event(&event).await;
        let snap = SystemSnapshot {
            timestamp: 0,
            cpu_percent: 0.0,
            mem_percent: 0.0,
            load_avg: [0.0; 3],
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
            psi_cpu_some_avg10: 0.0,
            psi_memory_some_avg10: 0.0,
            psi_memory_full_avg10: 0.0,
            psi_io_some_avg10: 0.0,
            psi_io_full_avg10: 0.0,
        };
        handler.on_snapshot(&snap).await;
        let content = tokio::fs::read_to_string(file.path()).await.unwrap();
        assert_eq!(content.lines().count(), 2);
    }
}
