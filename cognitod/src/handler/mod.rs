#[cfg(test)]
use crate::ProcessEventWire;
use crate::{ProcessEvent, types::SystemSnapshot};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use linnix_ai_ebpf_common::EventType;

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

// =============================================================================
// MANDATE RECEIPT HANDLER
// =============================================================================
//
// Listens for MandateAllow events from the kernel LSM hook, builds a signed
// execution receipt, and attaches it to the mandate via mark_executed().
//
// Event fields (from lsm.rs push_mandate_receipt):
//   event_type = MandateAllow (8)
//   pid        = process TID that triggered the check
//   data       = cmd_hash of the checked operation
//   data2      = mandate_seq (0 if no mandate matched)
//   aux        = enforcement mode (0=monitor, 1=enforce)

pub struct MandateReceiptHandler {
    mandate: Arc<crate::mandate::MandateManager>,
    identity: Arc<crate::identity::AgentIdentity>,
}

impl MandateReceiptHandler {
    pub fn new(
        mandate: Arc<crate::mandate::MandateManager>,
        identity: Arc<crate::identity::AgentIdentity>,
    ) -> Self {
        Self { mandate, identity }
    }
}

#[async_trait]
impl Handler for MandateReceiptHandler {
    fn name(&self) -> &'static str {
        "mandate-receipt"
    }

    async fn on_event(&self, event: &ProcessEvent) {
        // Only process MandateAllow events (event_type = 8)
        if event.event_type != EventType::MandateAllow as u32 {
            return;
        }

        let mandate_seq = event.data2;
        if mandate_seq == 0 {
            return; // No mandate matched (shouldn't happen for MandateAllow)
        }

        // Resolve mandate_seq → mandate_id via reverse index
        let mandate_id = match self.mandate.find_id_by_seq(mandate_seq).await {
            Some(id) => id,
            None => {
                log::debug!(
                    "[mandate-receipt] no mandate found for seq={} (may have expired)",
                    mandate_seq
                );
                return;
            }
        };

        // Get execution data for receipt building
        let (args, seq) = match self.mandate.get_execution_data(&mandate_id).await {
            Some(data) => data,
            None => {
                log::debug!(
                    "[mandate-receipt] mandate {} no longer active for receipt",
                    mandate_id
                );
                return;
            }
        };

        let cmd_hash = event.data;
        let enforcement_mode = if event.aux == 1 { "enforce" } else { "monitor" };

        // Build execution details for the receipt
        let execution = crate::receipt::ExecutionDetails {
            pid: event.pid,
            ppid: None,
            binary: args.first().cloned().unwrap_or_default(),
            args_hash: format!("{:#018x}", cmd_hash),
            exit_code: 0, // MandateAllow = authorized, not yet exited
            started_at_ns: Some(event.ts_ns),
            finished_at_ns: None,
            duration_ms: 0,
            cpu_pct: None,
            mem_pct: None,
        };

        // Build and sign the receipt
        let receipt = crate::receipt::ReceiptBuilder::new(mandate_id.clone(), execution)
            .kernel_seq(seq)
            .enforcement_mode(enforcement_mode)
            .sign(&self.identity);

        match receipt {
            Ok(signed_receipt) => {
                if let Err(e) = self
                    .mandate
                    .mark_executed(&mandate_id, signed_receipt)
                    .await
                {
                    log::warn!(
                        "[mandate-receipt] failed to mark mandate {} as executed: {}",
                        mandate_id,
                        e
                    );
                }
            }
            Err(e) => {
                log::warn!(
                    "[mandate-receipt] failed to sign receipt for mandate {}: {}",
                    mandate_id,
                    e
                );
            }
        }
    }

    async fn on_snapshot(&self, _snapshot: &SystemSnapshot) {
        // No-op: MandateReceiptHandler only processes events.
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
