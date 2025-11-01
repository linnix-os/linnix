use crate::types::ProcessEvent;
use std::sync::Mutex;
use std::collections::VecDeque;
use std::time::Duration;

pub struct MemoryStore {
    inner: Mutex<VecDeque<(ProcessEvent, std::time::Instant)>>,
    max_age: Duration,
    max_len: usize,
}

impl MemoryStore {
    pub fn new(max_age: Duration, max_len: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            max_age,
            max_len,
        }
    }

    pub fn add(&self, event: ProcessEvent) {
        // push and prune logic
    }

    pub fn recent(&self) -> Vec<ProcessEvent> {
        // return filtered events
    }
}

// Add this where you handle LLM tag parse errors:
if let Err(e) = serde_json::from_str::<Vec<String>>(answer) {
    metrics.tag_failures_total.fetch_add(1, Ordering::Relaxed);
    return Err(anyhow::anyhow!("Failed to parse LLM tags JSON: {e}\nLLM output: {}", answer));
}