use crate::schema::Insight;
use log::warn;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Feedback {
    Useful,
    Noise,
}

#[derive(Debug, Clone, Serialize)]
pub struct InsightRecord {
    pub timestamp: u64,
    pub insight: Insight,
    pub feedback: Option<Feedback>,
}

pub struct InsightStore {
    inner: Mutex<VecDeque<InsightRecord>>,
    capacity: usize,
    file_path: Option<PathBuf>,
}

impl InsightStore {
    pub fn new(capacity: usize, file_path: Option<PathBuf>) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            file_path,
        }
    }

    pub fn record(&self, insight: Insight) {
        let record = InsightRecord {
            timestamp: current_epoch_secs(),
            insight: insight.clone(),
            feedback: None,
        };

        {
            let mut inner = self.inner.lock().unwrap();
            if inner.len() == self.capacity {
                inner.pop_front();
            }
            inner.push_back(record.clone());
        }

        if let Some(path) = &self.file_path {
            if let Err(err) = ensure_parent(path) {
                warn!("[insights] failed to create directory {:?}: {}", path, err);
                return;
            }
            if let Err(err) = append_record(path, &record) {
                warn!(
                    "[insights] failed to append insight to {}: {}",
                    path.display(),
                    err
                );
            }
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<InsightRecord> {
        if limit == 0 {
            return Vec::new();
        }
        let inner = self.inner.lock().unwrap();
        inner.iter().rev().take(limit).cloned().collect::<Vec<_>>()
    }

    pub fn get_by_id(&self, id: &str) -> Option<InsightRecord> {
        let inner = self.inner.lock().unwrap();
        inner.iter().find(|r| r.insight.id == id).cloned()
    }

    pub fn update_feedback(&self, id: &str, rating: Feedback) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if let Some(record) = inner.iter_mut().find(|r| r.insight.id == id) {
            let rating_label = match &rating {
                Feedback::Useful => "useful",
                Feedback::Noise => "noise",
            };
            
            record.feedback = Some(rating);
            
            // Persist feedback to disk
            if let Some(path) = &self.file_path {
                let path_str = path.to_string_lossy();
                let feedback_path = path_str.replace(".json", "_feedback.json");
                let feedback_entry = serde_json::json!({
                    "insight_id": id,
                    "timestamp": current_epoch_secs(),
                    "label": rating_label,
                    "source": "unknown", // Caller should provide this
                });
                
                // Append to feedback log
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&feedback_path)
                {
                    let _ = writeln!(file, "{}", feedback_entry);
                }
            }
            
            true
        } else {
            false
        }
    }
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .unwrap_or(0)
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn append_record(path: &Path, record: &InsightRecord) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(record).map_err(std::io::Error::other)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Insight, InsightReason};
    use tempfile::NamedTempFile;

    fn sample_insight(suffix: usize) -> Insight {
        Insight {
            reason_code: InsightReason::Normal,
            confidence: 0.5,
            id: format!("test-id-{}", suffix),
            primary_process: None,
            summary: format!("why-{}", suffix),
            k8s: None,
            top_pods: Vec::new(),
            suggested_next_step: "Do nothing".to_string(),
        }
    }

    #[test]
    fn insight_store_enforces_capacity_limit() {
        // Given: A store with capacity for only 2 insights
        let store = InsightStore::new(2, None);
        
        // When: Three insights are recorded
        store.record(sample_insight(0));
        store.record(sample_insight(1));
        store.record(sample_insight(2));

        // Then: Only the 2 most recent insights are retained (FIFO eviction)
        let recent = store.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].insight.summary, "why-2"); // Most recent first
        assert_eq!(recent[1].insight.summary, "why-1");
    }

    #[test]
    fn insights_are_persisted_for_audit_trail() {
        // Given: A store configured to write to disk
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();
        let store = InsightStore::new(4, Some(path.clone()));
        
        // When: An insight is recorded
        store.record(sample_insight(42));

        // Then: The serialized insight appears in the file
        let content = std::fs::read_to_string(path).unwrap();
        assert!(
            content.contains("\"summary\":\"why-42\""),
            "Audit trail should contain the insight explanation"
        );
    }
}
