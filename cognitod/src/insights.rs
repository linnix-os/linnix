use crate::handler::local_ilm::schema::Insight;
use log::warn;
use serde::Serialize;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct InsightRecord {
    pub timestamp: u64,
    pub insight: Insight,
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
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .unwrap_or(0)
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    Ok(())
}

fn append_record(path: &Path, record: &InsightRecord) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(record)
        .map_err(std::io::Error::other)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::local_ilm::schema::{Insight, InsightClass};
    use tempfile::NamedTempFile;

    fn sample_insight(suffix: usize) -> Insight {
        Insight {
            class: InsightClass::Normal,
            confidence: 0.5,
            primary_process: None,
            why: format!("why-{suffix}"),
            actions: Vec::new(),
        }
    }

    #[test]
    fn retains_recent_records() {
        let store = InsightStore::new(2, None);
        store.record(sample_insight(0));
        store.record(sample_insight(1));
        store.record(sample_insight(2));

        let recent = store.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].insight.why, "why-2");
        assert_eq!(recent[1].insight.why, "why-1");
    }

    #[test]
    fn writes_records_to_disk() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();
        let store = InsightStore::new(4, Some(path.clone()));
        store.record(sample_insight(42));

        let content = std::fs::read_to_string(path).unwrap();
        assert!(
            content.contains("\"why\":\"why-42\""),
            "serialized insight should land in file"
        );
    }
}
