//! Incident storage and retrieval system
//!
//! This module provides persistent storage for circuit breaker incidents,
//! system events, and LLM analysis. Uses SQLite for simplicity and reliability.

mod analyzer;

pub use analyzer::{IncidentAnalysis, IncidentAnalyzer};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::path::Path;
use tracing::{debug, info};

/// Represents a circuit breaker incident or system event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub timestamp: i64,     // Unix epoch seconds
    pub event_type: String, // "circuit_breaker", "manual_kill", "warning", etc

    // Trigger conditions
    pub psi_cpu: f32,
    pub psi_memory: f32,
    pub cpu_percent: f32,
    pub load_avg: String, // "1.5,2.3,3.1"

    // Action taken
    pub action: String, // "kill", "alert", "throttle"
    pub target_pid: Option<i32>,
    pub target_name: Option<String>,

    // Context (stored as JSON)
    pub system_snapshot: Option<String>,

    // LLM analysis (added asynchronously)
    pub llm_analysis: Option<String>,
    pub llm_analyzed_at: Option<i64>,

    // Outcome
    pub recovery_time_ms: Option<i64>,
    pub psi_after: Option<f32>,
}

/// Incident storage backed by SQLite
pub struct IncidentStore {
    pool: SqlitePool,
}

impl IncidentStore {
    /// Create a new incident store
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, sqlx::Error> {
        let db_url = format!("sqlite://{}?mode=rwc", db_path.as_ref().display());

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await?;

        // Create schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                psi_cpu REAL NOT NULL,
                psi_memory REAL NOT NULL,
                cpu_percent REAL NOT NULL,
                load_avg TEXT NOT NULL,
                action TEXT NOT NULL,
                target_pid INTEGER,
                target_name TEXT,
                system_snapshot TEXT,
                llm_analysis TEXT,
                llm_analyzed_at INTEGER,
                recovery_time_ms INTEGER,
                psi_after REAL
            );
            CREATE INDEX IF NOT EXISTS idx_timestamp ON incidents(timestamp);
            CREATE INDEX IF NOT EXISTS idx_event_type ON incidents(event_type);
            CREATE INDEX IF NOT EXISTS idx_psi_cpu ON incidents(psi_cpu);
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                insight_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                label TEXT NOT NULL,
                source TEXT NOT NULL,
                user_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_feedback_insight_id ON feedback(insight_id);
            CREATE TABLE IF NOT EXISTS stall_attributions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_pod TEXT NOT NULL,
                victim_namespace TEXT NOT NULL,
                offender_pod TEXT NOT NULL,
                offender_namespace TEXT NOT NULL,
                stall_us INTEGER NOT NULL,
                blame_score REAL NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_victim_time ON stall_attributions(victim_pod, victim_namespace, timestamp);
            CREATE INDEX IF NOT EXISTS idx_offender_time ON stall_attributions(offender_pod, offender_namespace, timestamp);
            CREATE INDEX IF NOT EXISTS idx_timestamp_attr ON stall_attributions(timestamp);
            "#,
        )
        .execute(&pool)
        .await?;

        info!(
            "Incident store initialized at {}",
            db_path.as_ref().display()
        );
        Ok(Self { pool })
    }

    /// Insert a new incident
    pub async fn insert(&self, incident: &Incident) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO incidents (
                timestamp, event_type, psi_cpu, psi_memory, cpu_percent, load_avg,
                action, target_pid, target_name, system_snapshot,
                recovery_time_ms, psi_after
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(incident.timestamp)
        .bind(&incident.event_type)
        .bind(incident.psi_cpu)
        .bind(incident.psi_memory)
        .bind(incident.cpu_percent)
        .bind(&incident.load_avg)
        .bind(&incident.action)
        .bind(incident.target_pid)
        .bind(&incident.target_name)
        .bind(&incident.system_snapshot)
        .bind(incident.recovery_time_ms)
        .bind(incident.psi_after)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        debug!("Inserted incident #{} (type: {})", id, incident.event_type);
        Ok(id)
    }

    /// Add LLM analysis to an existing incident
    pub async fn add_llm_analysis(&self, id: i64, analysis: String) -> Result<(), sqlx::Error> {
        let now = Utc::now().timestamp();

        sqlx::query("UPDATE incidents SET llm_analysis = ?, llm_analyzed_at = ? WHERE id = ?")
            .bind(analysis)
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        debug!("Added LLM analysis to incident #{}", id);
        Ok(())
    }

    /// Insert user feedback for an insight
    pub async fn insert_feedback(
        &self,
        insight_id: &str,
        label: &str,
        source: &str,
        user_id: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            r#"
            INSERT INTO feedback (insight_id, timestamp, label, source, user_id)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(insight_id)
        .bind(now)
        .bind(label)
        .bind(source)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        debug!("Inserted feedback #{} for insight {}", id, insight_id);
        Ok(id)
    }

    /// Insert stall attribution event
    pub async fn insert_stall_attribution(
        &self,
        victim_pod: &str,
        victim_namespace: &str,
        offender_pod: &str,
        offender_namespace: &str,
        stall_us: u64,
        blame_score: f64,
        timestamp: u64,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO stall_attributions (
                victim_pod, victim_namespace, offender_pod, offender_namespace,
                stall_us, blame_score, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(victim_pod)
        .bind(victim_namespace)
        .bind(offender_pod)
        .bind(offender_namespace)
        .bind(stall_us as i64)
        .bind(blame_score)
        .bind(timestamp as i64)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        debug!(
            "Inserted stall attribution #{}: {}/{} blamed {}/{}",
            id, victim_namespace, victim_pod, offender_namespace, offender_pod
        );
        Ok(id)
    }

    /// Get incident by ID
    pub async fn get(&self, id: i64) -> Result<Option<Incident>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, timestamp, event_type, psi_cpu, psi_memory, cpu_percent, load_avg,
                   action, target_pid, target_name, system_snapshot,
                   llm_analysis, llm_analyzed_at, recovery_time_ms, psi_after
            FROM incidents WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Incident {
            id: Some(r.get(0)),
            timestamp: r.get(1),
            event_type: r.get(2),
            psi_cpu: r.get(3),
            psi_memory: r.get(4),
            cpu_percent: r.get(5),
            load_avg: r.get(6),
            action: r.get(7),
            target_pid: r.get(8),
            target_name: r.get(9),
            system_snapshot: r.get(10),
            llm_analysis: r.get(11),
            llm_analyzed_at: r.get(12),
            recovery_time_ms: r.get(13),
            psi_after: r.get(14),
        }))
    }

    /// Get recent incidents
    pub async fn recent(&self, limit: i64) -> Result<Vec<Incident>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, timestamp, event_type, psi_cpu, psi_memory, cpu_percent, load_avg,
                   action, target_pid, target_name, system_snapshot,
                   llm_analysis, llm_analyzed_at, recovery_time_ms, psi_after
            FROM incidents
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Incident {
                id: Some(r.get(0)),
                timestamp: r.get(1),
                event_type: r.get(2),
                psi_cpu: r.get(3),
                psi_memory: r.get(4),
                cpu_percent: r.get(5),
                load_avg: r.get(6),
                action: r.get(7),
                target_pid: r.get(8),
                target_name: r.get(9),
                system_snapshot: r.get(10),
                llm_analysis: r.get(11),
                llm_analyzed_at: r.get(12),
                recovery_time_ms: r.get(13),
                psi_after: r.get(14),
            })
            .collect())
    }

    /// Get incidents within a time range
    pub async fn since(
        &self,
        start_timestamp: i64,
        event_type: Option<&str>,
    ) -> Result<Vec<Incident>, sqlx::Error> {
        let rows = if let Some(evt_type) = event_type {
            sqlx::query(
                r#"
                SELECT id, timestamp, event_type, psi_cpu, psi_memory, cpu_percent, load_avg,
                       action, target_pid, target_name, system_snapshot,
                       llm_analysis, llm_analyzed_at, recovery_time_ms, psi_after
                FROM incidents
                WHERE timestamp >= ? AND event_type = ?
                ORDER BY timestamp DESC
                "#,
            )
            .bind(start_timestamp)
            .bind(evt_type)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id, timestamp, event_type, psi_cpu, psi_memory, cpu_percent, load_avg,
                       action, target_pid, target_name, system_snapshot,
                       llm_analysis, llm_analyzed_at, recovery_time_ms, psi_after
                FROM incidents
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                "#,
            )
            .bind(start_timestamp)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| Incident {
                id: Some(r.get(0)),
                timestamp: r.get(1),
                event_type: r.get(2),
                psi_cpu: r.get(3),
                psi_memory: r.get(4),
                cpu_percent: r.get(5),
                load_avg: r.get(6),
                action: r.get(7),
                target_pid: r.get(8),
                target_name: r.get(9),
                system_snapshot: r.get(10),
                llm_analysis: r.get(11),
                llm_analyzed_at: r.get(12),
                recovery_time_ms: r.get(13),
                psi_after: r.get(14),
            })
            .collect())
    }

    /// Get statistics about incidents
    pub async fn stats(&self) -> Result<IncidentStats, sqlx::Error> {
        let total_row = sqlx::query("SELECT COUNT(*) FROM incidents")
            .fetch_one(&self.pool)
            .await?;
        let total: i64 = total_row.get(0);

        let cb_row =
            sqlx::query("SELECT COUNT(*) FROM incidents WHERE event_type = 'circuit_breaker'")
                .fetch_one(&self.pool)
                .await?;
        let circuit_breaker_count: i64 = cb_row.get(0);

        let avg_row = sqlx::query(
            "SELECT AVG(recovery_time_ms) FROM incidents WHERE recovery_time_ms IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        let avg_recovery: Option<f64> = avg_row.get(0);

        let feedback_row = sqlx::query("SELECT COUNT(*) FROM feedback")
            .fetch_one(&self.pool)
            .await?;
        let feedback_count: i64 = feedback_row.get(0);

        Ok(IncidentStats {
            total: total as u64,
            circuit_breaker_triggers: circuit_breaker_count as u64,
            avg_recovery_time_ms: avg_recovery.map(|r| r as u64),
            feedback_entries: feedback_count as u64,
        })
    }
}

/// Statistics about stored incidents
#[derive(Debug, Serialize)]
pub struct IncidentStats {
    pub total: u64,
    pub circuit_breaker_triggers: u64,
    pub avg_recovery_time_ms: Option<u64>,
    pub feedback_entries: u64,
}
