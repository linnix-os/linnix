//! Incident storage and retrieval system
//!
//! This module provides persistent storage for circuit breaker incidents,
//! system events, and LLM analysis. Uses SQLite for simplicity and reliability.

mod analyzer;
pub mod investigation;
pub mod outcome;

pub use analyzer::{AnalysisOutcome, IncidentAnalyzer};
pub use investigation::{Fact, IncidentInvestigation};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::path::Path;
use tracing::{debug, info, warn};

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
    /// The model's reply verbatim, kept even when it failed to ground so a
    /// broken endpoint can be told apart from a model that answers badly.
    pub llm_analysis: Option<String>,
    pub llm_analyzed_at: Option<i64>,

    /// The grounded [`IncidentInvestigation`] as JSON. `None` when no analysis
    /// ran, and also when one ran and nothing it claimed could be checked
    /// against the facts the daemon supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub investigation: Option<String>,

    // Outcome
    pub recovery_time_ms: Option<i64>,
    pub psi_after: Option<f32>,
}

/// Represents a stall attribution event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallAttribution {
    pub offender_pod: String,
    pub offender_namespace: String,
    /// The victim's total stall for the window. The same value repeats across
    /// every offender of one event, so summing it double-counts.
    pub stall_us: u64,
    /// This offender's share of `stall_us`, matching what
    /// `linnix_stall_induced_seconds_total` reports. `None` on rows written
    /// before the split existed and whose blame could not be renormalised.
    pub attributed_stall_us: Option<u64>,
    pub blame_score: f64,
    pub timestamp: u64,
    // Detailed metrics
    pub cpu_share: f64,
    pub fork_count: u64,
    pub short_job_count: u64,
    /// The stall event this row belongs to. `None` on rows written before the
    /// PSI monitor emitted one — those are grouped by `(timestamp, stall_us)`
    /// as before, with the ambiguity that implies.
    pub event_id: Option<String>,
}

/// Incident storage backed by SQLite
pub struct IncidentStore {
    pool: SqlitePool,
}

struct RequiredColumn {
    table: &'static str,
    column: &'static str,
    ddl: &'static str,
}

const REQUIRED_COLUMNS: &[RequiredColumn] = &[
    RequiredColumn {
        table: "stall_attributions",
        column: "cpu_share",
        ddl: "ALTER TABLE stall_attributions ADD COLUMN cpu_share REAL DEFAULT 0.0",
    },
    RequiredColumn {
        table: "stall_attributions",
        column: "fork_count",
        ddl: "ALTER TABLE stall_attributions ADD COLUMN fork_count INTEGER DEFAULT 0",
    },
    RequiredColumn {
        table: "stall_attributions",
        column: "short_job_count",
        ddl: "ALTER TABLE stall_attributions ADD COLUMN short_job_count INTEGER DEFAULT 0",
    },
    RequiredColumn {
        table: "stall_attributions",
        column: "attributed_stall_us",
        ddl: "ALTER TABLE stall_attributions ADD COLUMN attributed_stall_us INTEGER",
    },
    RequiredColumn {
        table: "stall_attributions",
        column: "event_id",
        ddl: "ALTER TABLE stall_attributions ADD COLUMN event_id TEXT",
    },
    RequiredColumn {
        table: "incidents",
        column: "investigation",
        ddl: "ALTER TABLE incidents ADD COLUMN investigation TEXT",
    },
];

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
                psi_after REAL,
                investigation TEXT
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
                timestamp INTEGER NOT NULL,
                cpu_share REAL DEFAULT 0.0,
                fork_count INTEGER DEFAULT 0,
                short_job_count INTEGER DEFAULT 0,
                -- This offender's share of stall_us. Nullable rather than
                -- defaulted: a row written before this column existed has an
                -- unknown share, and zero would claim the offender caused no
                -- stall at all.
                attributed_stall_us INTEGER,
                -- The stall event this row belongs to. Nullable for the same
                -- reason: rows written before the PSI monitor emitted an id
                -- genuinely have none, and any default would group unrelated
                -- events together — inventing exactly the collapse the id was
                -- added to prevent.
                event_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_victim_time ON stall_attributions(victim_pod, victim_namespace, timestamp);
            CREATE INDEX IF NOT EXISTS idx_offender_time ON stall_attributions(offender_pod, offender_namespace, timestamp);
            CREATE INDEX IF NOT EXISTS idx_timestamp_attr ON stall_attributions(timestamp);
            "#,
        )
        .execute(&pool)
        .await?;

        apply_required_column_migrations(&pool).await?;

        // No backfill: an id cannot be reconstructed for rows written before
        // the monitor emitted one, and grouping them by `(timestamp, stall_us)`
        // to synthesise one would bake today's ambiguity into permanent data.
        // They stay NULL and consumers keep the existing fallback.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_attr_event ON stall_attributions(event_id)")
            .execute(&pool)
            .await?;

        // Rows written before the column existed stored only the victim's
        // total stall, repeated against every offender. The share each was
        // actually responsible for is recoverable: attributions from one event
        // share a (victim, timestamp, stall_us), so blame can be renormalised
        // within that group. Nothing prunes this table, so old rows stay
        // queryable and are worth reconciling rather than leaving unknown.
        //
        // stall_us belongs in the grouping key, not just the numerator. The
        // timestamp has one-second resolution and a single victim can produce
        // two events within one second — a pod's containers are scanned
        // separately, and they collapse to the same pod key. Grouping on victim
        // and timestamp alone would pool both events' blame into one
        // denominator while each numerator kept its own stall, leaving shares
        // that reconcile to neither event. stall_us is a microsecond delta, so
        // it separates them.
        let backfilled = sqlx::query(
            r#"
            UPDATE stall_attributions AS a
            SET attributed_stall_us = CAST(
                a.stall_us * a.blame_score / (
                    SELECT SUM(b.blame_score) FROM stall_attributions AS b
                    WHERE b.victim_pod = a.victim_pod
                      AND b.victim_namespace = a.victim_namespace
                      AND b.timestamp = a.timestamp
                      AND b.stall_us = a.stall_us
                ) AS INTEGER)
            WHERE a.attributed_stall_us IS NULL
              AND (
                    SELECT SUM(b.blame_score) FROM stall_attributions AS b
                    WHERE b.victim_pod = a.victim_pod
                      AND b.victim_namespace = a.victim_namespace
                      AND b.timestamp = a.timestamp
                      AND b.stall_us = a.stall_us
                  ) > 0
            "#,
        )
        .execute(&pool)
        .await?;
        if backfilled.rows_affected() > 0 {
            info!(
                "Backfilled attributed stall for {} historical attribution rows",
                backfilled.rows_affected()
            );
        }

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

    /// Records what an analysis attempt produced.
    ///
    /// The raw reply is stored whether or not it grounded. A reply that
    /// claimed things the daemon never observed leaves `investigation` NULL
    /// with the text intact, which is the only way to tell that case apart
    /// from an analysis that never ran.
    pub async fn add_llm_analysis(
        &self,
        id: i64,
        outcome: &AnalysisOutcome,
    ) -> Result<(), sqlx::Error> {
        let now = Utc::now().timestamp();
        let investigation = outcome
            .investigation
            .as_ref()
            .and_then(|i| serde_json::to_string(i).ok());

        sqlx::query(
            "UPDATE incidents SET llm_analysis = ?, llm_analyzed_at = ?, investigation = ? WHERE id = ?",
        )
        .bind(&outcome.raw_response)
        .bind(now)
        .bind(investigation)
        .bind(id)
        .execute(&self.pool)
        .await?;

        debug!("Added LLM analysis to incident #{}", id);
        Ok(())
    }

    /// Reads back the grounded investigation for an incident.
    ///
    /// `Ok(None)` covers both "no analysis ran" and "the reply did not
    /// ground"; the raw text on the incident distinguishes them. A stored
    /// value that cannot be read back is a third case and warns rather than
    /// passing silently as either — it cannot happen today, and will the first
    /// time [`investigation::SCHEMA_VERSION`] moves.
    pub async fn get_investigation(
        &self,
        id: i64,
    ) -> Result<Option<IncidentInvestigation>, sqlx::Error> {
        let row = sqlx::query("SELECT investigation FROM incidents WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        let Some(json) = row.and_then(|r| r.get::<Option<String>, _>(0)) else {
            return Ok(None);
        };

        match serde_json::from_str::<IncidentInvestigation>(&json) {
            Ok(found) if found.schema_version > investigation::SCHEMA_VERSION => {
                warn!(
                    "Incident #{} holds a v{} investigation; this build reads v{}",
                    id,
                    found.schema_version,
                    investigation::SCHEMA_VERSION
                );
                Ok(None)
            }
            Ok(found) => Ok(Some(found)),
            Err(e) => {
                warn!("Incident #{} holds an unreadable investigation: {}", id, e);
                Ok(None)
            }
        }
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
    #[allow(clippy::too_many_arguments)]
    /// Persists one blame attribution.
    ///
    /// Takes the attribution whole rather than a dozen positional arguments:
    /// five of the columns are bare integers and transposing two of them would
    /// compile cleanly and corrupt the record.
    pub async fn insert_stall_attribution(
        &self,
        attr: &crate::collectors::psi::BlameAttribution,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO stall_attributions (
                victim_pod, victim_namespace, offender_pod, offender_namespace,
                stall_us, blame_score, timestamp,
                cpu_share, fork_count, short_job_count, attributed_stall_us,
                event_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&attr.victim_pod)
        .bind(&attr.victim_namespace)
        .bind(&attr.offender_pod)
        .bind(&attr.offender_namespace)
        .bind(attr.stall_us as i64)
        .bind(attr.blame_score)
        .bind(attr.timestamp as i64)
        .bind(attr.cpu_share)
        .bind(attr.fork_count as i64)
        .bind(attr.short_job_count as i64)
        .bind(attr.attributed_stall_us as i64)
        .bind(&attr.event_id)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        debug!(
            "Inserted stall attribution #{}: {}/{} blamed {}/{} (score={:.2})",
            id,
            attr.victim_namespace,
            attr.victim_pod,
            attr.offender_namespace,
            attr.offender_pod,
            attr.blame_score
        );
        Ok(id)
    }

    /// Query stall attributions for a victim pod within a time window
    /// Attributions for a victim over a window ending now.
    ///
    /// Convenience over [`query_attributions_between`] for "what is happening
    /// lately". The bounds it resolves to move with every call, so a caller
    /// that needs a stable answer — anything shareable — must resolve them once
    /// and pass them explicitly.
    pub async fn query_attributions(
        &self,
        victim_pod: &str,
        victim_namespace: &str,
        window_seconds: i64,
    ) -> Result<Vec<StallAttribution>, sqlx::Error> {
        let to = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        self.query_attributions_between(victim_pod, victim_namespace, to - window_seconds, to, None)
            .await
            .map(|(rows, _watermark)| rows)
    }

    /// Attributions for a victim between two absolute unix timestamps.
    ///
    /// Both bounds are inclusive. Timestamps here have one-second resolution,
    /// so an exclusive upper bound would drop any attribution recorded during
    /// the current second — invisible in testing and wrong exactly when a
    /// stall is being written as it is being read.
    ///
    /// Fixed bounds are what makes an answer citable: the same pair of
    /// timestamps returns the same rows next week, which a `now`-relative
    /// window cannot promise for the length of a paragraph, let alone an
    /// incident review.
    ///
    /// Timestamps alone are not enough for that promise, though. They have
    /// one-second resolution and the PSI collector writes on the same clock,
    /// so a row stamped in the current second can land *after* a query has
    /// answered and still fall inside its inclusive upper bound — absent from
    /// the response, present when the link is reopened. `max_row_id` closes
    /// that: rows are only considered up to a watermark taken before the
    /// select, and the returned watermark is what the caller puts in the link.
    /// Passing it back reproduces the original answer exactly, including
    /// against rows backfilled later with older timestamps, which no
    /// time-based boundary can exclude.
    ///
    /// Returns the rows and the watermark they were read at.
    pub async fn query_attributions_between(
        &self,
        victim_pod: &str,
        victim_namespace: &str,
        from: i64,
        to: i64,
        max_row_id: Option<i64>,
    ) -> Result<(Vec<StallAttribution>, i64), sqlx::Error> {
        self.query_attributions_filtered(victim_pod, victim_namespace, from, to, max_row_id, None)
            .await
    }

    /// As [`query_attributions_between`], narrowed to a single stall event.
    ///
    /// An event id makes a citation exact rather than merely bounded: the rows
    /// of one event, not whatever else shared its window. Rows written before
    /// the monitor emitted ids have `event_id IS NULL` and can never match, so
    /// an event-filtered query over old data correctly returns nothing rather
    /// than guessing at a grouping.
    pub async fn query_attributions_filtered(
        &self,
        victim_pod: &str,
        victim_namespace: &str,
        from: i64,
        to: i64,
        max_row_id: Option<i64>,
        event_id: Option<&str>,
    ) -> Result<(Vec<StallAttribution>, i64), sqlx::Error> {
        // Taken before the select, never after: a watermark read afterwards
        // could include a row the select had already missed, which is the race
        // this exists to remove.
        let watermark = match max_row_id {
            Some(id) => id,
            None => sqlx::query("SELECT COALESCE(MAX(id), 0) AS watermark FROM stall_attributions")
                .fetch_one(&self.pool)
                .await?
                .get::<i64, _>("watermark"),
        };

        let rows = sqlx::query(
            r#"
            SELECT offender_pod, offender_namespace, stall_us, blame_score, timestamp,
                   cpu_share, fork_count, short_job_count, attributed_stall_us,
                   event_id
            FROM stall_attributions
            WHERE victim_pod = ? AND victim_namespace = ? AND timestamp >= ? AND timestamp <= ?
                  AND id <= ?
                  -- Bound twice rather than numbered: `?5` would silently
                  -- refer to the watermark, since the unnumbered binds above
                  -- consume positions 1-5.
                  AND (? IS NULL OR event_id = ?)
            ORDER BY blame_score DESC
            "#,
        )
        .bind(victim_pod)
        .bind(victim_namespace)
        .bind(from)
        .bind(to)
        .bind(watermark)
        .bind(event_id)
        .bind(event_id)
        .fetch_all(&self.pool)
        .await?;

        let rows = rows
            .into_iter()
            // Columns are read by name: positional access silently shifts
            // every field after any column added to the SELECT above.
            .map(|r| StallAttribution {
                offender_pod: r.get("offender_pod"),
                offender_namespace: r.get("offender_namespace"),
                stall_us: r.get::<i64, _>("stall_us") as u64,
                blame_score: r.get("blame_score"),
                timestamp: r.get::<i64, _>("timestamp") as u64,
                cpu_share: r.get("cpu_share"),
                fork_count: r.get::<i64, _>("fork_count") as u64,
                short_job_count: r.get::<i64, _>("short_job_count") as u64,
                attributed_stall_us: r
                    .get::<Option<i64>, _>("attributed_stall_us")
                    .map(|v| v as u64),
                event_id: r.get::<Option<String>, _>("event_id"),
            })
            .collect();

        Ok((rows, watermark))
    }

    /// Records what happened after the action.
    ///
    /// Separate from `insert` because the outcome is not known when the
    /// incident is written — that is the whole point of measuring it. Called
    /// once per incident, after the recovery window closes.
    pub async fn record_outcome(
        &self,
        id: i64,
        outcome: &crate::incidents::outcome::RecoveryOutcome,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE incidents SET psi_after = ?, recovery_time_ms = ? WHERE id = ?")
            .bind(outcome.psi_after)
            .bind(outcome.recovery_time_ms)
            .bind(id)
            .execute(&self.pool)
            .await?;

        debug!(
            "Recorded outcome for incident #{}: psi_after={:?} recovery={:?}",
            id, outcome.psi_after, outcome.recovery_time_ms
        );
        Ok(())
    }

    /// Get incident by ID
    pub async fn get(&self, id: i64) -> Result<Option<Incident>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, timestamp, event_type, psi_cpu, psi_memory, cpu_percent, load_avg,
                   action, target_pid, target_name, system_snapshot,
                   llm_analysis, llm_analyzed_at, recovery_time_ms, psi_after,
                   investigation
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
            investigation: r.get(15),
        }))
    }

    /// Get recent incidents
    pub async fn recent(&self, limit: i64) -> Result<Vec<Incident>, sqlx::Error> {
        self.recent_filtered(limit, None, None).await
    }

    /// Get recent incidents, optionally filtered by event type and analysis state
    pub async fn recent_filtered(
        &self,
        limit: i64,
        event_type: Option<&str>,
        analyzed: Option<bool>,
    ) -> Result<Vec<Incident>, sqlx::Error> {
        let mut sql = String::from(
            r#"
            SELECT id, timestamp, event_type, psi_cpu, psi_memory, cpu_percent, load_avg,
                   action, target_pid, target_name, system_snapshot,
                   llm_analysis, llm_analyzed_at, recovery_time_ms, psi_after,
                   investigation
            FROM incidents
            "#,
        );
        let mut filters = Vec::new();

        if event_type.is_some() {
            filters.push("event_type = ?");
        }
        if let Some(analyzed) = analyzed {
            filters.push(if analyzed {
                "llm_analysis IS NOT NULL"
            } else {
                "llm_analysis IS NULL"
            });
        }
        if !filters.is_empty() {
            sql.push_str("WHERE ");
            sql.push_str(&filters.join(" AND "));
            sql.push('\n');
        }
        sql.push_str("ORDER BY timestamp DESC LIMIT ?");

        let mut query = sqlx::query(&sql);
        if let Some(evt_type) = event_type {
            query = query.bind(evt_type);
        }
        let rows = query.bind(limit).fetch_all(&self.pool).await?;

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
                investigation: r.get(15),
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
                       llm_analysis, llm_analyzed_at, recovery_time_ms, psi_after,
                   investigation
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
                       llm_analysis, llm_analyzed_at, recovery_time_ms, psi_after,
                   investigation
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
                investigation: r.get(15),
            })
            .collect())
    }

    /// Get statistics about incidents
    pub async fn stats(&self) -> Result<IncidentStats, sqlx::Error> {
        let total_row = sqlx::query("SELECT COUNT(*) FROM incidents")
            .fetch_one(&self.pool)
            .await?;
        let total: i64 = total_row.get(0);

        let cb_row = sqlx::query(
            "SELECT COUNT(*) FROM incidents WHERE event_type = 'circuit_breaker' OR event_type GLOB 'circuit_breaker_*'",
        )
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

async fn apply_required_column_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    for migration in REQUIRED_COLUMNS {
        if !column_exists(pool, migration.table, migration.column).await? {
            sqlx::query(migration.ddl).execute(pool).await?;
        }
    }
    Ok(())
}

async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> Result<bool, sqlx::Error> {
    let escaped_table = table.replace('"', "\"\"");
    let rows = sqlx::query(&format!("PRAGMA table_info(\"{escaped_table}\")"))
        .fetch_all(pool)
        .await?;

    Ok(rows
        .iter()
        .any(|row| row.get::<String, _>("name").eq_ignore_ascii_case(column)))
}

/// Statistics about stored incidents
#[derive(Debug, Serialize)]
pub struct IncidentStats {
    pub total: u64,
    pub circuit_breaker_triggers: u64,
    /// Mean recovery time across incidents that *did* recover.
    ///
    /// Incidents watched but still stalling at the end of the window record no
    /// recovery time, so they are absent here rather than counted as slow
    /// recoveries. Read it as "when it worked, how fast", not "how well it
    /// works" — `total` against the number with a recovery time is
    /// the second half of that picture.
    pub avg_recovery_time_ms: Option<u64>,
    pub feedback_entries: u64,
}
