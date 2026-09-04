-- Migration 007: Widen feedback to the five-way correction taxonomy.
--
-- The old label set (useful, noise, wrong_root_cause) said whether an insight
-- was worth reading, not what was wrong with it. The Incident Lab scores
-- Top-1 culprit accuracy and reason-code accuracy separately, so "wrong" has
-- to say which one failed. Existing rows are remapped rather than dropped:
-- useful -> correct (the closest existing signal to "this was right"),
-- noise -> incomplete (a insight worth ignoring was, at minimum, missing
-- something), wrong_root_cause -> wrong_culprit (the label the old schema
-- actually meant by "root cause" was the offending pod, not the reason
-- code -- BlameReason had no reason-code axis to be wrong about until the
-- v0.2 schema merge).
--
-- NOT executed by a migration runner: like every other schema change here
-- (see 004_add_stall_attributions.sql, 005_add_attribution_details.sql,
-- 006_add_investigation.sql), this file documents the change; the actual
-- database work happens in cognitod/src/incidents.rs on daemon startup. The
-- column/table shape is IncidentStore::new()'s own `CREATE TABLE IF NOT
-- EXISTS feedback` (no CHECK constraint -- validity is enforced by the
-- `FeedbackLabel` Rust enum instead, the same way REQUIRED_COLUMNS covers
-- ADD COLUMN rather than a CHECK-constrained rebuild). The row remap this
-- file describes is performed by `remap_legacy_feedback_labels`, called from
-- `IncidentStore::new()` on every startup and idempotent: once no row
-- carries a legacy label, it matches nothing.

UPDATE feedback
SET label = CASE label
    WHEN 'useful' THEN 'correct'
    WHEN 'noise' THEN 'incomplete'
    WHEN 'wrong_root_cause' THEN 'wrong_culprit'
    ELSE label
END
WHERE label IN ('useful', 'noise', 'wrong_root_cause');
