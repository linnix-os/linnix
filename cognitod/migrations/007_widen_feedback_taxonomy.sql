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
-- SQLite cannot ALTER a CHECK constraint in place, so the table is rebuilt.

CREATE TABLE feedback_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    insight_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    label TEXT NOT NULL CHECK(label IN (
        'correct', 'wrong_culprit', 'wrong_reason', 'incomplete', 'what_fixed_it'
    )),
    source TEXT NOT NULL CHECK(source IN ('slack', 'cli')),
    user_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (insight_id) REFERENCES insights(id)
);

INSERT INTO feedback_new (id, insight_id, timestamp, label, source, user_id, created_at)
SELECT
    id,
    insight_id,
    timestamp,
    CASE label
        WHEN 'useful' THEN 'correct'
        WHEN 'noise' THEN 'incomplete'
        WHEN 'wrong_root_cause' THEN 'wrong_culprit'
        ELSE label
    END,
    source,
    user_id,
    created_at
FROM feedback;

DROP TABLE feedback;
ALTER TABLE feedback_new RENAME TO feedback;

CREATE INDEX IF NOT EXISTS idx_feedback_insight_id ON feedback(insight_id);
CREATE INDEX IF NOT EXISTS idx_feedback_timestamp ON feedback(timestamp);
CREATE INDEX IF NOT EXISTS idx_feedback_label ON feedback(label);
