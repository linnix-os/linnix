-- Feedback table for insight quality tracking
-- Enables future tuning and monetization metrics

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    insight_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    label TEXT NOT NULL CHECK(label IN ('useful', 'noise', 'wrong_root_cause')),
    source TEXT NOT NULL CHECK(source IN ('slack', 'cli')),
    user_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (insight_id) REFERENCES insights(id)
);

CREATE INDEX IF NOT EXISTS idx_feedback_insight_id ON feedback(insight_id);
CREATE INDEX IF NOT EXISTS idx_feedback_timestamp ON feedback(timestamp);
CREATE INDEX IF NOT EXISTS idx_feedback_label ON feedback(label);
