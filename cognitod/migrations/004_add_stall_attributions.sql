-- Migration 004: Add stall_attributions table for PSI blame tracking

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

CREATE INDEX IF NOT EXISTS idx_victim_time 
    ON stall_attributions(victim_pod, victim_namespace, timestamp);

CREATE INDEX IF NOT EXISTS idx_offender_time 
    ON stall_attributions(offender_pod, offender_namespace, timestamp);

CREATE INDEX IF NOT EXISTS idx_timestamp 
    ON stall_attributions(timestamp);
