-- Add detailed attribution metrics
ALTER TABLE stall_attributions ADD COLUMN cpu_share REAL DEFAULT 0.0;
ALTER TABLE stall_attributions ADD COLUMN fork_count INTEGER DEFAULT 0;
ALTER TABLE stall_attributions ADD COLUMN short_job_count INTEGER DEFAULT 0;
