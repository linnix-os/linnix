-- Migration 006: Store the grounded investigation alongside the raw LLM reply.
--
-- `llm_analysis` keeps holding the model's response verbatim. This column
-- holds the parsed, fact-checked form: hypotheses whose every citation
-- resolved to a fact the daemon supplied. Keeping them in separate columns
-- means no reader has to distinguish prose from JSON by inspecting the value,
-- and a reply that failed to ground leaves this NULL with the raw text intact
-- for diagnosis.

ALTER TABLE incidents ADD COLUMN investigation TEXT;
