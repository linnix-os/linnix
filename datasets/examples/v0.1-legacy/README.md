# v0.1 Sample Incident Insights (legacy)

**Superseded by v0.2.** This directory holds the process-scoped `class`/`why`/`actions` shape from
before the schema was regenerated from `cognitod::schema::Insight`. It never matched what cognitod
actually emits (pod-scoped `reason_code`/`top_pods`/`suggested_next_step`), and nothing regenerated
or validated it against the daemon. Kept here for historical reference only — do not add new
examples in this shape, and do not point new tooling at `datasets/schema/insight.schema.json`'s v0.1
predecessor. See `datasets/schema/insight.schema.json` (v0.2) and `datasets/episodes/` for the
current contract.

This directory seeds the incident→insight pipeline with a couple of hand-crafted examples. Each line
in `incident_insights.jsonl` combines:

- **context.telemetry_summary** – the information the ILM handler would send to the model.
- **context.kb_snippets** – optional RAG excerpts that informed the decision.
- **insight** – a fully schema-compliant response the model should emit.

The samples are intentionally simple but cover common classes:

1. `cpu_spin` with a clear primary process and mitigation steps.
2. `fork_storm` demonstrating how cooldowns and dedupe behave when many forks arrive together.

Use these examples to smoke-test validation scripts or to prime labeling tooling before you ingest
real incidents. Copy the file, adjust the metadata, and expand the list as you collect canonical
postmortems.
