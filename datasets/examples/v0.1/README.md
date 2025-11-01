# v0.1 Sample Incident Insights

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
