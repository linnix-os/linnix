# Pilot Outreach Kit

## Target Organizations & Success Criteria

1. **Cloud Operations Team (Fintech A)**  
   Success: Detect fork storm <10s, daemon CPU <3%, zero crashes during 48h soak.
2. **SRE Platform Group (SaaS B)**  
   Success: Alert on short-job flood in under 1 minute, daemon RSS <200 MB, no dropped perf buffers.
3. **Security Operations Center (Media C)**  
   Success: Runaway tree alerting <15s, rules exported to SIEM, single-click uninstall validated.

## 30-Minute Demo Agenda

1. Quick install (0–5 min) — run `./demo_phase1.sh`, review status and metrics.
2. Live event stream (5–15 min) — tail CLI, show lineage backfill, drill into `/metrics`.
3. Rule hit (15–25 min) — trigger fork storm, inspect alert payload + SSE.
4. Q&A & next steps (25–30 min) — sizing, success criteria, white-glove follow-up.

## Outreach Email Draft

> Subject: Pilot Linnix Phase 1 — eBPF-powered process insight in <30 minutes  
>  
> Hi <Name>,  
> We’re lining up three design partners for Linnix Phase 1 — our eBPF + LLM-ready process visibility stack. The pilot deploys with `./demo_phase1.sh`, streams live exec/fork telemetry, and ships with guardrails: offline-by-default, capability checks, and metrics for every drop.  
>  
> I’d love to give your team a 30-minute walkthrough covering install, live event drill-down, and the fork-storm/runaway-tree detectors. We’ll stay on the Zoom afterward for a white-glove install or config tweaks.  
>  
> Interested in a slot next week? Happy to tailor success criteria (<10 s alert latency, <3% CPU, zero daemon crashes) to your environment.  
>  
> — <Your Name>

## One-Pager Talking Points

- **What**: Cognitod daemon + CLI for live Linux process observability; rules engine ships with numeric detectors (fork burst, short-job flood, runaway tree).
- **Why now**: Offline by default, capability gate, and low fixed footprint (<25% CPU target, 512 MB RSS cap) make it safe to pilot on production nodes.
- **How fast**: Installer handles binaries, configs, caps, systemd unit, and post-flight health check. Demo script validates end-to-end in minutes.
- **Integrations**: `/metrics`, `/status`, and `/alerts` SSE feed into existing monitoring; JSONL handler ready for SIEM ingest.
- **Support**: White-glove Zoom sessions, uninstall script, and shared roadmap for LLM reasoning tie-ins.
