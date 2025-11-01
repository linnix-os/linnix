# Linnix Phase 1 Substack Series

## Goals for the Series
- Announce that Linnix Phase 1 already delivers live, semantic observability for Linux processes and set expectations for readers following along the buildout.
- Highlight the pieces that are production-ready today—Cognitod, the Linnix CLI, and the lightweight dashboard—and show how teams can start experimenting in under 30 minutes.
- Build trust around the safety guardrails (offline-by-default, capability checks, metrics) while previewing the LLM-native roadmap.

## Core Audience & Tone
- **Primary readers**: Staff+ SREs, platform engineers, and security responders who are curious about eBPF-powered observability but need low-risk proofs before piloting.
- **Secondary readers**: AI infrastructure leads exploring how LLMs can reason over live systems.
- **Voice**: Confident, technical storytelling that blends architecture diagrams, CLI transcripts, and lightweight callouts. Treat every post as a field report from a team that already has the daemon running.

## Publishing Cadence & Format
- Ship a five-part weekly series. Each post stands alone but references the previous installment for continuity.
- Close every article with a "Get the bits" box that points to the demo script and outreach call-to-action.
- Include one short code or CLI snippet per post to reinforce that everything described is already in the repo.

## Post Line-Up

### Post 1 — "Linnix Phase 1: Live Process Observability for the LLM Era"
- **Purpose**: Position Linnix as the first LLM-native Linux platform and outline the Phase 1 scope.
- **Key beats**:
  - Explain the triad of Cognitod, Linnix CLI, and the shared event library as the foundation of the stack.【F:README.md†L1-L13】
  - Walk through the two-command quickstart (`cargo build --workspace`, `./demo_phase1.sh`) to set the expectation that readers can follow along immediately.【F:README.md†L16-L27】
  - Close with the sample fork/exec/exit event snippet to show what "semantic OS visibility" looks like on day one.【F:README.md†L38-L43】
- **CTA**: Invite readers to run the demo script before the next installment and reply with their first impressions of the event stream.

### Post 2 — "Inside Cognitod: How Our eBPF Daemon Streams a Linux Graph"
- **Purpose**: Deep dive into the daemon that is already shipping and emphasize operational readiness.
- **Key beats**:
  - Detail the boot sequence: environment checks for required kernel version and capabilities, configuration loading, and metrics initialization.【F:cognitod/src/main.rs†L59-L190】
  - Highlight the pluggable handler system (JSONL storage, rules engine) and the ability to select BPF objects at runtime for different environments.【F:README.md†L29-L37】【F:cognitod/src/main.rs†L193-L200】
  - Include a sidebar on the fake event profiles for fork storms, short-job floods, and runaway trees to help readers stress-test locally.【F:cognitod/src/main.rs†L53-L56】
- **CTA**: Encourage readers to enable the rules handler and share what custom conditions they want to write next.

### Post 3 — "Streaming Telemetry You Can Actually Use: CLI + Dashboard"
- **Purpose**: Showcase the end-user interfaces that already work today.
- **Key beats**:
  - Demonstrate how the CLI can switch between status snapshots, alert SSE streams, and live process events, including exporting incident reports for a given rule and time window.【F:linnix-cli/src/main.rs†L18-L153】
  - Describe how the React dashboard consumes the `/stream` endpoint over Server-Sent Events and visualize the same feed in the browser for operators who prefer a graphical console.【F:README.md†L54-L67】
  - Share one combined workflow: run the daemon, tail the CLI for alerts, and open the dashboard for lineage graphs.
- **CTA**: Ask readers to send screenshots of their favorite CLI transcripts or dashboard panels once they connect to `/stream`.

### Post 4 — "Guardrails First: Offline Mode, Capabilities, and Safe Rollouts"
- **Purpose**: Build confidence that Linnix Phase 1 can be piloted on production hosts without surprises.
- **Key beats**:
  - Emphasize that the daemon ships offline-by-default, requires explicit capability grants, and surfaces resource targets plus overflow behavior through `/metrics`.【F:README.md†L79-L85】
  - Explain how the OfflineGuard wraps any network-aware feature—including LLM tagging—so administrators can keep every request local until they opt in.【F:cognitod/src/main.rs†L156-L160】【F:cognitod/src/inference/summarizer.rs†L53-L66】
  - Outline the detach workflow for uninstall scripts and the uninstall helper for a clean rollback if pilots need to pause.【F:cognitod/src/main.rs†L136-L149】【F:README.md†L85-L85】
- **CTA**: Offer a checklist PDF for change-management reviews covering capabilities, resource budgets, and rollback steps.

### Post 5 — "From Observability to Autonomy: Tagging, Insights, and the Roadmap"
- **Purpose**: Show how the shipping features hint at Linnix's LLM-native future and invite readers into the roadmap.
- **Key beats**:
  - Explain the LLM tagging pipeline that classifies process names, caches results on disk, and respects offline gating—demonstrating how Linnix is already capturing semantic metadata.【F:cognitod/src/inference/summarizer.rs†L17-L167】
  - Revisit the roadmap items: additional event types, richer system snapshots, and integrations like rule-based alerts and JSONL exports that already have working stubs today.【F:README.md†L45-L52】
  - End with how insights, `/alerts`, and `/metrics` streams pave the way for autonomous remediation workflows in future phases.【F:README.md†L35-L37】【F:README.md†L54-L67】
- **CTA**: Invite subscribers to join a feedback call on prioritizing the next wave of event types or LLM-assisted responses.

## Distribution Extras
- Repurpose each article into a short LinkedIn recap the day after publication, linking back to the Substack installment and the outreach email template.
- After the series concludes, compile the five posts into a downloadable PDF playbook for prospective design partners.
- Feed notable reader replies into the `/insights` endpoint to test summarization quality against real operator language.
