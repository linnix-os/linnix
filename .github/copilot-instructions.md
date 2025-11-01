# Linnix AI Agent Instructions

## Architecture Overview

Linnix is an eBPF-powered Linux observability platform that captures process lifecycle events (fork/exec/exit) with lightweight CPU/memory telemetry and streams them to user-space for AI-powered incident detection.

**Core Components:**
- **cognitod** (`cognitod/`) - Main daemon that loads eBPF programs, consumes perf buffers, maintains process state, and exposes HTTP/SSE APIs
- **linnix-ai-ebpf** (`linnix-ai-ebpf/`) - Dual-space eBPF collector: kernel-side tracepoints/kprobes and userland Aya bindings
- **linnix-cli** (`linnix-cli/`) - CLI client consuming SSE streams from cognitod
- **linnix-reasoner** (`linnix-reasoner/`) - Fetches system snapshots from cognitod and sends to OpenAI LLM for semantic analysis
- **insight_tool** (Python, `insight_tool/`) - Dataset pipeline for incident→insight training data; validates against JSON Schema

**Data Flow:**
```
Kernel (eBPF probes) → Perf buffers → cognitod runtime → Handler pipeline (rules/JSONL/ILM) → HTTP/SSE endpoints → CLI/Dashboard/Reasoner
```

## Critical Developer Workflows

### Build & Test
```bash
# Full workspace build
cargo build --release

# Build eBPF artifacts (requires nightly-2024-12-10)
cargo xtask build-ebpf

# Test suite (uses nextest)
make test  # or RUSTFLAGS="-D warnings" cargo nextest run --workspace

# Format + lint (CI enforces this)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
```

### Running Cognitod Locally
Cognitod requires root/CAP_BPF to load eBPF programs. The daemon looks for compiled eBPF objects in these paths (priority order):
1. `LINNIX_BPF_PATH` env var
2. `/usr/local/share/linnix/linnix-ai-ebpf-ebpf`
3. `target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf`
4. Fallback search in `target/bpf/*.o`

```bash
# Build workspace + eBPF, then run daemon
cargo build --release -p cognitod
cargo xtask build-ebpf
sudo LINNIX_BPF_PATH=target/bpf/linnix-ai-ebpf-ebpf.o \
  ./target/release/cognitod --config configs/linnix.toml --handler rules:configs/rules.yaml
```

Use `demo_phase1_local.sh` for a complete local demo with synthetic events.

### BTF-Dependent Features
Cognitod uses kernel BTF (`/sys/kernel/btf/vmlinux`) to dynamically derive struct offsets for:
- `task_struct` fields (real_parent, tgid, se.sum_exec_runtime)
- RSS accounting (either `mm_struct->rss_stat` or `signal_struct->rss_stat` depending on kernel version)

Without BTF, the daemon runs in degraded mode (no per-process CPU/RSS metrics). See `cognitod/src/bpf_config.rs::derive_telemetry_config()`.

### Handler System
Cognitod supports pluggable event handlers specified via `--handler <type>:<path>`:
- `jsonl:<path>` - Append events/snapshots as JSONL (see `cognitod/src/handler/mod.rs::JsonlHandler`)
- `rules:<path>` - YAML-based rule engine for fork storms, exec rates, subtree CPU spikes (see `cognitod/src/handler/local_ilm/`)
- Handlers implement the `Handler` trait (`async fn on_event`, `async fn on_snapshot`)

## Project-Specific Conventions

### eBPF/Userspace Boundary
- Kernel events use `ProcessEventWire` (POD struct defined in `linnix-ai-ebpf-common`)
- Userspace extends to `ProcessEvent` with tags, hash caches, and helper methods
- CPU/mem percentages stored as `u16` milli-percent (10000 = 100.0%); `PERCENT_MILLI_UNKNOWN` (65535) indicates no data

### Workspace Structure
- Multi-crate workspace with shared dependencies in root `Cargo.toml` under `[workspace.dependencies]`
- eBPF code lives in `linnix-ai-ebpf/linnix-ai-ebpf-ebpf/src/program.rs`; uses Aya's attribute macros (`#[tracepoint]`, `#[kprobe]`)
- Tests use nextest with profiles: `default` (1 retry for flaky tests), `e2e` (serial execution)

### Dual Licensing
- Core daemon/CLI: **AGPL-3.0** or commercial
- eBPF code: **GPL-2.0** or MIT (eBPF programs must be GPL-compatible)
- Sign CLA before contributing (see `CONTRIBUTING.md`)

## Key Integration Points

### External Dependencies
- **Aya** (`git` dependency pinned to `fe8e1c48`) - eBPF loading/management; not published to crates.io
- **BTF library** (`btf` crate) - Parse `/sys/kernel/btf/vmlinux` for dynamic offset resolution
- **Tokio** - Async runtime; perf buffer polling uses `tokio::spawn` workers per CPU
- **Axum** - HTTP server exposing `/events` (SSE), `/processes`, `/graph/{pid}`, `/insights`, `/metrics`, etc.

### API Endpoints (see `cognitod/src/api/mod.rs`)
- `GET /stream` - Server-sent events for real-time process events
- `GET /processes` - All live processes
- `GET /graph/{pid}` - Process ancestry graph (descendants + lineage)
- `GET /insights` - Recent insights from rule engine or LLM
- `GET /metrics` - Prometheus-compatible metrics

### Configuration
Cognitod loads TOML config from:
1. `LINNIX_CONFIG` env var
2. `--config` CLI flag
3. `/etc/linnix/linnix.toml` (default)

Schema in `cognitod/src/config.rs`. Notable fields:
- `runtime.offline = true` disables all external HTTP egress (Slack/PagerDuty/Prometheus)
- `telemetry.sample_interval_ms` controls eBPF sampling frequency

## Code Patterns

### Error Handling
Use `anyhow::Result` with `.context()` for rich error chains; propagate with `?` unless recovery is possible. eBPF attachment failures for optional probes (network, block IO) use `attach_kprobe_optional()` which logs warnings but doesn't abort.

### Fake Events for Testing
Enable `--features fake-events` to inject synthetic fork storms, short-job floods, or runaway trees. Profiles defined in `cognitod/src/fake_events.rs`. Use in CI or local stress testing.

### Process Tagging
Cognitod maintains an LRU cache of process tags (comm hash → Vec<String>) persisted to `/var/lib/linnix/tag_cache.json`. Tags drive alert routing and insight classification. See `cognitod/src/context.rs`.

## Dataset Pipeline (Incident→Insight Workflow)

### Pipeline Architecture
The dataset pipeline transforms raw incident telemetry into schema-validated training data for LLM fine-tuning:

```
Raw Incidents → insight_tool CLI → Schema Validation → JSONL Dataset → Model Training
```

### Data Collection & Generation

**1. Capture Live Incidents**
```bash
# Capture system snapshot during incident window
./scripts/capture_window.sh fork-storm datasets/synthetic/my-incident

# Collect JSONL events from cognitod handler
cognitod --handler jsonl:output.jsonl
```

**2. Create Training Records**
```bash
# From plaintext incident descriptions (one per line)
insight from-contexts incidents.txt --out dataset.jsonl --strategy heuristics

# Single record with full metadata
insight new --id incident-001 --version v0.1 \
  --context "CPU 97% for 3m; java pid 4412 top" \
  --source-type recorded --source-notes "pagerduty export" \
  --out records.jsonl

# LLM-assisted generation (requires INSIGHT_LLM_ENDPOINT)
export INSIGHT_LLM_ENDPOINT="http://localhost:8087/v1/chat/completions"
export INSIGHT_LLM_TOKEN="your-token"
insight from-contexts incidents.txt --out dataset.jsonl --strategy llm --model qwen2.5-7b
```

**3. Schema Validation**
```bash
# Fetch live schema from cognitod (port 3000)
python scripts/fetch_insight_schema.py --output datasets/schema/insight.schema.json

# Validate all records
insight validate dataset.jsonl --schema datasets/schema/insight.schema.json

# Repair malformed records
insight repair broken.json --out fixed.json
```

### Dataset Record Format
Each JSONL line contains:
```jsonc
{
  "id": "unique-id",
  "version": "v0.1",
  "source": {"type": "synthetic|recorded", "notes": "provenance"},
  "context": {
    "telemetry_summary": "w=5 eps=240 frk=3 exe=1 top=java cpu=96%",
    "events_per_sec": 240,
    "kb_snippets": [{"title": "cpu_spin.md", "excerpt": "..."}]
  },
  "insight": {
    "class": "cpu_spin|fork_storm|io_saturation|oom_risk|normal",
    "confidence": 0.62,
    "primary_process": "java",
    "why": "java pid 4412 held >95% cpu throughout sample",
    "actions": ["capture async-profiler traces", "move to throttled tier"]
  }
}
```

### Insight Classes & Heuristics
The pipeline recognizes these incident classes (see `insight_tool/heuristics.py`):
- **cpu_spin**: CPU >95%, runq elevated, hot pid dominates
- **io_saturation**: Disk util >90%, latency spikes, request queue elevated
- **fork_storm**: Forks/sec spike, short-lived shells
- **short_job_flood**: Thousands of <1s jobs, scheduler churn
- **oom_risk**: RSS rising, swapin activity, cgroup near limit
- **runaway_tree**: Child process fan-out, tree growth

Each class has curated action templates in `ACTION_LIBRARY` dict.

## Building a Custom Language Model

### Training Data Requirements

**Minimum Dataset Size**: 500-1000 labeled incidents for domain-specific fine-tuning; 5000+ for production-grade models.

**Data Sources**:
1. **Synthetic Incidents**: Use fake-events feature (`--features fake-events`) to generate fork storms, short jobs, runaway trees
2. **Recorded Production**: Export from PagerDuty, Slack alerts, JSONL handler output
3. **Curated Examples**: Expand `datasets/examples/v0.1/incident_insights.jsonl` with postmortem analysis

### Fine-Tuning Workflow (Qwen2.5-7B Example)

**1. Prepare Training Data**
```bash
# Build large corpus from mixed sources
cat datasets/synthetic/*/*.jsonl datasets/examples/v0.1/*.jsonl > training_full.jsonl

# Validate all records
insight validate training_full.jsonl

# Split train/val (80/20)
head -n 800 training_full.jsonl > train.jsonl
tail -n 200 training_full.jsonl > val.jsonl
```

**2. Convert to Chat Format**
```python
# transform_for_training.py - convert Insight JSONL to chat completions
import json

def format_chat_record(record):
    context_summary = record["context"]["telemetry_summary"]
    insight = record["insight"]
    
    return {
        "messages": [
            {"role": "system", "content": "Convert incident telemetry into structured Insight JSON."},
            {"role": "user", "content": f"INCIDENT: {context_summary}"},
            {"role": "assistant", "content": json.dumps(insight)}
        ]
    }

with open("train.jsonl") as f, open("train_chat.jsonl", "w") as out:
    for line in f:
        record = json.loads(line)
        out.write(json.dumps(format_chat_record(record)) + "\n")
```

**3. Fine-Tune with Axolotl/Unsloth**
```yaml
# axolotl_config.yml
base_model: Qwen/Qwen2.5-7B-Instruct
model_type: AutoModelForCausalLM
tokenizer_type: AutoTokenizer

datasets:
  - path: train_chat.jsonl
    type: chat_template
    
# LoRA configuration for efficient fine-tuning
adapter: lora
lora_r: 16
lora_alpha: 32
lora_dropout: 0.05
lora_target_modules: [q_proj, k_proj, v_proj, o_proj]

# Training params
learning_rate: 2.0e-5
num_epochs: 3
micro_batch_size: 2
gradient_accumulation_steps: 4
warmup_steps: 100
```

```bash
# Run fine-tuning
accelerate launch -m axolotl.cli.train axolotl_config.yml

# Or use Unsloth for 2x faster training
python -m unsloth.train --config axolotl_config.yml
```

**4. Export & Deploy Model**
```bash
# Merge LoRA weights and export
python scripts/merge_lora.py --base Qwen/Qwen2.5-7B-Instruct \
  --adapter outputs/checkpoint-500 --out linnix-qwen-v1

# Quantize for inference (GGUF for llama.cpp)
python -m llama_cpp.convert linnix-qwen-v1 --outtype q5_k_m

# Serve with llama.cpp
./llama-server -m linnix-qwen-v1-q5_k_m.gguf --port 8087 --ctx-size 4096
```

**5. Integrate with Cognitod**
```bash
# Point reasoner to custom model
export LLM_ENDPOINT="http://localhost:8087/v1/chat/completions"
export LLM_MODEL="linnix-qwen-v1"

cargo run -p linnix-reasoner -- --model linnix-qwen-v1

# Use in insight_tool for dataset expansion
export INSIGHT_LLM_ENDPOINT="http://localhost:8087/v1/chat/completions"
insight from-contexts new_incidents.txt --strategy llm --model linnix-qwen-v1
```

### Continuous Improvement Loop

**Active Learning Pipeline**:
1. Deploy model in shadow mode alongside heuristics
2. Log predictions with low confidence (<0.65) to review queue
3. Human-label ambiguous cases and append to `datasets/examples/vX.Y/`
4. Re-train monthly with accumulated corrections
5. A/B test new checkpoint against baseline (track precision/recall via `/metrics`)

**Evaluation Metrics** (see `cognitod/src/metrics.rs`):
- Insight schema validation rate (`linnix_ilm_schema_errors_total`)
- Class distribution balance (avoid overfitting to `cpu_spin`)
- Action relevance score (manual audit of top 50 predictions/week)

## References
- Main README: `README.md`
- eBPF probe inventory: `docs/collector.md`
- Prometheus integration: `docs/prometheus-integration.md`
- Dataset schema: `datasets/schema/insight.schema.json` (fetch from running daemon via `scripts/fetch_insight_schema.py`)
- Dataset examples: `datasets/examples/v0.1/incident_insights.jsonl`
- Insight tool CLI: `insight_tool/cli.py`
- Heuristic rules: `insight_tool/heuristics.py`
- Systemd units: `configs/systemd/cognitod.service`
