# Linnix

[![CI](https://github.com/linnix-os/linnix/actions/workflows/docker.yml/badge.svg)](https://github.com/linnix-os/linnix/actions/workflows/docker.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/linnixos/cognitod?style=flat-square)](https://github.com/linnix-os/linnix/pkgs/container/cognitod)
[![GitHub Stars](https://img.shields.io/github/stars/linnix-os/linnix?style=social)](https://github.com/linnix-os/linnix)

<p align="center">
  <img src="docs/images/linnix-demo.gif" alt="Linnix detecting a fork storm" width="800"/>
</p>

**eBPF-powered Linux observability with optional AI incident detection**

Linnix monitors every process on your Linux system using eBPF - forks, execs, exits, and basic CPU/memory telemetry. It can run standalone with a built-in rules engine, or you can add AI for natural language insights.

## What it does

- Monitors process lifecycle events at the kernel level using eBPF
- Low overhead (<1% CPU on my test systems)
- Built-in rules engine catches common issues (fork storms, CPU spikes, runaway processes)
- Optional LLM integration for natural language incident analysis
- Works with any OpenAI-compatible API or local models (llama.cpp, Ollama, vLLM)

## Why I built this

Traditional monitoring tools alert you after things break. I wanted something that could spot weird patterns early - like memory allocation rates that look off, or unusual fork behavior - before they cascade into actual outages.

eBPF gives us kernel-level visibility without the overhead of traditional monitoring agents. The LLM part is optional but helps spot patterns that simple threshold alerts miss.

## Quick Start

### Option 1: Docker (Simplest)

```bash
git clone https://github.com/linnix-os/linnix.git && cd linnix
docker-compose up -d

# Stream live process events
curl -N http://localhost:3000/stream

# Get incident alerts from rules engine
curl http://localhost:3000/insights | jq
```

No AI needed for basic monitoring. Works out of the box.

### Option 2: With AI (Optional)

```bash
git clone https://github.com/linnix-os/linnix.git && cd linnix
./setup-llm.sh  # Downloads model (~2GB) and sets everything up

# Then open: http://localhost:8080
```

This downloads a small model (linnix-3b, distilled for CPU inference) and starts the full stack.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Kernel Space (eBPF)                       │
├──────────────────────────────────────────────────────────────┤
│  fork hook  →  exec hook  →  exit hook  →  CPU/mem sampling  │
└────────────────────────┬─────────────────────────────────────┘
                         │ Perf buffers
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                   User Space (cognitod)                      │
├──────────────────────────────────────────────────────────────┤
│  • Event processing    • Process tree tracking               │
│  • State management    • Rules engine                        │
│  • HTTP/SSE API        • Prometheus metrics                  │
└────────────────────────┬─────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
   ┌─────────┐    ┌──────────┐   ┌─────────────┐
   │ CLI     │    │ Reasoner │   │ Prometheus  │
   │ Stream  │    │ (AI)     │   │ Grafana     │
   └─────────┘    └──────────┘   └─────────────┘
```

## What It's Designed to Catch

The eBPF probes monitor:
- Fork storms (rapid process spawning)
- Memory allocation patterns (potential leaks)
- File descriptor usage (exhaustion risk)
- CPU thrashing (processes stuck in loops)

The rules engine can alert on these patterns. The AI reasoner (experimental) attempts to explain what's happening in natural language.

**Current testing status:** Built and tested in local Docker environments. Rules engine works for basic pattern detection. AI reasoning is experimental and depends heavily on model quality. Not yet tested at scale or in production environments.

## Testing

The codebase includes 35+ automated tests covering:

**eBPF Event Detection:**
- Fork storm detection (rapid process spawning)
- Fork burst patterns
- Process lifecycle tracking (fork → exec → exit)

**Rules Engine:**
- Pattern matching for forks/sec, CPU usage, memory growth
- Alert cooldown and deduplication
- YAML/TOML configuration parsing

**API & Integration:**
- HTTP/SSE streaming endpoints
- Prometheus metrics export
- CLI alert processing
- Install/uninstall scripts

Run tests:
```bash
# Unit and integration tests
cargo test --workspace

# Including fork storm detection tests
cargo test --features fake-events
```

All tests passing as of last commit. CI runs these on every push.

## Demo Scenarios

**Watch it in action:**

[![asciicast](https://asciinema.org/a/iiVMjlLzJTrtjBgvCavDnTOOc.svg)](https://asciinema.org/a/iiVMjlLzJTrtjBgvCavDnTOOc)

Linnix catching a fork bomb in real-time - **4 different alert types** from a single scenario.

---

Want to run it yourself? Try the demo scenarios that trigger actual failures:

```bash
# Quick demo: Fork bomb detection
./scenarios/demo/demo-script.sh

# Or run individual scenarios:
docker run --rm linnix-demo-fork-bomb
docker run --rm --memory=200m linnix-demo-memory-leak
docker run --rm --ulimit nofile=256:256 linnix-demo-fd-exhaustion
```

**What Linnix catches:**
- Fork storm (50+ forks/second)
- Fork burst (60+ forks in 5 seconds)
- Runaway process trees
- Memory leaks before OOM
- File descriptor exhaustion

Each scenario runs in an isolated container and triggers real resource exhaustion. Linnix alerts **before they cause failures**.

See [scenarios/README.md](scenarios/README.md) and [DEMO_RESULTS.md](DEMO_RESULTS.md) for full details.

## Requirements

- Linux kernel 5.8+ with BTF support
- Privileged container or root access (needed for eBPF)
- ~100MB RAM for the daemon
- Optional: ~2GB for the AI model if you want that

## API Endpoints

Cognitod runs on port 3000:

- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `GET /processes` - All live processes
- `GET /graph/:pid` - Process ancestry graph
- `GET /stream` - Server-sent events (real-time)
- `GET /insights` - AI insights (if enabled)
- `GET /alerts` - Active alerts from rules engine

## LLM Integration (Optional)

Works with any OpenAI-compatible endpoint:

```bash
# Use included model
./setup-llm.sh

# Or bring your own
export LLM_ENDPOINT="http://localhost:8090/v1/chat/completions"
export LLM_MODEL="qwen2.5-7b"
linnix-reasoner --insights
```

Supports: llama.cpp, Ollama, vLLM, OpenAI, Anthropic, or anything with an OpenAI-compatible API.

## Configuration

Create `/etc/linnix/linnix.toml`:

```toml
[runtime]
offline = false  # Set true to disable external calls

[telemetry]
sample_interval_ms = 1000  # How often to sample CPU/memory

[rules]
enabled = true
config_path = "/etc/linnix/rules.yaml"

[api]
bind_address = "127.0.0.1:3000"

[llm]
endpoint = "http://localhost:8090/v1/chat/completions"
model = "qwen2.5-7b"
timeout_secs = 120
```

## Current Status

**What works well:**
- eBPF monitoring (stable, low overhead)
- Rules engine (catches common issues)
- Prometheus export
- Docker/Kubernetes monitoring

**What's rough:**
- AI detection is hit-or-miss (depends heavily on the model)
- No web UI yet (just APIs and CLI)
- Limited documentation
- Haven't tested beyond my own setups

**What's missing:**
- Multi-node management UI
- Better alerting integrations (working on PagerDuty, Slack)
- Historical data storage (currently in-memory only)
- More sophisticated correlation

## Installation from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/linnix-os/linnix.git
cd linnix
cargo xtask build-ebpf
cargo build --release

# Install binaries
sudo cp target/release/cognitod /usr/local/bin/
sudo cp target/release/linnix-cli /usr/local/bin/
sudo cp target/release/linnix-reasoner /usr/local/bin/
```

## Contributing

Contributions welcome! The code is mostly in Rust using the Aya framework for eBPF.

Have ideas or questions? Check out [GitHub Discussions](https://github.com/linnix-os/linnix/discussions) or see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.


## License

Apache License 2.0 - see [LICENSE](LICENSE)

eBPF programs are dual-licensed under GPL-2.0 OR MIT (eBPF requirement).

## Acknowledgments

Built with:
- [Aya](https://github.com/aya-rs/aya) - Rust eBPF framework
- [Tokio](https://tokio.rs/) - Async runtime
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) - BPF Type Format

---

**GitHub**: [github.com/linnix-os/linnix](https://github.com/linnix-os/linnix)
**Twitter**: [@parth21shah](https://twitter.com/parth21shah)
