# Linnix

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

**eBPF-powered Linux observability with AI incident detection**

Linnix captures every process fork, exec, and exit with lightweight CPU/memory telemetry using eBPF, then uses AI to detect incidents before they become outages.

## 🎯 Why Linnix?

- **⚡ Zero Overhead**: <1% CPU usage with eBPF probes
- **🧠 AI-Powered**: LLM-based incident detection and classification
- **💰 Cost-Effective**: 60-80% cheaper than Datadog or Dynatrace
- **🔓 Open Source**: Apache-2.0 license, run anywhere
- **🚀 Production-Ready**: Battle-tested on multi-node clusters

## ⚡ Quick Start (5 Minutes)

```bash
# 1. Install cognitod
curl -sfL https://linnix.io/install.sh | sh

# 2. Start monitoring
sudo systemctl start cognitod

# 3. Stream live events
linnix-cli stream

# 4. Get AI insights (requires LLM endpoint)
export LLM_ENDPOINT="http://localhost:8090/v1/chat/completions"
export LLM_MODEL="qwen2.5-7b"
linnix-reasoner --insights
```

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Kernel Space (eBPF)                       │
├──────────────────────────────────────────────────────────────┤
│  fork hook  →  exec hook  →  exit hook  →  CPU/mem sampling │
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
   │ Stream  │    │ AI       │   │ Grafana     │
   └─────────┘    └──────────┘   └─────────────┘
```

## 📊 Features

| Feature | Community (Free) | Enterprise |
|---------|-----------------|------------|
| eBPF monitoring | ✅ | ✅ |
| Real-time event streaming | ✅ | ✅ |
| Process tree tracking | ✅ | ✅ |
| CPU/memory telemetry | ✅ | ✅ |
| Local rules engine | ✅ | ✅ |
| Prometheus integration | ✅ | ✅ |
| LLM inference (BYO model) | ✅ | ✅ |
| 50 training examples | ✅ | ✅ |
| Custom model training platform | ❌ | ✅ |
| 500+ training records | ❌ | ✅ |
| Dataset expansion tools | ❌ | ✅ |
| SSO/RBAC | ❌ | ✅ |
| 24/7 support | ❌ | ✅ |

[Learn more about Enterprise →](https://linnix.io/pricing)

## 🚀 Installation

### Docker (Recommended)

```bash
docker run -d \
  --name cognitod \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  linnixos/cognitod:latest
```

### From Package

**Ubuntu/Debian:**
```bash
wget https://github.com/linnix-os/linnix/releases/latest/download/cognitod_amd64.deb
sudo dpkg -i cognitod_amd64.deb
sudo systemctl start cognitod
```

**RHEL/CentOS:**
```bash
wget https://github.com/linnix-os/linnix/releases/latest/download/cognitod.rpm
sudo rpm -i cognitod.rpm
sudo systemctl start cognitod
```

### From Source

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone repository
git clone https://github.com/linnix-os/linnix.git
cd linnix

# Build eBPF programs
cargo xtask build-ebpf

# Build and install
cargo build --release
sudo cp target/release/cognitod /usr/local/bin/
sudo cp target/release/linnix-cli /usr/local/bin/
sudo cp target/release/linnix-reasoner /usr/local/bin/
```

## 📚 Documentation

- [Getting Started](docs/getting-started.md) - Installation and first steps
- [Architecture](docs/architecture.md) - System design and components
- [API Reference](docs/api-reference.md) - HTTP endpoints and SSE
- [LLM Integration](docs/llm-integration.md) - How to bring your own LLM
- [Configuration](docs/configuration.md) - Config file reference
- [Troubleshooting](docs/troubleshooting.md) - Common issues

Full documentation: [docs.linnix.io](https://docs.linnix.io)

## 🔌 API Endpoints

Cognitod exposes a REST API on port 3000:

- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `GET /processes` - All live processes
- `GET /graph/:pid` - Process ancestry graph
- `GET /stream` - Server-sent events (real-time)
- `GET /insights` - AI-generated insights
- `GET /alerts` - Active alerts from rules engine

See [API Reference](docs/api-reference.md) for details.

## 🤖 LLM Integration

Linnix works with any OpenAI-compatible LLM endpoint:

```bash
# Option 1: Local model with llama.cpp
./llama-server -m qwen2.5-7b-instruct-q5_k_m.gguf --port 8090

# Option 2: vLLM
vllm serve Qwen/Qwen2.5-7B-Instruct --port 8090

# Option 3: Ollama
ollama serve qwen2.5:7b

# Configure endpoint
export LLM_ENDPOINT="http://localhost:8090/v1/chat/completions"
export LLM_MODEL="qwen2.5-7b"

# Get insights
linnix-reasoner --insights
```

You can also use commercial APIs (OpenAI, Anthropic, etc.) by pointing to their endpoints.

## 🔧 Configuration

Create `/etc/linnix/linnix.toml`:

```toml
[runtime]
offline = false  # Set true to disable external HTTP calls

[telemetry]
sample_interval_ms = 1000  # CPU/memory sampling frequency

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

## 🎓 Examples

### Stream events in real-time

```bash
# CLI streaming
linnix-cli stream

# Or use curl with SSE
curl -N http://localhost:3000/stream
```

### Get process tree

```bash
# For a specific PID
curl http://localhost:3000/graph/1234 | jq .

# All processes
curl http://localhost:3000/processes | jq .
```

### Detect incidents with AI

```bash
# Get AI-generated insights
linnix-reasoner --insights

# Output:
# {
#   "summary": "System experiencing high CPU due to fork storm...",
#   "risks": ["cpu_spin", "fork_storm"]
# }
```

### Configure custom rules

Edit `/etc/linnix/rules.yaml`:

```yaml
rules:
  - name: fork_storm
    condition: "forks_per_sec > 100"
    severity: critical
    actions:
      - alert
      - log

  - name: cpu_spike
    condition: "process.cpu_percent > 95 AND duration > 60"
    severity: warning
    actions:
      - alert
```

## 🤝 Contributing

We love contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feat/amazing-feature`)
3. **Make your changes**
4. **Run tests** (`cargo test --workspace`)
5. **Commit** (`git commit -m 'Add amazing feature'`)
6. **Push** (`git push origin feat/amazing-feature`)
7. **Open a Pull Request**

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Development Setup

```bash
# Clone repo
git clone https://github.com/linnix-os/linnix.git
cd linnix

# Install dependencies
cargo build --workspace

# Build eBPF programs
cargo xtask build-ebpf

# Run tests
cargo test --workspace

# Run clippy
cargo clippy --all-targets -- -D warnings
```

## 🐛 Bug Reports

Found a bug? Please [open an issue](https://github.com/linnix-os/linnix/issues/new) with:
- Your OS and kernel version
- Cognitod version (`cognitod --version`)
- Steps to reproduce
- Expected vs actual behavior

## 📝 License

Linnix is licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) for details.

### Third-Party Licenses

Linnix uses several open source libraries. See [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) for details.

### eBPF Code

The eBPF programs in `linnix-ai-ebpf/linnix-ai-ebpf-ebpf/` are dual-licensed under **GPL-2.0 OR MIT** (eBPF programs must be GPL-compatible).

## 🌟 Star History

If you find Linnix useful, please star the repo! It helps us grow the community.

[![Star History Chart](https://api.star-history.com/svg?repos=linnix-os/linnix&type=Date)](https://star-history.com/#linnix-os/linnix&Date)

## 💬 Community

- **Discord**: [Join our server](https://discord.gg/linnix) (coming soon)
- **Twitter**: [@linnixhq](https://twitter.com/linnixhq)
- **Blog**: [blog.linnix.io](https://blog.linnix.io)
- **Discussions**: [GitHub Discussions](https://github.com/linnix-os/linnix/discussions)

## 🏢 Enterprise

Need custom training, SSO, or 24/7 support? Check out [Linnix Enterprise](https://linnix.io/pricing).

Features:
- Custom LLM training on your incidents
- 500+ curated training records
- Dataset expansion tools
- Multi-tenancy
- SSO/RBAC
- Service-level agreements
- Dedicated support engineer

Contact: sales@linnix.io

## 🙏 Acknowledgments

Linnix is built on the shoulders of giants:

- [Aya](https://github.com/aya-rs/aya) - Rust eBPF framework
- [Tokio](https://tokio.rs/) - Async runtime
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) - BPF Type Format

Special thanks to the eBPF community for making kernel observability accessible!

## 📖 Citations

If you use Linnix in research, please cite:

```bibtex
@software{linnix2025,
  author = {Shah, Parth},
  title = {Linnix: eBPF-powered Linux observability with AI},
  year = {2025},
  url = {https://github.com/linnix-os/linnix}
}
```

---

**Made with ❤️ by the Linnix team**

[Website](https://linnix.io) • [Docs](https://docs.linnix.io) • [Blog](https://blog.linnix.io) • [Twitter](https://twitter.com/linnixhq)
