# Getting Started

## Prerequisites

- Linux kernel 5.4+ (5.8+ recommended)
- Docker and Docker Compose (for quick start)
- Or: Rust toolchain (for building from source)

## Quick Start with Docker

```bash
git clone https://github.com/linnix-os/linnix.git
cd linnix
./quickstart.sh
```

This starts:
- **cognitod** on port 3000 (dashboard & API)
- **llama-server** on port 8090 (local LLM)

## Quick Start on Kubernetes

```bash
kubectl apply -f k8s/
kubectl port-forward svc/linnix-dashboard 3000:3000
```

Open http://localhost:3000

## Verify Installation

```bash
# Health check
curl http://localhost:3000/healthz
# Expected: {"status":"ok","version":"..."}

# System status
curl http://localhost:3000/status | jq

# Real-time events
curl -N http://localhost:3000/stream
```

## First Steps

1. **Watch the dashboard**: Open http://localhost:3000
2. **Generate activity**: Run `stress --cpu 2 --timeout 10`
3. **View insights**: `curl http://localhost:3000/insights | jq`
4. **Use the CLI**: `linnix-cli doctor`

## Next Steps

- [Configuration Guide](Configuration-Guide) - Customize settings
- [API Reference](API-Reference) - Full endpoint documentation
- [Safety Model](Safety-Model) - Understand guarantees

---
*Source: `README.md`, `quickstart.sh`*
