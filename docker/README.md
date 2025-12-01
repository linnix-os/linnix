# Linnix Docker Quick Start

Get from zero to AI-powered Linux monitoring in **< 5 minutes** with Docker Compose.

## Prerequisites

- **Docker** 20.10+ ([install](https://docs.docker.com/get-docker/))
- **Docker Compose** 2.0+ ([install](https://docs.docker.com/compose/install/))
- **Linux** 5.0+ kernel (for eBPF support)
- **2GB RAM** minimum (4GB+ recommended for LLM)
- **5GB disk space** (for images + demo model)

## Quick Start

### Option 1: One-Line Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/quickstart.sh | bash
```

This script will:
1. ✅ Check prerequisites (Docker, kernel version, BTF)
2. 📥 Download demo model (2.1GB, one-time)
3. 🚀 Start cognitod + llama-server
4. ✅ Run health checks
5. 🎉 Show you your first AI insight!

### Option 2: Manual Setup

```bash
# Clone repository
git clone https://github.com/linnix-os/linnix.git
cd linnix

# Start services
docker-compose up -d

# Wait for services (30-60 seconds for first start)
docker-compose logs -f

# Test AI analysis
curl http://localhost:3000/insights | jq
```

## Services

After running `docker-compose up`, you'll have:

| Service | Port | Description |
|---------|------|-------------|
| **cognitod** | 3000 | eBPF monitoring daemon |
| **llama-server** | 8090 | 3B LLM for AI analysis |

## API Endpoints

### Cognitod (Port 3000)

```bash
# Health check
curl http://localhost:3000/healthz

# System status
curl http://localhost:3000/status | jq

# AI insights
curl http://localhost:3000/insights | jq

# Live process tree
curl http://localhost:3000/processes | jq

# Real-time event stream (SSE)
curl -N http://localhost:3000/stream

# Prometheus metrics
curl http://localhost:3000/metrics/prometheus
```

### LLM Server (Port 8090)

```bash
# Health check
curl http://localhost:8090/health

# Direct LLM query (OpenAI-compatible)
curl http://localhost:8090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "linnix-3b-distilled",
    "messages": [{"role": "user", "content": "Explain fork bombs"}],
    "max_tokens": 200
  }'
```

## Configuration

### Custom Config

Create `./configs/linnix.toml` (auto-created by quickstart.sh):

```toml
[runtime]
offline = false  # Disable external webhooks (Slack, PagerDuty)

[reasoner]
enabled = true
endpoint = "http://llama-server:8090/v1/chat/completions"
```

Changes take effect after restart:
```bash
docker-compose restart cognitod
```

### Environment Variables

Override in `docker-compose.yml` or `.env` file:

```bash
# Cognitod
RUST_LOG=debug                    # Log level: debug|info|warn|error
LINNIX_CONFIG=/etc/linnix/linnix.toml

# LLM Server
LLAMA_ARG_N_GPU_LAYERS=0          # 0 for CPU-only, >0 for GPU
```

## Troubleshooting

### Cognitod fails to start

**Symptom**: `docker-compose logs cognitod` shows eBPF load errors

**Solution**:
```bash
# Check kernel version
uname -r  # Should be 5.0+

# Check BTF
ls -la /sys/kernel/btf/vmlinux  # Should exist

# Try with --privileged
docker run --privileged --pid=host --network=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  linnixos/cognitod:latest
```

### Model download is slow

**Symptom**: `llama-server` container takes >5 minutes to start

**Solution**: Pre-download model manually
```bash
mkdir -p ./models
wget https://github.com/linnix-os/linnix/releases/download/v0.1.0/linnix-3b-distilled-q5_k_m.gguf \
  -O ./models/linnix-3b-distilled-q5_k_m.gguf

# Then restart
docker-compose up -d
```

### No AI insights returned

**Symptom**: `/insights` endpoint returns empty or generic responses

**Solution**:
```bash
# Check LLM server is healthy
curl http://localhost:8090/health

# Check logs
docker-compose logs llama-server

# Test LLM directly
curl -X POST http://localhost:8090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"linnix-3b-distilled","messages":[{"role":"user","content":"test"}]}'
```

### High CPU usage

**Symptom**: cognitod uses >10% CPU

**Possible causes**:
1. **High event rate** - Normal for busy systems (1000s of events/sec)
2. **Model inference** - llama-server is CPU-intensive during analysis

**Verify overhead**:
```bash
# Check cognitod self-reported metrics
curl http://localhost:3000/status | jq '.cpu_pct'

# Should be <1% when idle, <5% under load
```

## Performance

| Metric | Value |
|--------|-------|
| **Cognitod CPU** | <1% (idle), <5% (load) |
| **Cognitod Memory** | ~50MB |
| **LLM CPU** | 100% during inference (12.78 tok/s) |
| **LLM Memory** | ~2.3GB |
| **Events/sec** | 100-1000 (typical) |
| **Time to insight** | 5-15 seconds |

## Upgrading

```bash
# Pull latest images
docker-compose pull

# Restart services
docker-compose up -d

# Verify versions
curl http://localhost:3000/status | jq '.version'
```

## Uninstall

```bash
# Stop and remove containers
docker-compose down

# Remove volumes (persistent data)
docker-compose down -v

# Remove images
docker rmi linnixos/cognitod:latest linnixos/llama-cpp:latest
```

## Next Steps

1. **Install CLI**: `cargo install --path linnix-cli`
2. **Read Docs**: [github.com/linnix-os/linnix/tree/main/docs](https://github.com/linnix-os/linnix/tree/main/docs)
3. **Join Discord**: [github.com/linnix-os/linnix/discussions](https://github.com/linnix-os/linnix/discussions)
4. **Deploy to K8s**: See Kubernetes guide (coming soon)
5. **Integrate Alerts**: See Alerting setup (coming soon)

## Architecture

```
┌────────────────────────────────────────────────────┐
│  Linux Kernel (eBPF probes)                        │
│  - fork/exec/exit hooks                            │
│  - CPU/memory sampling                             │
└─────────────────┬──────────────────────────────────┘
                  │ Perf buffers
                  ▼
┌─────────────────────────────────────────────────────┐
│  Cognitod (container: privileged, host network)     │
│  - Event processing                                 │
│  - Process tree tracking                            │
│  - HTTP/SSE API (port 3000)                         │
└─────────────────┬───────────────────────────────────┘
                  │ HTTP
                  ▼
┌─────────────────────────────────────────────────────┐
│  LLM Server (container: llama-cpp)                  │
│  - 3B distilled model (CPU inference)               │
│  - OpenAI-compatible API (port 8090)                │
│  - 12.78 tok/s on CPU                               │
└─────────────────────────────────────────────────────┘
```

## Production Deployment

For production use:

1. **Use tagged releases** (not `latest`):
   ```yaml
   image: linnixos/cognitod:v0.1.0
   ```

2. **Enable Prometheus scraping**:
   ```yaml
   prometheus:
     enabled: true
   ```

3. **Configure resource limits**:
   ```yaml
   services:
     cognitod:
       deploy:
         resources:
           limits:
             cpus: '2'
             memory: 1G
   ```

4. **Enable persistent storage**:
   ```yaml
   volumes:
     - /var/lib/linnix:/var/lib/linnix
   ```

5. **Set up alerts** (Slack, PagerDuty) in `configs/linnix.toml`

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup.

## License

AGPL-3.0 (open source)

---

**Need help?** Open an [issue](https://github.com/linnix-os/linnix/issues) or ask in [Discord](https://github.com/linnix-os/linnix/discussions)
