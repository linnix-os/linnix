# Linnix Quick Start 🚀

**eBPF-powered Linux observability with AI insights in under 5 minutes**

## One-Command Setup

```bash
# Clone and start Linnix
git clone https://github.com/your-org/linnix-opensource.git
cd linnix-opensource
./setup-llm.sh
```

That's it! The script will:
- ✅ Check prerequisites (Docker, Linux with BTF)
- ⬇️ Download the AI model (2GB)
- 🚀 Start all services with Docker Compose
- 🔍 Validate everything is healthy
- 🌐 Show you the URLs to access

## What You Get

- **Real-time Process Monitoring**: See every fork, exec, exit with CPU/memory telemetry
- **AI-Powered Insights**: LLM detects fork storms, CPU spins, resource leaks automatically
- **Web Dashboard**: Beautiful interface at `http://localhost:8080`
- **Live Event Stream**: Real-time process events via Server-Sent Events
- **REST API**: Full programmatic access to all data

## Try the Demo

Once setup is complete, generate some interesting system activity:

```bash
./demo-workload.sh
```

This creates realistic workloads (CPU spikes, memory allocation, process spawning, file I/O) for the AI to analyze.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Dashboard │◄───┤    cognitod     │◄───┤   eBPF Probes   │
│  (Port 8080)    │    │  (Port 3000)    │    │   (Kernel)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │
         ▼                        ▼
┌─────────────────┐    ┌─────────────────┐
│  llama-server   │    │ linnix-reasoner │
│  (Port 8087)    │    │  (Background)   │
└─────────────────┘    └─────────────────┘
```

## Quick Commands

```bash
# Check service status
docker-compose ps

# View live events
curl -N http://localhost:3000/stream

# Get current processes
curl http://localhost:3000/processes | jq

# See AI insights
curl http://localhost:3000/insights | jq

# System health
curl http://localhost:3000/healthz

# Stop everything
docker-compose down
```

## Troubleshooting

**Services won't start?**
```bash
# Check prerequisites
./setup-llm.sh --check-only

# View logs
docker-compose logs cognitod
docker-compose logs llama-server
```

**No eBPF data?**
- Ensure you're on Linux with BTF support: `ls -la /sys/kernel/btf/vmlinux`
- Run with privileges: `sudo ./setup-llm.sh` (if needed)

**AI model download failed?**
- Check internet connection
- Verify disk space (needs 2GB)
- Retry: `./setup-llm.sh --force-download`

**Docker Compose can't talk to Docker (`http+docker` error)?**
- Pin Python Requests to a Compose-compatible version:  
  ```bash
  python3 -m pip install --user 'requests<2.32'
  python3 -m pip install --user requests-unixsocket
  ```
- Re-run `./setup-llm.sh`

## What's Next?

1. **Explore the Dashboard**: Click around, watch the real-time updates
2. **Run the Demo**: `./demo-workload.sh` to see AI detection in action
3. **Check the API**: All data is available via REST endpoints
4. **Generate Load**: Run your own workloads and see what the AI catches
5. **Customize**: Edit `docker-compose.yml` to adjust configuration

## Learn More

- 📖 **Full Documentation**: [docs/](docs/)
- 🏗️ **Architecture Deep Dive**: [docs/architecture.md](docs/architecture.md)  
- 🔧 **Configuration Guide**: [configs/](configs/)
- 🤝 **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- 💬 **Community**: [Discord](https://discord.gg/linnix) | [GitHub Discussions](https://github.com/your-org/linnix-opensource/discussions)

---

**Built with ❤️ using eBPF, Rust, and AI**

*Linnix makes Linux observability accessible with zero-instrumentation monitoring and intelligent incident detection.*
