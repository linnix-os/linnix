# LLM Installation Guide for AWS EC2

## Quick Answer: Do I need Docker?

**No!** You can install the LLM natively without Docker using `install-llm-native.sh`.

## Installation Options

### Option 1: Native Installation (Recommended for EC2)

**Best for:** Production EC2 deployments, resource-constrained instances

**Advantages:**
- No Docker daemon overhead (~500MB RAM saved)
- Faster startup (10-20s vs 30-60s)
- Integrates with systemd like your existing cognitod installation
- Better performance with native CPU optimizations

**Installation on EC2:**

```bash
# Clone or pull the repo
cd /tmp
git clone https://github.com/linnix-os/linnix.git
cd linnix

# Run the native installer
sudo ./install-llm-native.sh
```

This will:
- Build llama.cpp from source with CMake
- Download the Linnix 3B distilled model (2.1GB)
- Create a systemd service `linnix-llm.service`
- Start the LLM server on port 8090

**Verification:**

```bash
# Check service status
sudo systemctl status linnix-llm.service

# Test health endpoint
curl http://localhost:8090/health

# Test inference
curl http://localhost:8090/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "linnix-3b-distilled",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

**Resource Usage:**
- Disk: ~3GB (2.1GB model + llama.cpp build)
- RAM: 2-4GB (depends on model loading)
- CPU: 4 threads by default (configurable)

---

### Option 2: Docker Installation

**Best for:** Local development, quick demos, consistent environments

**Requirements:**
- Docker and Docker Compose installed
- At least 4GB RAM available

**Installation:**

```bash
# Install Docker first
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in for group changes

# Run the setup script
cd linnix
./setup-llm.sh
```

This runs the full stack (cognitod, LLM, dashboard) in Docker containers.

**Note:** This replaces your native cognitod installation with a containerized one.

---

## Integration with Cognitod

Both options expose the LLM server on `http://localhost:8090/v1/chat/completions`.

Your cognitod installation (from `install-ec2.sh`) is pre-configured to use this endpoint via the `LLM_ENDPOINT` environment variable in the systemd service.

**Check integration:**

```bash
# View cognitod config
sudo systemctl cat linnix-cognitod.service | grep LLM_ENDPOINT

# Should show:
# Environment="LLM_ENDPOINT=http://127.0.0.1:8090/v1/chat/completions"
```

Once the LLM server is running, cognitod will automatically send events for AI analysis.

---

## Troubleshooting

### Native Installation Issues

**Build fails:**
```bash
# Check build dependencies
cmake --version  # Should be >= 3.10
gcc --version    # Should be >= 7.0

# View build logs
sudo journalctl -u linnix-llm.service -f
```

**Model download fails:**
```bash
# Manual download with retry
cd /var/lib/linnix/models
sudo wget --continue https://huggingface.co/parth21shah/linnix-3b-distilled/resolve/main/linnix-3b-distilled-q5_k_m.gguf
```

**Service won't start:**
```bash
# Check service logs
sudo journalctl -u linnix-llm.service -n 50

# Common issues:
# - Model file not found: Check /var/lib/linnix/models/
# - Port 8090 in use: netstat -tulpn | grep 8090
# - Memory limit: Adjust MemoryMax in /etc/systemd/system/linnix-llm.service
```

### Docker Installation Issues

**Port conflicts:**
```bash
# Check if ports are available
netstat -tulpn | grep -E ':(3000|8080|8090)'

# Stop conflicting services
sudo systemctl stop linnix-cognitod  # If using native cognitod
```

**Docker daemon not running:**
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

---

## Comparison Table

| Feature | Native | Docker |
|---------|--------|--------|
| Installation time | 10-15 min (build from source) | 5-10 min (pull images) |
| Disk space | ~3GB | ~4GB |
| RAM overhead | None | +200-300MB |
| Startup time | 10-20s | 30-60s |
| Updates | Rebuild llama.cpp | `docker pull` |
| Integration | Systemd services | Docker Compose |
| Resource control | Systemd directives | Docker limits |
| Best for | Production EC2 | Local dev |

---

## Recommended Setup for EC2

For production EC2 deployments, we recommend:

1. **Use native installation for both cognitod and LLM**
   - Run `install-ec2.sh` first (already done)
   - Then run `install-llm-native.sh`
   - Both managed via systemd

2. **Resource allocation:**
   - t3.medium minimum (2 vCPU, 4GB RAM)
   - t3.large recommended (2 vCPU, 8GB RAM)
   - m6a.large for production (2 vCPU, 8GB RAM, better performance)

3. **Security:**
   - Open ports: 3000 (API), 8090 (LLM) in Security Group
   - Consider restricting 8090 to localhost only if not needed externally
   - Both services run as root (required for eBPF)

4. **Monitoring:**
   ```bash
   # Watch both services
   watch -n 2 'systemctl status linnix-cognitod linnix-llm --no-pager'

   # Monitor resource usage
   htop
   ```

---

## Next Steps

After installation:

1. **Test the dashboard:** `http://<ec2-public-ip>:3000`
2. **View AI insights:** `curl http://localhost:3000/insights`
3. **Check process monitoring:** `curl http://localhost:3000/processes`
4. **Monitor logs:** `sudo journalctl -f -u linnix-cognitod -u linnix-llm`

The AI model will analyze your system events every 30-60 seconds and provide insights through the dashboard and API.
