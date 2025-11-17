#!/bin/bash
# Linnix Quick Start Script
# Gets you from zero to AI-powered insights in < 5 minutes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║   🚀  Linnix Quick Start                                   ║"
echo "║   eBPF Monitoring + AI Incident Detection                 ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Check prerequisites
echo -e "${BLUE}[1/6]${NC} Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found${NC}"
    echo "   Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
    echo -e "${RED}❌ Docker Compose not found${NC}"
    echo "   Install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# Determine compose command
if docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

echo -e "${GREEN}✅ Docker and Compose installed${NC}"

# Ensure docker-compose (v1) can talk to the local Docker socket
if [ "$COMPOSE_CMD" = "docker-compose" ]; then
    echo "   Detected docker-compose v1 (Python CLI)"
    if ! command -v python3 > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  python3 not found. Install python3 to let docker-compose talk to Docker (${NC}sudo apt install python3${YELLOW}).${NC}"
        exit 1
    fi

    if ! python3 -m pip --version > /dev/null 2>&1; then
        echo -e "${RED}❌ pip for python3 not found.${NC}"
        echo "   Install pip: sudo apt install python3-pip"
        exit 1
    fi

    if python3 - <<'PY' > /dev/null 2>&1
import re
import sys
from itertools import zip_longest
try:
    import requests
except ModuleNotFoundError:
    sys.exit(1)

def needs_pin(current, ceiling="2.32.0"):
    def parse(v):
        nums = [int(x) for x in re.findall(r'\d+', v)]
        return nums

    cur = parse(current)
    cap = parse(ceiling)
    for a, b in zip_longest(cur, cap, fillvalue=0):
        if a > b:
            return True
        if a < b:
            return False
    return True  # equal

sys.exit(0 if needs_pin(requests.__version__) else 1)
PY
    then
        echo -e "${YELLOW}   ⚠️ requests >= 2.32 detected (Compose v1 incompatibility). Pinning to <2.32...${NC}"
        if python3 -m pip install --user 'requests<2.32' > /dev/null; then
            echo -e "${GREEN}   ✅ requests pinned to a Compose-compatible version${NC}"
        else
            echo -e "${RED}❌ Failed to pin requests automatically.${NC}"
            echo "   Try: python3 -m pip install --user 'requests<2.32'"
            exit 1
        fi
    else
        echo -e "${GREEN}   ✅ requests version compatible${NC}"
    fi

    if python3 - <<'PY' > /dev/null 2>&1
import importlib
import sys
sys.exit(0 if importlib.util.find_spec("requests_unixsocket") else 1)
PY
    then
        echo -e "${GREEN}   ✅ requests-unixsocket already installed${NC}"
    else
        echo -e "${YELLOW}   📦 Installing requests-unixsocket so docker-compose can reach Docker...${NC}"
        if python3 -m pip install --user requests-unixsocket; then
            echo -e "${GREEN}   ✅ Installed requests-unixsocket${NC}"
        else
            echo -e "${RED}❌ Failed to install requests-unixsocket automatically.${NC}"
            echo "   Try: python3 -m pip install --user requests-unixsocket"
            exit 1
        fi
    fi
fi

# Check if running as root or in docker group
if ! docker ps &> /dev/null; then
    echo -e "${YELLOW}⚠️  Docker requires elevated permissions${NC}"
    echo "   Either run with sudo or add your user to docker group:"
    echo "   $ sudo usermod -aG docker \$USER && newgrp docker"
    exit 1
fi

# Check kernel version for eBPF
KERNEL_VERSION=$(uname -r | cut -d. -f1)
if [ "$KERNEL_VERSION" -lt 5 ]; then
    echo -e "${YELLOW}⚠️  Kernel version $(uname -r) detected${NC}"
    echo "   eBPF works best on Linux 5.0+. You may experience limited functionality."
    read -p "   Continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}✅ Kernel $(uname -r) supports eBPF${NC}"
fi


if [ ! -d "/sys/kernel/btf" ]; then
    echo -e "${YELLOW}⚠️  BTF not found at /sys/kernel/btf${NC}"
    echo "   Cognitod will run in degraded mode (no per-process CPU/mem metrics)"
    echo "   To enable BTF: Upgrade kernel or install linux-headers"
else
    echo -e "${GREEN}✅ BTF available for dynamic telemetry${NC}"
fi

# Step 2: Download demo model
echo ""
echo -e "${BLUE}[2/6]${NC} Checking for demo model..."

MODEL_PATH="./models/linnix-3b-distilled-q5_k_m.gguf"
MODEL_SIZE="2.1GB"

if [ -f "$MODEL_PATH" ]; then
    echo -e "${GREEN}✅ Model already downloaded${NC}"
else
    mkdir -p ./models
    echo -e "${YELLOW}📥 Demo model not found. Will be downloaded on first container start.${NC}"
    echo "   Size: $MODEL_SIZE (may take 2-5 minutes)"
    echo "   Alternatively, download manually:"
    echo "   $ wget https://github.com/linnix-os/linnix/releases/download/v0.1.0/linnix-3b-distilled-q5_k_m.gguf -P ./models"
fi

# Step 3: Create default config if missing
echo ""
echo -e "${BLUE}[3/6]${NC} Setting up configuration..."

mkdir -p ./configs

if [ ! -f "./configs/linnix.toml" ]; then
    cat > ./configs/linnix.toml << 'EOF'
# Linnix Configuration
# Documentation: https://docs.linnix.io/configuration

[runtime]
# Offline mode: disable external HTTP requests (Slack, PagerDuty, etc.)
offline = false

[telemetry]
# Sample interval for CPU/memory metrics (milliseconds)
sample_interval_ms = 1000

# Event retention window (seconds)
retention_seconds = 60

[probes]
# Page fault tracing (high overhead - disabled by default)
enable_page_faults = false

[reasoner]
# AI-powered incident detection
enabled = true
endpoint = "http://llama-server:8090/v1/chat/completions"
model = "linnix-3b-distilled"
window_seconds = 30
timeout_ms = 30000

[prometheus]
# Prometheus metrics endpoint
enabled = true
EOF
    echo -e "${GREEN}✅ Created default config at ./configs/linnix.toml${NC}"
else
    echo -e "${GREEN}✅ Using existing config${NC}"
fi

# Step 4: Pull/build Docker images
echo ""
echo -e "${BLUE}[4/6]${NC} Starting Docker containers..."
echo "   This will:"
echo "   - Pull cognitod and llama-cpp images (or build if needed)"
echo "   - Download demo model (2.1GB) if not present"
echo "   - Start monitoring services"
echo ""

$COMPOSE_CMD up -d || {
    echo -e "${YELLOW}⚠️  Compose failed on first attempt; attempting recovery...${NC}"
    LAST_ERR=$(mktemp)
    if ! $COMPOSE_CMD up -d 2>"$LAST_ERR"; then
        if grep -q "ContainerConfig" "$LAST_ERR" || grep -q "KeyError" "$LAST_ERR"; then
            echo -e "   Detected ContainerConfig KeyError from docker-compose. Trying to remove LLM image and retry..."
            if sudo docker image rm -f ghcr.io/ggerganov/llama.cpp:server > /dev/null 2>&1; then
                echo "   Removed stale LLM image"
            fi
            if $COMPOSE_CMD up -d; then
                echo -e "${GREEN}✅ Compose started after removing LLM image${NC}"
                rm -f "$LAST_ERR"
            else
                echo -e "${YELLOW}⚠️  Compose still failing. Falling back to manual LLM start and partial compose.${NC}"
                LLM_MODEL_PATH="$(pwd)/models/linnix-3b-distilled-q5_k_m.gguf"
                echo "   Starting llama-server manually (docker run)..."
                sudo docker run -d --name linnix-llm --restart unless-stopped \
                    -v "$(pwd)/models:/models:ro" -p 8090:8090 ghcr.io/ggerganov/llama.cpp:server \
                    --host 0.0.0.0 --port 8090 -m /models/$(basename "$LLM_MODEL_PATH") \
                    --alias linnix-3b-distilled --ctx-size 4096 -t 4 --log-disable || true
                sleep 2
                echo "   Bringing up remaining services (cognitod, dashboard) via compose..."
                if $COMPOSE_CMD up -d cognitod dashboard; then
                    echo -e "${GREEN}✅ Remaining services started${NC}"
                else
                    echo -e "${RED}❌ Failed to start remaining services via compose.${NC}"
                    echo "   Inspect compose output or try 'docker compose up -d' if available."
                    echo "   Last compose error:";
                    sed -n '1,200p' "$LAST_ERR" || true
                    rm -f "$LAST_ERR"
                    exit 1
                fi
            fi
        else
            echo -e "${RED}❌ docker-compose failed with an unexpected error.${NC}"
            echo "   Last compose output:";
            sed -n '1,200p' "$LAST_ERR" || true
            rm -f "$LAST_ERR"
            exit 1
        fi
    fi
}

# Step 5: Wait for services to be healthy
echo ""
echo -e "${BLUE}[5/6]${NC} Waiting for services to start..."

# Wait for cognitod
echo -n "   Cognitod: "
for i in {1..30}; do
    if curl -sf http://localhost:3000/healthz > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Running${NC}"
        break
    fi
    echo -n "."
    sleep 1
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ Timeout${NC}"
        echo "   Check logs: $COMPOSE_CMD logs cognitod"
        exit 1
    fi
done

# Wait for llama-server (may take longer due to model download)
echo -n "   LLM Server: "
for i in {1..120}; do
    if curl -sf http://localhost:8090/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Running${NC}"
        break
    fi
    echo -n "."
    sleep 1
    if [ $i -eq 120 ]; then
        echo -e "${RED}❌ Timeout${NC}"
        echo "   Check logs: $COMPOSE_CMD logs llama-server"
        exit 1
    fi
done

# Step 6: Success!
echo ""
echo -e "${BLUE}[6/6]${NC} Testing AI analysis..."

# Test linnix-reasoner
if command -v cargo &> /dev/null; then
    echo ""
    echo "Running AI analysis (this may take 10-15 seconds)..."
    export LLM_ENDPOINT="http://localhost:8090/v1/chat/completions"
    export LLM_MODEL="linnix-3b-distilled"
    cargo run --release -p linnix-reasoner 2>/dev/null || {
        echo -e "${YELLOW}⚠️  Rust not installed. Run reasoner with Docker:${NC}"
        echo "   $ docker run --rm --network=host linnixos/linnix-cli linnix-reasoner"
    }
else
    echo -e "${YELLOW}⚠️  Rust not installed. Skipping reasoner test.${NC}"
fi

# Success message
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║   🎉  Linnix is running!                                   ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Services:${NC}"
echo "   • Cognitod (monitoring):    http://localhost:3000"
echo "   • LLM Server:               http://localhost:8090"
echo "   • Prometheus metrics:       http://localhost:3000/metrics/prometheus"
echo ""
echo -e "${GREEN}Quick Commands:${NC}"
echo "   • View status:      $COMPOSE_CMD ps"
echo "   • View logs:        $COMPOSE_CMD logs -f"
echo "   • Get AI insights:  curl http://localhost:3000/insights"
echo "   • Stream events:    curl http://localhost:3000/stream"
echo "   • Stop services:    $COMPOSE_CMD down"
echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo "   1. Open http://localhost:3000/status in browser"
echo "   2. Try: curl http://localhost:3000/insights | jq"
echo "   3. Install CLI: cargo install --path linnix-cli"
echo "   4. Read docs: https://docs.linnix.io"
echo ""
echo -e "${BLUE}Time to first insight: $(date +%s) seconds${NC}"
echo ""
