#!/bin/bash
# Linnix Quick Start Script
# Starts Linnix with Docker Compose

set -e

# --- Configuration ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Globals ---
COMPOSE_CMD=""
ACTION="start"

# --- Functions ---

# Display a banner for the script
banner() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║   Linnix Quick Start                                       ║"
    echo "║   eBPF System Monitoring                                   ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
}

# Parse command-line arguments
parse_args() {
    for arg in "$@"; do
        case "$arg" in
            stop|down)
                ACTION="stop"
                ;;
            --help|-h)
                echo "Usage: $0 [start|stop|--help|-h]"
                echo "  start (default):    Start services with automatic demo scenarios."
                echo "  stop:               Stop all running Linnix services."
                echo ""
                echo "Demo scenarios (run automatically on startup):"
                echo "  1. Fork storm       - Rapid process spawning detection"
                echo "  2. Short jobs       - Exec/exit cycle monitoring"
                echo "  3. Runaway tree     - High CPU parent+child processes"
                echo "  4. CPU spike        - Sustained high CPU detection"
                echo "  5. Memory leak      - Gradual RSS growth pattern"
                echo ""
                echo "For production use, comment out the 'command:' line in docker-compose.yml"
                exit 0
                ;;
        esac
    done
}

# Check for all necessary prerequisites
check_prerequisites() {
    echo -e "${BLUE}[1/5]${NC} Checking prerequisites..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker not found. Please install it: https://docs.docker.com/get-docker/${NC}"
        exit 1
    fi

    # Check Docker Compose
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
        echo -e "${YELLOW}⚠️  Detected legacy 'docker-compose' (V1). Upgrade to 'docker compose' (V2) for better stability.${NC}"
    else
        echo -e "${RED}❌ Docker Compose not found. Please install it: https://docs.docker.com/compose/install/${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Docker and Docker Compose are installed.${NC}"

    # Check Docker permissions
    if ! docker ps &> /dev/null; then
        echo -e "${RED}❌ Docker permissions error. Your user cannot connect to the Docker daemon.${NC}"
        echo "   Fix by running: sudo usermod -aG docker $USER && newgrp docker"
        exit 1
    fi
    echo -e "${GREEN}✅ Docker permissions are correct.${NC}"

    # Check kernel version and BTF support
    local kernel_version
    kernel_version=$(uname -r)
    if [[ "$(echo "$kernel_version" | cut -d. -f1)" -lt 5 ]]; then
        echo -e "${YELLOW}⚠️  Kernel version $kernel_version is older than 5.0. eBPF features may be limited.${NC}"
    else
        echo -e "${GREEN}✅ Kernel version $kernel_version supports eBPF.${NC}"
    fi

    if [ ! -d "/sys/kernel/btf" ]; then
        echo -e "${YELLOW}⚠️  BTF not found. Linnix will run in degraded mode (no per-process CPU/mem metrics).${NC}"
        echo "   To enable BTF, consider upgrading your kernel or installing linux-headers."
    else
        echo -e "${GREEN}✅ BTF is available for dynamic telemetry.${NC}"
    fi
}

# Check for the LLM model file
check_model() {
    echo -e "\n${BLUE}[2/5]${NC} Checking for demo model..."
    local model_path="./models/linnix-3b-distilled-q5_k_m.gguf"
    if [ -f "$model_path" ]; then
        echo -e "${GREEN}✅ Model already downloaded.${NC}"
    else
        mkdir -p ./models
        echo -e "${YELLOW}⚠️  Demo model not found. It will be downloaded when containers start (2.1GB).${NC}"
    fi
}

# Create a default configuration if one doesn't exist
setup_config() {
    echo -e "\n${BLUE}[3/5]${NC} Setting up configuration..."
    mkdir -p ./configs
    if [ ! -f "./configs/linnix.toml" ]; then
        cat > ./configs/linnix.toml << 'EOF'
# Linnix Configuration
[runtime]
offline = false
[telemetry]
sample_interval_ms = 1000
retention_seconds = 60
[probes]
enable_page_faults = false
[reasoner]
enabled = true
endpoint = "http://llama-server:8090/v1/chat/completions"
model = "linnix-3b-distilled"
window_seconds = 30
timeout_ms = 30000
min_eps_to_enable = 0
[prometheus]
enabled = true
EOF
        echo -e "${GREEN}✅ Created default config at ./configs/linnix.toml${NC}"
    else
        echo -e "${GREEN}✅ Using existing config file.${NC}"
    fi

    if [ ! -f "./configs/rules.yaml" ]; then
        if [ -f "./configs/rules.yaml.example" ]; then
            cp "./configs/rules.yaml.example" "./configs/rules.yaml"
            echo -e "${GREEN}✅ Created rules.yaml from example.${NC}"
        else
            echo -e "${YELLOW}⚠️  No rules.yaml found. Using default rules from container.${NC}"
        fi
    else
        echo -e "${GREEN}✅ Using existing rules.yaml${NC}"
    fi
}

# Start all Docker containers
start_services() {
    echo -e "\n${BLUE}[4/5]${NC} Starting Docker containers..."
    echo "   This will pull required images and start all services."
    if ! $COMPOSE_CMD up -d; then
        echo -e "${RED}❌ Docker Compose failed to start.${NC}"
        echo "   Please check the logs for errors:"
        $COMPOSE_CMD logs --tail=50
        exit 1
    fi
}

# Wait for services to become healthy
wait_for_health() {
    echo -e "\n${BLUE}[5/5]${NC} Waiting for services to become healthy..."
    echo -n "   Cognitod: "
    for i in {1..30}; do
        if curl -sf http://localhost:3000/healthz > /dev/null; then
            echo -e "${GREEN}✅ Running${NC}"
            break
        fi
        echo -n "." && sleep 1
        if [ $i -eq 30 ]; then
            echo -e "${RED}❌ Timeout. Check logs: $COMPOSE_CMD logs cognitod${NC}"
            exit 1
        fi
    done

    echo -n "   LLM Server: "
    for i in {1..180}; do # Increased timeout for model download
        if curl -sf http://localhost:8090/health > /dev/null; then
            echo -e "${GREEN}✅ Running${NC}"
            break
        fi
        echo -n "." && sleep 1
        if [ $i -eq 180 ]; then
            echo -e "${RED}❌ Timeout. Check logs: $COMPOSE_CMD logs llama-server${NC}"
            exit 1
        fi
    done
}

# Display a summary of commands and next steps
show_summary() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║   Linnix is running                                        ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${GREEN}Services:${NC}"
    echo "   • Dashboard & API:          http://localhost:3000"
    echo "   • LLM Server:               http://localhost:8090"
    echo "   • Prometheus Metrics:       http://localhost:3000/metrics/prometheus"
    echo ""
    echo -e "${GREEN}Quick Commands:${NC}"
    echo "   • Watch alerts:             curl -N http://localhost:3000/stream"
    echo "   • Get LLM insights:         curl http://localhost:3000/insights | jq"
    echo "   • View all logs:            $COMPOSE_CMD logs -f"
    echo "   • Stop services:            ./quickstart.sh stop"
    echo ""
    echo -e "${YELLOW}Note:${NC} Demo mode is disabled by default"
    echo "      To enable, uncomment the 'command:' line in docker-compose.yml"
    echo ""
}

# Stop and remove all services
stop_services() {
    echo -e "${BLUE}Stopping all Linnix services...${NC}"
    if ! $COMPOSE_CMD down; then
        echo -e "${RED}❌ Failed to stop services. Please check Docker.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Services stopped and removed.${NC}"
}

# --- Main Execution ---
main() {
    parse_args "$@"
    
    # Determine compose command early for stop action
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi

    if [ "$ACTION" = "stop" ]; then
        stop_services
        exit 0
    fi

    banner
    check_prerequisites
    check_model
    setup_config
    start_services
    wait_for_health
    show_summary
}

main "$@"
