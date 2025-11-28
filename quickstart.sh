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

# Detect compose command (v1 or v2) and add macOS override if needed
detect_compose() {
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif docker-compose --version &> /dev/null; then
        echo -e "${YELLOW}⚠️  Detected legacy 'docker-compose' (V1). Upgrade to 'docker compose' (V2) for better stability.${NC}"
        COMPOSE_CMD="docker-compose"
    else
        echo -e "${RED}❌ Neither 'docker compose' nor 'docker-compose' found.${NC}"
        echo "   Please install Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    # Detect macOS and add override file for network compatibility
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if [ -f "docker-compose.darwin.yml" ]; then
            COMPOSE_CMD="$COMPOSE_CMD -f docker-compose.yml -f docker-compose.darwin.yml"
            echo -e "${BLUE}ℹ️  Detected macOS - using network override (bridge mode)${NC}"
            echo "   Note: eBPF will monitor Docker VM processes only, not macOS processes."
            echo ""
        fi
    fi
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
    detect_compose
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

# Check for and download the LLM model file if needed
check_model() {
    echo -e "\n${BLUE}[2/5]${NC} Checking for demo model..."
    local model_path="./models/linnix-3b-distilled-q5_k_m.gguf"
    local model_url="https://huggingface.co/parth21shah/linnix-3b-distilled/resolve/main/linnix-3b-distilled-q5_k_m.gguf"
    
    if [ -f "$model_path" ]; then
        echo -e "${GREEN}✅ Model already downloaded.${NC}"
    else
        mkdir -p ./models
        echo -e "${YELLOW}⚠️  Demo model not found. Downloading now (2.1GB)...${NC}"
        echo "   This may take a few minutes depending on your connection."
        
        # Try wget first, then curl
        if command -v wget &> /dev/null; then
            if wget --show-progress -q -O "$model_path" "$model_url"; then
                echo -e "${GREEN}✅ Model downloaded successfully.${NC}"
            else
                echo -e "${RED}❌ Download failed. Please check your internet connection.${NC}"
                echo "   You can manually download from: $model_url"
                exit 1
            fi
        elif command -v curl &> /dev/null; then
            if curl -L --progress-bar -o "$model_path" "$model_url"; then
                echo -e "${GREEN}✅ Model downloaded successfully.${NC}"
            else
                echo -e "${RED}❌ Download failed. Please check your internet connection.${NC}"
                echo "   You can manually download from: $model_url"
                exit 1
            fi
        else
            echo -e "${RED}❌ Neither wget nor curl found. Cannot download model.${NC}"
            echo "   Please install wget or curl, or manually download from: $model_url"
            exit 1
        fi
    fi
}

# Check if required ports are available
check_ports() {
    echo -e "\n${BLUE}[3/5]${NC} Checking port availability..."
    local ports_in_use=()
    local required_ports=(3000 8090)
    
    for port in "${required_ports[@]}"; do
        if command -v lsof &> /dev/null; then
            if lsof -i ":$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
                ports_in_use+=("$port")
            fi
        elif command -v ss &> /dev/null; then
            if ss -tlnp 2>/dev/null | grep -q ":$port "; then
                ports_in_use+=("$port")
            fi
        elif command -v netstat &> /dev/null; then
            if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
                ports_in_use+=("$port")
            fi
        fi
    done
    
    if [ ${#ports_in_use[@]} -gt 0 ]; then
        echo -e "${RED}❌ The following required ports are already in use:${NC}"
        for port in "${ports_in_use[@]}"; do
            echo -e "   ${RED}•${NC} Port $port"
            echo -e "     Find process: ${YELLOW}lsof -i :$port${NC} or ${YELLOW}ss -tlnp | grep :$port${NC}"
        done
        echo ""
        echo -e "${YELLOW}To fix this:${NC}"
        echo "   1. Stop the conflicting service(s)"
        echo "   2. Or run: ./quickstart.sh stop (to stop any existing Linnix containers)"
        echo "   3. Then try starting Linnix again"
        exit 1
    else
        echo -e "${GREEN}✅ All required ports are available.${NC}"
    fi
}

# Create a default configuration if one doesn't exist
setup_config() {
    echo -e "\n${BLUE}[4/5]${NC} Setting up configuration..."
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
    echo -e "\n${BLUE}[5/5]${NC} Starting Docker containers..."
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
    check_ports
    setup_config
    start_services
    wait_for_health
    show_summary
}

main "$@"
