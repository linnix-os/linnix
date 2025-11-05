#!/bin/bash
# Linnix Quick Setup - 5-minute eBPF monitoring with AI
# 
# This script sets up the complete Linnix stack:
# - Cognitod (eBPF monitoring daemon)
# - LLM Server (AI insights)
# - Web Dashboard (visualization)

set -e

# Change to script directory to ensure we're in the right place
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "${BLUE}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${NC}"
}

print_step() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check if running on Linux
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        print_error "Linnix requires Linux. Current OS: $OSTYPE"
        exit 1
    fi
    
    # Check for Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is required but not installed."
        echo "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Check for Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is required but not installed."
        echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running or not accessible."
        echo "Please start Docker daemon or add your user to the docker group."
        exit 1
    fi
    
    # Check for root/sudo (needed for eBPF)
    if [[ $EUID -ne 0 ]] && ! groups | grep -q docker; then
        print_warning "eBPF requires privileged access. You may need sudo for Docker commands."
    fi
    
    print_step "Prerequisites check completed"
}

# Download AI model
download_model() {
    print_info "Setting up AI model..."
    
    # Create models directory
    mkdir -p models
    cd models
    
    # Model configuration
    MODEL_FILE="linnix-3b-distilled-q5_k_m.gguf"
    MODEL_URL="https://huggingface.co/parth21shah/linnix-3b-distilled/resolve/main/$MODEL_FILE"
    
    if [ -f "$MODEL_FILE" ]; then
        print_step "AI model already downloaded: $MODEL_FILE"
        ls -lh "$MODEL_FILE"
    else
        print_info "Downloading Linnix 3B AI model (2.1GB)..."
        echo "   Source: Hugging Face Hub"
        echo "   This may take 5-15 minutes depending on your connection..."
        echo
        
        # Try wget first, fallback to curl
        if command -v wget &> /dev/null; then
            if wget --show-progress "$MODEL_URL"; then
                print_step "Model downloaded successfully with wget"
            else
                print_error "Download failed with wget, trying curl..."
                curl -L --progress-bar "$MODEL_URL" -o "$MODEL_FILE"
            fi
        elif command -v curl &> /dev/null; then
            curl -L --progress-bar "$MODEL_URL" -o "$MODEL_FILE"
        else
            print_error "Neither wget nor curl found. Please install one and try again."
            echo
            echo "On Ubuntu/Debian: sudo apt install wget curl"
            echo "On CentOS/RHEL: sudo yum install wget curl"
            exit 1
        fi
        
        # Verify download
        if [ -f "$MODEL_FILE" ] && [ -s "$MODEL_FILE" ]; then
            print_step "AI model downloaded successfully!"
            ls -lh "$MODEL_FILE"
        else
            print_error "Model download failed or file is empty"
            exit 1
        fi
    fi
    
    cd ..
}

# Start services
start_services() {
    print_info "Starting Linnix services..."
    
    # Pull latest images first
    print_info "Pulling latest Docker images..."
    docker-compose pull
    
    # Start services
    print_info "Starting Docker containers..."
    docker-compose up -d
    
    print_step "Services started successfully"
}

# Health checks
wait_for_services() {
    print_info "Waiting for services to be healthy..."
    
    # Wait for cognitod
    print_info "Checking cognitod (eBPF daemon)..."
    for i in {1..30}; do
        if curl -sf http://localhost:3000/healthz &>/dev/null; then
            print_step "Cognitod is healthy"
            break
        fi
        if [ $i -eq 30 ]; then
            print_error "Cognitod failed to start after 5 minutes"
            echo "Check logs with: docker-compose logs cognitod"
            exit 1
        fi
        sleep 10
        printf "."
    done
    
    # Wait for LLM server
    print_info "Checking AI model server..."
    for i in {1..60}; do
        if curl -sf http://localhost:8090/health &>/dev/null; then
            print_step "AI model server is healthy"
            break
        fi
        if [ $i -eq 60 ]; then
            print_warning "AI model server taking longer than expected (this is normal on first start)"
            echo "The model server may still be loading. Check status at http://localhost:8090/health"
            break
        fi
        sleep 10
        printf "."
    done
    
    # Check dashboard
    print_info "Checking web dashboard..."
    for i in {1..10}; do
        if curl -sf http://localhost:8080 &>/dev/null; then
            print_step "Web dashboard is ready"
            break
        fi
        if [ $i -eq 10 ]; then
            print_error "Web dashboard failed to start"
            echo "Check logs with: docker-compose logs dashboard"
        fi
        sleep 5
    done
    
    echo
}

# Show service status
show_status() {
    print_info "Service status:"
    docker-compose ps
    echo
    
    print_info "Container resource usage:"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" || true
}

# Display success information
show_success() {
    print_header "🎉 Linnix Setup Complete!"
    
    echo -e "${GREEN}Your eBPF monitoring with AI is now running!${NC}"
    echo
    echo -e "${BLUE}📊 Access Points:${NC}"
    echo "  • Web Dashboard:    http://localhost:8080"
    echo "  • API Endpoints:    http://localhost:3000"
    echo "  • AI Model Server:  http://localhost:8090"
    echo
    echo -e "${BLUE}🧪 Quick Tests:${NC}"
    echo "  • System health:    curl http://localhost:3000/healthz"
    echo "  • Live processes:   curl http://localhost:3000/processes"
    echo "  • AI insights:      curl http://localhost:3000/insights"
    echo "  • Performance:      curl http://localhost:3000/metrics"
    echo
    echo -e "${BLUE}📱 Web Dashboard Features:${NC}"
    echo "  • Real-time process monitoring"
    echo "  • Live event stream (eBPF)"
    echo "  • AI-powered incident detection"
    echo "  • Performance metrics"
    echo
    echo -e "${BLUE}🛠️ Management Commands:${NC}"
    echo "  • View logs:        docker-compose logs -f"
    echo "  • Stop services:    docker-compose down"
    echo "  • Restart:          docker-compose restart"
    echo "  • Update:           git pull && docker-compose pull && docker-compose up -d"
    echo
    echo -e "${BLUE}📚 Documentation:${NC}"
    echo "  • GitHub:           https://github.com/linnix-os/linnix"
    echo "  • Documentation:    https://docs.linnix.io"
    echo "  • AI Model:         https://huggingface.co/parth21shah/linnix-3b-distilled"
    echo
    echo -e "${YELLOW}💡 Pro Tips:${NC}"
    echo "  • The AI model analyzes your system every 30 seconds"
    echo "  • eBPF monitoring has <1% CPU overhead"
    echo "  • Dashboard updates in real-time"
    echo "  • All data stays local - no external API calls"
    echo
    print_step "Setup completed successfully! Open http://localhost:8080 to get started."
}

# Cleanup on exit
cleanup() {
    if [ $? -ne 0 ]; then
        echo
        print_error "Setup failed! Check the error messages above."
        echo
        echo "Common issues:"
        echo "  • Docker not running: sudo systemctl start docker"
        echo "  • Permission issues: sudo usermod -aG docker \$USER (then logout/login)"
        echo "  • Port conflicts: Check if ports 3000, 8080, 8090 are available"
        echo "  • Download issues: Check internet connection and try again"
        echo
        echo "For help:"
        echo "  • GitHub Issues: https://github.com/linnix-os/linnix/issues"
        echo "  • Discord: https://discord.gg/linnix"
    fi
}

trap cleanup EXIT

# Main execution
main() {
    print_header "🐧 Linnix Setup - eBPF Monitoring with AI"
    
    echo "This script will set up:"
    echo "  • Cognitod - eBPF monitoring daemon"
    echo "  • AI Model - 3B parameter model for incident detection"
    echo "  • Web Dashboard - Real-time visualization"
    echo
    print_warning "Note: This requires ~2.5GB download and 4GB RAM"
    echo
    
    # Ask for confirmation
    read -p "Continue with setup? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
    
    # Execute setup steps
    check_prerequisites
    download_model  
    start_services
    wait_for_services
    show_status
    show_success
}

# Run main function
main "$@"
