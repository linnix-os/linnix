#!/bin/bash
# Linnix LLM Native Installation for EC2
# Installs llama.cpp server without Docker for lightweight deployment
#
# Usage:
#   sudo ./install-llm-native.sh
#
# This script:
# - Builds llama.cpp from source with optimizations
# - Downloads Linnix 3B distilled model
# - Creates systemd service for LLM inference server
# - Configures to work with existing cognitod installation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_step() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Configuration
INSTALL_DIR="/opt/linnix"
MODEL_DIR="/var/lib/linnix/models"
LLAMA_DIR="/opt/llama.cpp"
MODEL_FILE="linnix-3b-distilled-q5_k_m.gguf"
MODEL_URL="https://huggingface.co/parth21shah/linnix-3b-distilled/resolve/main/$MODEL_FILE"

print_header "Linnix LLM Native Installation"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_VERSION=$VERSION_ID
    print_info "Detected OS: $PRETTY_NAME"
else
    print_error "Cannot detect OS version"
    exit 1
fi

# Install build dependencies
print_info "Installing build dependencies..."
if [[ "$OS_ID" == "ubuntu" ]] || [[ "$OS_ID" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y \
        build-essential \
        git \
        cmake \
        curl \
        libcurl4-openssl-dev \
        wget
elif [[ "$OS_ID" == "amzn" ]]; then
    yum groupinstall -y "Development Tools"
    yum install -y \
        git \
        cmake3 \
        curl \
        libcurl-devel \
        wget
    # Create cmake symlink for Amazon Linux
    if [ ! -f /usr/bin/cmake ]; then
        ln -s /usr/bin/cmake3 /usr/bin/cmake
    fi
else
    print_error "Unsupported OS: $OS_ID"
    exit 1
fi
print_step "Build dependencies installed"

# Clone and build llama.cpp
print_info "Building llama.cpp from source..."
if [ -d "$LLAMA_DIR" ]; then
    print_info "llama.cpp already exists, pulling latest changes..."
    cd "$LLAMA_DIR"
    git pull
else
    git clone https://github.com/ggerganov/llama.cpp.git "$LLAMA_DIR"
    cd "$LLAMA_DIR"
fi

# Build with CMake (llama.cpp switched from Makefile to CMake)
# Use all available CPU cores
NPROC=$(nproc)
print_info "Building with $NPROC CPU cores using CMake..."

# Clean previous build
rm -rf build 2>/dev/null || true

# Create build directory and configure with CMake
mkdir -p build
cd build

# Configure CMake with optimizations
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLAMA_BUILD_SERVER=ON \
    -DLLAMA_NATIVE=ON

# Build server binary
cmake --build . --config Release --target llama-server -j"$NPROC"

if [ ! -f "$LLAMA_DIR/build/bin/llama-server" ]; then
    print_error "llama-server build failed"
    exit 1
fi

# Copy binary to main llama.cpp directory for easier access
cp "$LLAMA_DIR/build/bin/llama-server" "$LLAMA_DIR/llama-server"

print_step "llama.cpp built successfully"

# Create directories
print_info "Creating directories..."
mkdir -p "$MODEL_DIR"
mkdir -p "$INSTALL_DIR"
print_step "Directories created"

# Download model
print_info "Downloading Linnix 3B AI model (2.1GB)..."
print_info "This may take 5-15 minutes depending on your connection..."

if [ -f "$MODEL_DIR/$MODEL_FILE" ]; then
    print_step "Model already exists: $MODEL_DIR/$MODEL_FILE"
    ls -lh "$MODEL_DIR/$MODEL_FILE"
else
    # Try wget first, fallback to curl
    if command -v wget &> /dev/null; then
        if wget --show-progress -O "$MODEL_DIR/$MODEL_FILE" "$MODEL_URL"; then
            print_step "Model downloaded successfully with wget"
        else
            print_error "Download failed with wget, trying curl..."
            curl -L --progress-bar "$MODEL_URL" -o "$MODEL_DIR/$MODEL_FILE"
        fi
    elif command -v curl &> /dev/null; then
        curl -L --progress-bar "$MODEL_URL" -o "$MODEL_DIR/$MODEL_FILE"
    else
        print_error "Neither wget nor curl found"
        exit 1
    fi

    # Verify download
    if [ -f "$MODEL_DIR/$MODEL_FILE" ] && [ -s "$MODEL_DIR/$MODEL_FILE" ]; then
        print_step "Model downloaded successfully"
        ls -lh "$MODEL_DIR/$MODEL_FILE"
    else
        print_error "Model download failed or file is empty"
        exit 1
    fi
fi

# Create systemd service
print_info "Creating systemd service..."

cat > /etc/systemd/system/linnix-llm.service <<EOF
[Unit]
Description=Linnix LLM Inference Server
Documentation=https://github.com/linnix-os/linnix
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$LLAMA_DIR
ExecStart=$LLAMA_DIR/llama-server \\
    --host 0.0.0.0 \\
    --port 8090 \\
    -m $MODEL_DIR/$MODEL_FILE \\
    --alias linnix-3b-distilled \\
    --ctx-size 4096 \\
    -t 4 \\
    --log-disable

Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Resource limits (adjust based on instance size)
MemoryMax=4G
CPUQuota=400%

[Install]
WantedBy=multi-user.target
EOF

print_step "Systemd service created"

# Enable and start service
print_info "Enabling and starting LLM service..."
systemctl daemon-reload
systemctl enable linnix-llm.service
systemctl restart linnix-llm.service

# Wait for service to start
print_info "Waiting for LLM server to start (this may take 30-60 seconds)..."
sleep 10

for i in {1..30}; do
    if systemctl is-active --quiet linnix-llm.service; then
        if curl -sf http://localhost:8090/health &>/dev/null; then
            print_step "LLM server is running and healthy!"
            break
        fi
    fi

    if [ $i -eq 30 ]; then
        print_error "LLM server failed to start"
        echo "Check logs with: sudo journalctl -u linnix-llm.service -f"
        exit 1
    fi

    sleep 2
    printf "."
done
echo

# Show status
print_header "Installation Complete!"
echo
print_step "LLM server is running on http://0.0.0.0:8090"
echo
echo -e "${BLUE}Service Status:${NC}"
systemctl status linnix-llm.service --no-pager -l
echo
echo -e "${BLUE}Quick Tests:${NC}"
echo "  • Health check:     curl http://localhost:8090/health"
echo "  • Test inference:   curl http://localhost:8090/v1/chat/completions -H 'Content-Type: application/json' -d '{\"model\":\"linnix-3b-distilled\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}'"
echo
echo -e "${BLUE}Management Commands:${NC}"
echo "  • View logs:        sudo journalctl -u linnix-llm.service -f"
echo "  • Stop service:     sudo systemctl stop linnix-llm.service"
echo "  • Start service:    sudo systemctl start linnix-llm.service"
echo "  • Restart service:  sudo systemctl restart linnix-llm.service"
echo "  • Service status:   sudo systemctl status linnix-llm.service"
echo
echo -e "${BLUE}Resource Usage:${NC}"
echo "  • Memory limit:     4GB (adjust in /etc/systemd/system/linnix-llm.service)"
echo "  • CPU threads:      4 (adjust with -t parameter)"
echo "  • Model size:       2.1GB (quantized Q5_K_M)"
echo
echo -e "${BLUE}Integration:${NC}"
echo "  • Cognitod API:     http://localhost:3000"
echo "  • LLM API:          http://localhost:8090"
echo "  • Dashboard:        Already embedded in cognitod at http://<ec2-ip>:3000"
echo
print_step "Installation successful! LLM server is ready for AI insights."
