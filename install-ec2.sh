#!/bin/bash
#
# Linnix One-Command AWS EC2 Installer
#
# This script installs and configures Linnix on a fresh AWS EC2 instance.
# Supports: Amazon Linux 2023, Ubuntu 22.04+, Debian 12+
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/install-ec2.sh | sudo bash
#   OR
#   wget -qO- https://raw.githubusercontent.com/linnix-os/linnix/main/install-ec2.sh | sudo bash
#
# For custom installation:
#   sudo bash install-ec2.sh [OPTIONS]
#
# Options:
#   --with-llm          Install LLM support for AI-powered insights
#   --skip-systemd      Don't enable/start systemd service
#   --dev               Install development dependencies for building from source
#   --port PORT         Set API server port (default: 3000)
#   --help              Show this help message
#

set -e  # Exit on error
set -o pipefail  # Catch errors in pipelines

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/linnix"
SHARE_DIR="/usr/local/share/linnix"
SYSTEMD_DIR="/etc/systemd/system"
LOG_DIR="/var/log/linnix"

LINNIX_VERSION="${LINNIX_VERSION:-latest}"
GITHUB_REPO="${GITHUB_REPO:-linnix-os/linnix}"
API_PORT="${API_PORT:-3000}"

# Flags
INSTALL_LLM=false
SKIP_SYSTEMD=false
DEV_MODE=false

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        echo -e "${RED}Error: Cannot detect OS${NC}"
        exit 1
    fi
}

# Print colored message
log() {
    local level=$1
    shift
    case $level in
        info)
            echo -e "${BLUE}[INFO]${NC} $*"
            ;;
        success)
            echo -e "${GREEN}[SUCCESS]${NC} $*"
            ;;
        warn)
            echo -e "${YELLOW}[WARN]${NC} $*"
            ;;
        error)
            echo -e "${RED}[ERROR]${NC} $*"
            ;;
    esac
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check kernel version and eBPF support
check_kernel() {
    log info "Checking kernel compatibility..."

    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    REQUIRED_VERSION="5.8"

    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$KERNEL_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
        log error "Kernel version $KERNEL_VERSION is too old. Minimum required: $REQUIRED_VERSION"
        exit 1
    fi

    # Check for BTF support
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        log warn "BTF support not found at /sys/kernel/btf/vmlinux"
        log warn "eBPF programs may not load correctly"
    fi

    log success "Kernel version $KERNEL_VERSION is compatible"
}

# Install system dependencies
install_dependencies() {
    log info "Installing system dependencies..."

    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq \
                curl \
                wget \
                ca-certificates \
                libelf1 \
                linux-headers-$(uname -r) \
                || apt-get install -y -qq linux-headers-generic

            if [ "$DEV_MODE" = true ]; then
                apt-get install -y -qq \
                    build-essential \
                    pkg-config \
                    libelf-dev \
                    clang \
                    llvm \
                    git
            fi
            ;;
        amzn|amazonlinux)
            yum install -y -q \
                curl \
                wget \
                ca-certificates \
                elfutils-libelf \
                kernel-headers \
                kernel-devel

            if [ "$DEV_MODE" = true ]; then
                yum install -y -q \
                    gcc \
                    make \
                    pkgconfig \
                    elfutils-libelf-devel \
                    clang \
                    llvm \
                    git
            fi
            ;;
        *)
            log error "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    log success "System dependencies installed"
}

# Install Rust (if dev mode)
install_rust() {
    if [ "$DEV_MODE" = false ]; then
        return
    fi

    log info "Installing Rust toolchain..."

    local rust_installed=false
    if command -v rustc &> /dev/null; then
        log info "Rust already installed: $(rustc --version)"
        rust_installed=true
    else
        # Install as non-root user if SUDO_USER is available
        if [ -n "$SUDO_USER" ]; then
            sudo -u "$SUDO_USER" bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
            export PATH="/home/$SUDO_USER/.cargo/bin:$PATH"
        else
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            export PATH="$HOME/.cargo/bin:$PATH"
        fi
    fi

    # Install eBPF build requirements
    log info "Installing eBPF build dependencies..."

    # Install nightly toolchain for eBPF
    if [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" bash -c "
            export PATH=\"/home/$SUDO_USER/.cargo/bin:\$PATH\"
            rustup install nightly-2024-12-10
            rustup component add rust-src --toolchain nightly-2024-12-10
            cargo install bpf-linker --version 0.9.13 --locked
        "
    else
        rustup install nightly-2024-12-10
        rustup component add rust-src --toolchain nightly-2024-12-10
        cargo install bpf-linker --version 0.9.13 --locked
    fi

    log success "Rust toolchain and eBPF dependencies installed"
}

# Download or build Linnix binaries
install_linnix_binaries() {
    log info "Installing Linnix binaries..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$SHARE_DIR"

    if [ "$DEV_MODE" = true ]; then
        # Build from source
        log info "Building from source..."

        TEMP_DIR=$(mktemp -d)
        cd "$TEMP_DIR"

        git clone "https://github.com/${GITHUB_REPO}.git" .

        # Build eBPF programs using xtask
        log info "Building eBPF programs..."
        cargo xtask build-ebpf --release

        # Copy eBPF artifacts
        cp target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf "$SHARE_DIR/"

        # Build userspace binaries
        log info "Building userspace binaries..."
        cargo build --release -p cognitod
        cargo build --release -p linnix-cli

        # Install binaries
        cp target/release/cognitod "$INSTALL_DIR/"
        cp target/release/linnix-cli "$INSTALL_DIR/"

        chmod +x "$INSTALL_DIR/cognitod"
        chmod +x "$INSTALL_DIR/linnix-cli"

        # Cleanup
        cd /
        rm -rf "$TEMP_DIR"
    else
        # Download pre-built binaries from GitHub releases
        log info "Downloading pre-built binaries (version: $LINNIX_VERSION)..."

        # Detect architecture
        ARCH=$(uname -m)
        case $ARCH in
            x86_64)
                ARCH_TAG="x86_64"
                ;;
            aarch64|arm64)
                ARCH_TAG="aarch64"
                ;;
            *)
                log error "Unsupported architecture: $ARCH"
                exit 1
                ;;
        esac

        # Download from GitHub releases
        RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${LINNIX_VERSION}"
        DOWNLOAD_URL="${RELEASE_URL}/linnix-${ARCH_TAG}-unknown-linux-gnu.tar.gz"

        log info "Downloading from: $DOWNLOAD_URL"

        # For now, since this is a new project, fall back to build mode
        log warn "Pre-built binaries not yet available, building from source..."
        DEV_MODE=true
        install_rust
        install_linnix_binaries
        return
    fi

    log success "Linnix binaries installed"
}

# Create configuration files
install_config() {
    log info "Setting up configuration..."

    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"

    # Download or create default config
    if [ "$DEV_MODE" = true ] && [ -f "configs/linnix.toml" ]; then
        cp configs/linnix.toml "$CONFIG_DIR/"
        [ -f configs/rules.yaml ] && cp configs/rules.yaml "$CONFIG_DIR/"
    else
        # Create minimal default config
        cat > "$CONFIG_DIR/linnix.toml" <<EOF
# Linnix Configuration
# Generated by install-ec2.sh

[runtime]
# Disable external HTTP requests in isolated environments
offline = true

[telemetry]
# Sampling interval for CPU/memory metrics (milliseconds)
sample_interval_ms = 1000

[probes]
# Enable high-overhead page fault tracing (disable for production)
enable_page_faults = false

[api]
# API server listen address
listen_addr = "0.0.0.0:${API_PORT}"

[reasoner]
# AI-powered insights (requires LLM setup)
enabled = ${INSTALL_LLM}
endpoint = "http://127.0.0.1:8090/v1/chat/completions"
model = "linnix-qwen-v1"

[prometheus]
# Prometheus metrics export
enabled = false
listen_addr = "0.0.0.0:9090"

[alerts]
# Alert destinations
apprise_urls = []
EOF
    fi

    log success "Configuration files created"
}

# Create systemd service
install_systemd_service() {
    if [ "$SKIP_SYSTEMD" = true ]; then
        log info "Skipping systemd service installation"
        return
    fi

    log info "Installing systemd service..."

    cat > "$SYSTEMD_DIR/linnix-cognitod.service" <<EOF
[Unit]
Description=Linnix eBPF Observability Daemon
Documentation=https://github.com/${GITHUB_REPO}
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/cognitod
Restart=on-failure
RestartSec=5s

# Environment
Environment="LINNIX_BPF_PATH=${SHARE_DIR}/linnix-ai-ebpf-ebpf"
Environment="LINNIX_KERNEL_BTF=/sys/kernel/btf/vmlinux"
Environment="RUST_LOG=info"
Environment="LLM_ENDPOINT=http://127.0.0.1:8090/v1/chat/completions"
Environment="LLM_MODEL=linnix-qwen-v1"

# Security
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_RESOURCE
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_RESOURCE
NoNewPrivileges=true

# Resources
LimitMEMLOCK=infinity
LimitNOFILE=65536

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=linnix-cognitod

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    log success "Systemd service installed"
}

# Configure firewall
configure_firewall() {
    log info "Configuring firewall for port ${API_PORT}..."

    # Check if ufw is available (Ubuntu/Debian)
    if command -v ufw &> /dev/null; then
        if ufw status | grep -q "Status: active"; then
            ufw allow ${API_PORT}/tcp comment "Linnix API"
            log success "UFW firewall rule added"
        fi
    fi

    # Check if firewall-cmd is available (Amazon Linux/RHEL)
    if command -v firewall-cmd &> /dev/null; then
        if firewall-cmd --state &> /dev/null; then
            firewall-cmd --permanent --add-port=${API_PORT}/tcp
            firewall-cmd --reload
            log success "firewalld rule added"
        fi
    fi
}

# Install LLM support (optional)
install_llm() {
    if [ "$INSTALL_LLM" = false ]; then
        return
    fi

    log info "Installing LLM support..."
    log warn "LLM installation requires 2-4GB of disk space and memory"

    # Install ollama or llama.cpp
    # This is a placeholder - actual implementation would download and setup LLM
    log info "Please manually set up LLM service on port 8090"
    log info "See: https://github.com/${GITHUB_REPO}/docs/llm-setup.md"
}

# Start service
start_service() {
    if [ "$SKIP_SYSTEMD" = true ]; then
        log info "Skipping service start (use --skip-systemd)"
        log info "To start manually: sudo ${INSTALL_DIR}/cognitod"
        return
    fi

    log info "Starting Linnix service..."

    systemctl enable linnix-cognitod
    systemctl start linnix-cognitod

    sleep 2

    if systemctl is-active --quiet linnix-cognitod; then
        log success "Linnix service is running"
    else
        log error "Failed to start Linnix service"
        log info "Check logs: journalctl -u linnix-cognitod -f"
        exit 1
    fi
}

# Verify installation
verify_installation() {
    log info "Verifying installation..."

    # Check binary
    if ! command -v cognitod &> /dev/null; then
        log error "cognitod binary not found in PATH"
        return 1
    fi

    # Check API endpoint
    sleep 3
    if curl -s "http://localhost:${API_PORT}/api/healthz" &> /dev/null; then
        log success "API server is responding"
    else
        log warn "API server not responding (it may still be starting up)"
    fi

    log success "Installation verified"
}

# Print summary
print_summary() {
    local instance_ip=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "INSTANCE_IP")

    echo ""
    echo -e "${GREEN}=====================================${NC}"
    echo -e "${GREEN}   Linnix Installation Complete!    ${NC}"
    echo -e "${GREEN}=====================================${NC}"
    echo ""
    echo -e "${BLUE}Service Status:${NC}"
    echo "  systemctl status linnix-cognitod"
    echo ""
    echo -e "${BLUE}View Logs:${NC}"
    echo "  journalctl -u linnix-cognitod -f"
    echo ""
    echo -e "${BLUE}API Endpoints:${NC}"
    echo "  Health Check: http://localhost:${API_PORT}/api/healthz"
    echo "  Dashboard:    http://localhost:${API_PORT}/"
    echo "  Processes:    http://localhost:${API_PORT}/api/processes"
    echo "  Metrics:      http://localhost:${API_PORT}/api/metrics"
    echo ""
    echo -e "${BLUE}Access from browser:${NC}"
    echo "  http://${instance_ip}:${API_PORT}/"
    echo ""
    echo -e "${YELLOW}Security Note:${NC}"
    echo "  Configure AWS Security Group to allow port ${API_PORT}"
    echo "  Or use SSH tunnel: ssh -L ${API_PORT}:localhost:${API_PORT} ec2-user@${instance_ip}"
    echo ""
    echo -e "${BLUE}CLI Usage:${NC}"
    echo "  linnix-cli --help"
    echo ""
    echo -e "${BLUE}Configuration:${NC}"
    echo "  Config file: ${CONFIG_DIR}/linnix.toml"
    echo "  Edit and reload: systemctl restart linnix-cognitod"
    echo ""

    if [ "$INSTALL_LLM" = true ]; then
        echo -e "${YELLOW}LLM Setup Required:${NC}"
        echo "  Complete LLM setup to enable AI-powered insights"
        echo ""
    fi
}

# Parse command line arguments
parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --with-llm)
                INSTALL_LLM=true
                ;;
            --skip-systemd)
                SKIP_SYSTEMD=true
                ;;
            --dev)
                DEV_MODE=true
                ;;
            --port)
                API_PORT="$2"
                shift
                ;;
            --help)
                grep "^#" "$0" | sed 's/^# \?//'
                exit 0
                ;;
            *)
                log error "Unknown option: $1"
                log info "Use --help for usage information"
                exit 1
                ;;
        esac
        shift
    done
}

# Main installation flow
main() {
    log info "Starting Linnix installation for AWS EC2..."
    echo ""

    parse_args "$@"
    check_root
    detect_os

    log info "Detected OS: $OS $OS_VERSION"
    log info "Kernel: $(uname -r)"
    log info "Architecture: $(uname -m)"
    echo ""

    check_kernel
    install_dependencies
    install_rust
    install_linnix_binaries
    install_config
    install_systemd_service
    configure_firewall
    install_llm
    start_service
    verify_installation

    echo ""
    print_summary

    log success "Installation complete!"
}

# Run main function
main "$@"
