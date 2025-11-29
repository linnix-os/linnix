#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Linnix Agent Installer${NC}"
echo "======================"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root.${NC}"
  exit 1
fi

# 2. Check OS
if [[ "$(uname -s)" != "Linux" ]]; then
    echo -e "${RED}Error: Linnix only supports Linux.${NC}"
    exit 1
fi

# 3. Check Kernel Version (Simple check, can be improved)
KERNEL_VERSION=$(uname -r)
MAJOR_VERSION=$(echo "$KERNEL_VERSION" | cut -d. -f1)
MINOR_VERSION=$(echo "$KERNEL_VERSION" | cut -d. -f2)

echo -n "Checking Kernel ($KERNEL_VERSION)... "
if [ "$MAJOR_VERSION" -lt 5 ] || ([ "$MAJOR_VERSION" -eq 5 ] && [ "$MINOR_VERSION" -lt 8 ]); then
    echo -e "${YELLOW}Warning: Kernel 5.8+ recommended for CO-RE. You may need to compile from source.${NC}"
else
    echo -e "${GREEN}OK${NC}"
fi

# 4. Check BTF
echo -n "Checking BTF Support... "
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}Error: /sys/kernel/btf/vmlinux not found. Please enable CONFIG_DEBUG_INFO_BTF.${NC}"
    exit 1
fi

# 5. Install Directories
echo "Setting up directories..."
mkdir -p /etc/linnix
mkdir -p /var/lib/linnix
mkdir -p /usr/local/bin

# 6. Install Binary (Mock for now - usually curl download)
# In a real script: curl -L https://.../cognitod -o /usr/local/bin/cognitod
if [ -f "./target/release/cognitod" ]; then
    echo "Installing local binary..."
    cp ./target/release/cognitod /usr/local/bin/cognitod
    chmod +x /usr/local/bin/cognitod
else
    echo -e "${YELLOW}Binary not found in ./target/release. Skipping binary install (assuming dev mode or manual install).${NC}"
fi

# 7. Create Systemd Service
echo "Creating systemd service..."
cat <<EOF > /etc/systemd/system/cognitod.service
[Unit]
Description=Linnix Agent (Cognitod)
After=network.target

[Service]
ExecStart=/usr/local/bin/cognitod
Restart=always
User=root
Environment=RUST_LOG=info
WorkingDirectory=/var/lib/linnix

[Install]
WantedBy=multi-user.target
EOF

# 8. Reload Daemon
systemctl daemon-reload
echo -e "${GREEN}Installation Complete!${NC}"
echo "Run 'systemctl start cognitod' to start the agent."
