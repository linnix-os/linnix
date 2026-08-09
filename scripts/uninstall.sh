#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root.${NC}"
  exit 1
fi

# Allow overrides for testing/packaging
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/linnix}"
SERVICE_DIR="${SERVICE_DIR:-/etc/systemd/system}"
DATA_DIR="${DATA_DIR:-/var/lib/linnix}"

echo "Uninstalling Linnix..."

# Disable service if present
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now cognitod.service || true
  systemctl daemon-reload || true
fi

rm -f "${SERVICE_DIR}/cognitod.service"
rm -f "${BIN_DIR}/cognitod"
rm -f "${CONFIG_DIR}/linnix.toml"

# Leave DATA_DIR intact (logs/state) to avoid data loss.

echo "Uninstall complete."
