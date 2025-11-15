#!/bin/bash
#
# Linnix First Boot Configuration Script
# This script runs once on the first boot of an AMI instance
#

set -e

FIRST_BOOT_FLAG="/var/lib/linnix/first-boot-completed"

# Check if already run
if [ -f "$FIRST_BOOT_FLAG" ]; then
    echo "First boot already completed, skipping..."
    exit 0
fi

echo "========================================="
echo "Linnix First Boot Configuration"
echo "Time: $(date)"
echo "========================================="

# Create flag directory
mkdir -p "$(dirname "$FIRST_BOOT_FLAG")"

# Regenerate SSH host keys
echo "Regenerating SSH host keys..."
sudo rm -f /etc/ssh/ssh_host_*
sudo dpkg-reconfigure openssh-server

# Get instance metadata (if available)
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
INSTANCE_TYPE=$(curl -s http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null || echo "unknown")

echo "Instance ID: $INSTANCE_ID"
echo "Instance Type: $INSTANCE_TYPE"
echo "Availability Zone: $AVAILABILITY_ZONE"

# Update configuration with instance-specific values if needed
if [ -f /etc/linnix/linnix.toml ]; then
    echo "Linnix configuration already exists"
else
    if [ -f /etc/linnix/templates/linnix.toml.template ]; then
        echo "Creating configuration from template..."
        cp /etc/linnix/templates/linnix.toml.template /etc/linnix/linnix.toml
    fi
fi

# Enable and start Linnix service
echo "Enabling Linnix service..."
sudo systemctl enable linnix-cognitod

echo "Starting Linnix service..."
sudo systemctl start linnix-cognitod

# Wait for service to start
sleep 5

# Check service status
if sudo systemctl is-active --quiet linnix-cognitod; then
    echo "Linnix service started successfully"
else
    echo "Warning: Linnix service failed to start, check logs with: journalctl -u linnix-cognitod"
fi

# Mark first boot as completed
echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" > "$FIRST_BOOT_FLAG"
echo "Instance ID: $INSTANCE_ID" >> "$FIRST_BOOT_FLAG"

echo "========================================="
echo "First boot configuration completed!"
echo "========================================="

exit 0
