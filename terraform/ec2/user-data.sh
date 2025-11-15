#!/bin/bash
#
# User data script for Linnix EC2 instance
# This script runs automatically when the instance launches
#

set -e

# Log output to file
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "========================================="
echo "Starting Linnix installation..."
echo "Time: $(date)"
echo "========================================="

# Wait for system to be ready
sleep 30

# Download and run installation script
GITHUB_REPO="${github_repo}"
INSTALL_OPTIONS="${install_llm}"

if [ "${enable_prometheus}" = "true" ]; then
    # Enable Prometheus in config (will be handled by install script)
    export ENABLE_PROMETHEUS=true
fi

# Download install script
curl -fsSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/install-ec2.sh" -o /tmp/install-ec2.sh

# Make executable
chmod +x /tmp/install-ec2.sh

# Run installation
if [ -n "$INSTALL_OPTIONS" ]; then
    /tmp/install-ec2.sh $INSTALL_OPTIONS --port ${linnix_port}
else
    /tmp/install-ec2.sh --port ${linnix_port}
fi

# Update Prometheus config if enabled
if [ "${enable_prometheus}" = "true" ]; then
    cat >> /etc/linnix/linnix.toml <<EOF

[prometheus]
enabled = true
listen_addr = "0.0.0.0:9090"
EOF
    systemctl restart linnix-cognitod
fi

echo "========================================="
echo "Linnix installation completed!"
echo "Time: $(date)"
echo "========================================="

# Signal completion (optional - for CloudFormation/ASG)
# If using CloudFormation, you can signal success here
# cfn-signal -e $? --stack STACK_NAME --resource RESOURCE_ID --region REGION
