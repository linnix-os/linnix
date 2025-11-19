# AWS EC2 Deployment Guide for Linnix

Complete guide for deploying Linnix eBPF observability platform on AWS EC2 instances.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start (One-Command Install)](#quick-start-one-command-install)
- [Step-by-Step Manual Installation](#step-by-step-manual-installation)
- [EC2 Instance Configuration](#ec2-instance-configuration)
- [Security Group Setup](#security-group-setup)
- [Post-Installation Configuration](#post-installation-configuration)
- [Accessing the Dashboard](#accessing-the-dashboard)
- [Monitoring and Logs](#monitoring-and-logs)
- [Troubleshooting](#troubleshooting)
- [Advanced Deployment Options](#advanced-deployment-options)

---

## Prerequisites

### AWS Account Requirements
- Active AWS account with EC2 permissions
- SSH key pair for instance access
- VPC with public subnet (or private with VPN/bastion)

### Supported EC2 Instance Types
| Instance Type | vCPU | Memory | Use Case | Cost (approx.) |
|--------------|------|--------|----------|----------------|
| t3.small | 2 | 2 GB | Testing, dev | ~$15/month |
| t3.medium | 2 | 4 GB | Small prod | ~$30/month |
| t3.large | 2 | 8 GB | Production | ~$60/month |
| c6a.xlarge | 4 | 8 GB | High performance | ~$120/month |
| m6a.xlarge | 4 | 16 GB | With LLM support | ~$140/month |

### Supported Operating Systems
✅ **Ubuntu 22.04 LTS** (Recommended)
✅ **Ubuntu 24.04 LTS**
✅ **Amazon Linux 2023**
✅ **Debian 12**

### Kernel Requirements
- **Minimum Kernel:** 5.8+
- **Recommended Kernel:** 5.15+ (Ubuntu 22.04), 6.1+ (Amazon Linux 2023)
- **Required Features:**
  - eBPF support (CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y)
  - BTF support (CONFIG_DEBUG_INFO_BTF=y)
  - Kernel headers installed

---

## Quick Start (One-Command Install)

### Option 1: Direct Installation (Recommended)

SSH into your EC2 instance and run:

```bash
curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/docs/examples/install-ec2.sh | sudo bash
```

### Option 2: Download and Inspect First

```bash
# Download the script
wget https://raw.githubusercontent.com/linnix-os/linnix/main/docs/examples/install-ec2.sh

# Review the script
less install-ec2.sh

# Make it executable
chmod +x install-ec2.sh

# Run installation
sudo ./install-ec2.sh
```

### Installation Options

```bash
# Install for development (builds from source)
sudo ./install-ec2.sh --dev

# Custom API port
sudo ./install-ec2.sh --port 8080

# Skip systemd service (manual control)
sudo ./install-ec2.sh --skip-systemd
```

**Note:** The install-llm-native.sh script has been removed. Use `./quickstart.sh` instead for Docker-based deployment with LLM support.

**Requirements:**
- Minimum 16 GB disk space (5 GB for model + build artifacts)
- Minimum 4 GB RAM
- At least t3.medium instance recommended

For Docker-based LLM deployment, use `./quickstart.sh` which includes the LLM service.

### What the docs/examples/install-ec2.sh Script Does

1. ✅ Detects OS and validates kernel version (>= 5.8)
2. ✅ Installs system dependencies (libelf, kernel headers, OpenSSL)
3. ✅ Downloads or builds Linnix binaries
   - Installs Rust toolchain with eBPF support (nightly-2024-12-10)
   - Installs rust-src component and bpf-linker
   - Builds eBPF programs using `cargo xtask build-ebpf`
4. ✅ Installs eBPF programs to `/usr/local/share/linnix/`
5. ✅ Creates configuration files in `/etc/linnix/`
6. ✅ Sets up systemd service with proper capabilities
7. ✅ Configures cognitod to listen on 0.0.0.0:3000 for external access
8. ✅ Starts and enables the service
9. ✅ Verifies installation

**Installation Time:** 3-5 minutes (pre-built) or 10-15 minutes (build from source)

### LLM Support (via Docker)

1. ✅ Checks disk space (requires 5 GB minimum)
2. ✅ Installs build dependencies (CMake, curl, git)
3. ✅ Clones and builds llama.cpp from source with CMake
4. ✅ Downloads Linnix 3B distilled model (2.1 GB) from Hugging Face
5. ✅ Creates systemd service for LLM inference server on port 8090
6. ✅ Configures resource limits (4GB RAM, 400% CPU)
7. ✅ Cleans up build artifacts to save disk space
8. ✅ Starts and enables the LLM service
9. ✅ Verifies LLM server health

**Installation Time:** 10-15 minutes (includes building llama.cpp and downloading 2.1 GB model)

---

## Step-by-Step Manual Installation

For those who prefer manual control or need to customize the installation.

### Step 1: Launch EC2 Instance

**Using AWS Console:**

1. Go to EC2 Dashboard → Launch Instance
2. Choose AMI:
   - **Ubuntu Server 22.04 LTS** (ami-0c7217cdde317cfec for us-east-1)
   - **Amazon Linux 2023** (ami-0440d3b780d96b29d for us-east-1)
3. Select instance type: `t3.medium` (minimum for production)
4. Configure instance:
   - Network: Default VPC or custom VPC
   - Auto-assign Public IP: **Enable**
   - IAM role: Optional (for CloudWatch, SSM)
5. Add storage: **20 GB gp3** (minimum)
6. Configure Security Group (see [Security Group Setup](#security-group-setup))
7. Select or create SSH key pair
8. Launch instance

**Using AWS CLI:**

```bash
# Set variables
KEY_NAME="my-keypair"
SECURITY_GROUP_ID="sg-xxxxxxxxx"
SUBNET_ID="subnet-xxxxxxxxx"

# Launch Ubuntu 22.04 instance
aws ec2 run-instances \
  --image-id ami-0c7217cdde317cfec \
  --instance-type t3.medium \
  --key-name $KEY_NAME \
  --security-group-ids $SECURITY_GROUP_ID \
  --subnet-id $SUBNET_ID \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":20,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=linnix-server}]'
```

### Step 2: Connect to Instance

```bash
# Get instance public IP
INSTANCE_IP=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=linnix-server" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

# SSH into instance
ssh -i ~/.ssh/my-keypair.pem ubuntu@$INSTANCE_IP
```

### Step 3: Verify Kernel and System

```bash
# Check kernel version
uname -r
# Should be >= 5.8

# Check BTF support
ls -la /sys/kernel/btf/vmlinux
# Should exist and be readable

# Check CPU and memory
lscpu
free -h
```

### Step 4: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
  curl \
  wget \
  ca-certificates \
  libelf1 \
  linux-headers-$(uname -r)
```

**Amazon Linux 2023:**
```bash
sudo dnf install -y \
  curl \
  wget \
  ca-certificates \
  elfutils-libelf \
  kernel-headers \
  kernel-devel
```

### Step 5: Install Linnix

**Option A: Using the install script**
```bash
curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/docs/examples/install-ec2.sh | sudo bash
```

**Option B: From pre-built packages**
```bash
# Download DEB package (Ubuntu/Debian)
wget https://github.com/linnix-os/linnix/releases/latest/download/linnix_amd64.deb
sudo dpkg -i linnix_amd64.deb

# Or RPM package (Amazon Linux)
wget https://github.com/linnix-os/linnix/releases/latest/download/linnix.x86_64.rpm
sudo rpm -i linnix.x86_64.rpm
```

**Option C: Build from source**
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Install build dependencies
sudo apt-get install -y build-essential pkg-config libelf-dev clang llvm git

# Clone and build
git clone https://github.com/linnix-os/linnix.git
cd linnix

# Build eBPF programs
cd linnix-ai-ebpf/linnix-ai-ebpf-ebpf
cargo build --release --target=bpfel-unknown-none

# Build userspace binaries
cd ../..
cargo build --release -p cognitod
cargo build --release -p linnix-cli

# Install binaries
sudo cp target/release/cognitod /usr/local/bin/
sudo cp target/release/linnix-cli /usr/local/bin/
sudo mkdir -p /usr/local/share/linnix
sudo cp target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf /usr/local/share/linnix/

# Install configs
sudo mkdir -p /etc/linnix
sudo cp configs/linnix.toml /etc/linnix/
sudo cp configs/rules.yaml /etc/linnix/
```

### Step 6: Configure Systemd Service

Create `/etc/systemd/system/linnix-cognitod.service`:

```ini
[Unit]
Description=Linnix eBPF Observability Daemon
Documentation=https://github.com/linnix-os/linnix
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cognitod
Restart=on-failure
RestartSec=5s

# Environment
Environment="LINNIX_BPF_PATH=/usr/local/share/linnix/linnix-ai-ebpf-ebpf"
Environment="LINNIX_KERNEL_BTF=/sys/kernel/btf/vmlinux"
Environment="RUST_LOG=info"

# Security - Required capabilities for eBPF
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
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable linnix-cognitod
sudo systemctl start linnix-cognitod
sudo systemctl status linnix-cognitod
```

---

## EC2 Instance Configuration

### Recommended EC2 Settings

**Storage:**
- Root volume: 20 GB gp3 (minimum for cognitod only)
- For LLM support: **30 GB gp3 minimum** (16 GB recommended to avoid disk space issues)
  - Model file: 2.1 GB
  - llama.cpp build artifacts: ~1-2 GB (cleaned up after build)
  - System and logs: 1-2 GB
  - Safety buffer: 10+ GB
- IOPS: 3000 (default for gp3)
- Throughput: 125 MB/s (default for gp3)

**Note:** If you run out of disk space, you can resize your EBS volume:
```bash
# In AWS Console: Modify volume size (e.g., 8 GB → 16 GB)
# Then on the instance:
sudo growpart /dev/nvme0n1 1
sudo resize2fs /dev/nvme0n1p1
```

**Network:**
- Enhanced networking: Enabled (default for modern instance types)
- IPv6: Optional
- DNS hostnames: Enabled

**IAM Role (Optional but Recommended):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    }
  ]
}
```

**User Data Script (Optional - for automated deployment):**
```bash
#!/bin/bash
# Auto-install Linnix on instance launch
curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/docs/examples/install-ec2.sh | sudo bash
```

---

## Security Group Setup

### Inbound Rules

| Type | Protocol | Port | Source | Purpose |
|------|----------|------|--------|---------|
| SSH | TCP | 22 | Your IP | SSH access |
| Custom TCP | TCP | 3000 | Your IP / VPC CIDR | Linnix API/Dashboard |
| Custom TCP | TCP | 8090 | Localhost only | LLM Server (internal) |
| Custom TCP | TCP | 9090 | Your IP (optional) | Prometheus metrics |

**Note:** Port 8090 (LLM server) should typically only be accessible from localhost. The cognitod service connects to it internally via `http://127.0.0.1:8090`.

**Security Best Practices:**
1. **Restrict SSH:** Only allow from your IP or bastion host
2. **Restrict API:** Use VPC CIDR or specific IPs, not 0.0.0.0/0
3. **Use SSH Tunneling:** For maximum security (see below)

### Outbound Rules
- Allow all outbound traffic (default)
- Or restrict to specific endpoints if required

### AWS CLI Security Group Creation

```bash
# Create security group
SG_ID=$(aws ec2 create-security-group \
  --group-name linnix-sg \
  --description "Security group for Linnix observability" \
  --vpc-id vpc-xxxxxxxx \
  --output text)

# Add SSH rule (replace YOUR_IP)
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr YOUR_IP/32

# Add Linnix API rule
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 3000 \
  --cidr YOUR_IP/32
```

---

## Post-Installation Configuration

### 1. Edit Configuration File

```bash
sudo nano /etc/linnix/linnix.toml
```

Key settings to configure:

```toml
[runtime]
offline = true  # Set to false if you need external HTTP

[telemetry]
sample_interval_ms = 1000  # Adjust sampling rate

[api]
listen_addr = "0.0.0.0:3000"  # API server binding

[reasoner]
enabled = true  # Enable if you have LLM installed via Docker
endpoint = "http://127.0.0.1:8090/v1/chat/completions"
model = "linnix-3b-distilled"

[prometheus]
enabled = true  # Enable Prometheus metrics
listen_addr = "0.0.0.0:9090"

[alerts]
# Add Apprise notification URLs
apprise_urls = [
  "slack://xoxb-your-token/channel",
  "discord://webhook_id/webhook_token"
]
```

Apply changes:
```bash
sudo systemctl restart linnix-cognitod
```

### 2. Verify Installation

```bash
# Check service status
sudo systemctl status linnix-cognitod

# View logs
sudo journalctl -u linnix-cognitod -f

# Test API endpoint
curl http://localhost:3000/api/healthz

# Expected response:
# {"status":"ok","version":"0.1.0"}
```

### 3. CLI Usage

```bash
# Check running processes
linnix-cli processes

# View system metrics
linnix-cli metrics

# Stream live events
linnix-cli stream
```

---

## Accessing the Dashboard

### Method 1: Direct Access (Public Instance)

If your instance has a public IP and security group allows port 3000:

```bash
# Get public IP
INSTANCE_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

# Open in browser
echo "http://$INSTANCE_IP:3000/"
```

**Open:** `http://YOUR_INSTANCE_PUBLIC_IP:3000/`

### Method 2: SSH Tunnel (Recommended for Security)

```bash
# Create SSH tunnel
ssh -i ~/.ssh/my-keypair.pem -L 3000:localhost:3000 ubuntu@$INSTANCE_IP

# In another terminal or background:
ssh -i ~/.ssh/my-keypair.pem -N -L 3000:localhost:3000 ubuntu@$INSTANCE_IP &
```

**Open:** `http://localhost:3000/`

### Method 3: Systems Manager Session Manager (No SSH Key Needed)

```bash
# Start session
aws ssm start-session --target i-xxxxxxxxx

# Create port forwarding session
aws ssm start-session \
  --target i-xxxxxxxxx \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["3000"],"localPortNumber":["3000"]}'
```

**Open:** `http://localhost:3000/`

### Method 4: Application Load Balancer (Production)

For production deployments:

1. Create Application Load Balancer
2. Create target group pointing to port 3000
3. Register EC2 instance
4. Configure SSL/TLS certificate
5. Access via: `https://linnix.yourdomain.com`

---

## Monitoring and Logs

### View Real-Time Logs

```bash
# Follow cognitod logs
sudo journalctl -u linnix-cognitod -f

# Follow LLM service logs (if installed)
sudo journalctl -u linnix-llm.service -f

# Follow both services together
sudo journalctl -u linnix-cognitod -u linnix-llm.service -f

# Show last 100 lines
sudo journalctl -u linnix-cognitod -n 100

# Filter by priority (errors only)
sudo journalctl -u linnix-cognitod -p err

# Export logs
sudo journalctl -u linnix-cognitod --since "1 hour ago" > linnix-logs.txt
```

### CloudWatch Logs Integration (Optional)

Install CloudWatch agent:

```bash
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i -E ./amazon-cloudwatch-agent.deb

# Configure agent to collect journald logs
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-config-wizard
```

### Performance Monitoring

```bash
# Check resource usage
htop

# Check eBPF program stats
sudo bpftool prog list
sudo bpftool map list

# Monitor API requests
curl http://localhost:3000/api/metrics | jq
```

### Health Checks

```bash
# Create comprehensive health check script
cat > /usr/local/bin/linnix-health-check.sh << 'EOF'
#!/bin/bash

echo "=== Linnix Health Check ==="

# Check cognitod service
if systemctl is-active --quiet linnix-cognitod; then
  echo "✓ Cognitod service: Running"
else
  echo "✗ Cognitod service: Stopped"
  exit 1
fi

# Check cognitod API
RESPONSE=$(curl -s -w "%{http_code}" http://localhost:3000/healthz -o /dev/null)
if [ "$RESPONSE" -eq 200 ]; then
  echo "✓ Cognitod API: Healthy (HTTP 200)"
else
  echo "✗ Cognitod API: Unhealthy (HTTP $RESPONSE)"
  exit 1
fi

# Check LLM service (if installed)
if systemctl list-units --full --all | grep -q "linnix-llm.service"; then
  if systemctl is-active --quiet linnix-llm.service; then
    echo "✓ LLM service: Running"

    # Check LLM health endpoint
    LLM_RESPONSE=$(curl -s -w "%{http_code}" http://localhost:8090/health -o /dev/null)
    if [ "$LLM_RESPONSE" -eq 200 ]; then
      echo "✓ LLM API: Healthy (HTTP 200)"
    else
      echo "⚠ LLM API: Unhealthy (HTTP $LLM_RESPONSE)"
    fi
  else
    echo "✗ LLM service: Stopped"
  fi
else
  echo "ℹ LLM service: Not installed"
fi

echo "=== Health check complete ==="
exit 0
EOF

sudo chmod +x /usr/local/bin/linnix-health-check.sh

# Test health check
/usr/local/bin/linnix-health-check.sh
```

---

## Troubleshooting

### Service Won't Start

**Check logs:**
```bash
sudo journalctl -u linnix-cognitod -n 50 --no-pager
```

**Common issues:**

1. **BTF not found:**
```
Error: BTF file not found at /sys/kernel/btf/vmlinux
```
**Solution:** Install kernel headers and reboot:
```bash
sudo apt-get install -y linux-headers-$(uname -r)
sudo reboot
```

2. **Permission denied (eBPF):**
```
Error: Failed to load eBPF program: Operation not permitted
```
**Solution:** Check capabilities in systemd service:
```bash
sudo systemctl cat linnix-cognitod | grep Capability
# Should show CAP_BPF, CAP_PERFMON, etc.
```

3. **Port already in use:**
```
Error: Address already in use (port 3000)
```
**Solution:** Change port in config or kill conflicting process:
```bash
sudo lsof -i :3000
sudo kill <PID>
```

### High CPU Usage

**Check sampling interval:**
```bash
grep sample_interval /etc/linnix/linnix.toml
# Increase value to reduce overhead
```

**Disable page fault tracing:**
```bash
# Edit config
sudo nano /etc/linnix/linnix.toml

# Set: enable_page_faults = false

sudo systemctl restart linnix-cognitod
```

### Dashboard Not Accessible

**Verify service is running:**
```bash
sudo systemctl status linnix-cognitod
curl http://localhost:3000/api/healthz
```

**Check security group:**
```bash
# Test from instance itself
curl http://localhost:3000/

# If works locally but not remotely, check AWS Security Group
aws ec2 describe-security-groups --group-ids sg-xxxxxxxx
```

**Check firewall:**
```bash
# Ubuntu/Debian
sudo ufw status

# Amazon Linux
sudo firewall-cmd --list-all
```

### Kernel Version Issues

**Kernel too old:**
```bash
# Check version
uname -r

# Upgrade kernel (Ubuntu)
sudo apt-get update
sudo apt-get install -y linux-generic-hwe-22.04
sudo reboot

# Upgrade kernel (Amazon Linux 2023)
sudo dnf update kernel
sudo reboot
```

### LLM Installation Issues

**Disk space full during model download:**
```bash
# Check available space
df -h

# Clean up
sudo apt-get clean
sudo journalctl --vacuum-size=100M

# Or resize EBS volume (see storage recommendations above)
```

**LLM service won't start:**
```bash
# Check logs
sudo journalctl -u linnix-llm.service -n 50

# Common issues:
# 1. Model file missing or corrupted
ls -lh /var/lib/linnix/models/linnix-3b-distilled-q5_k_m.gguf
# Should be ~2.1 GB

# 2. Re-download model if corrupted
sudo rm /var/lib/linnix/models/linnix-3b-distilled-q5_k_m.gguf
sudo wget --continue -P /var/lib/linnix/models \
  https://huggingface.co/parth21shah/linnix-3b-distilled/resolve/main/linnix-3b-distilled-q5_k_m.gguf

# 3. Restart service
sudo systemctl restart linnix-llm.service
```

**No AI insights being generated:**
```bash
# 1. Verify LLM service is healthy
curl http://localhost:8090/health
# Should return {"status":"ok"}

# 2. Check reasoner is enabled in config
grep -A 3 "^\[reasoner\]" /etc/linnix/linnix.toml
# Should show: enabled = true

# 3. Verify model name matches
curl http://localhost:8090/v1/models
# Should list "linnix-3b-distilled"

# 4. Check offline mode is disabled
grep "^offline" /etc/linnix/linnix.toml
# Should show: offline = false

# 5. Restart cognitod after config changes
sudo systemctl restart linnix-cognitod

# 6. Check metrics for ILM activity
curl http://localhost:3000/metrics | grep ilm
# Should show ilm_enabled:true and ilm_windows > 0

# 7. Wait for insights (requires system activity)
# Insights are generated every 30-60 seconds if EPS >= 20
curl http://localhost:3000/insights
```

**LLM issues:**
For LLM support, use Docker-based deployment via `./quickstart.sh` which includes the LLM service pre-configured. Native LLM installation is no longer supported via install scripts.

---

## Advanced Deployment Options

### 1. Auto Scaling Group Deployment

**Create Launch Template:**
```bash
aws ec2 create-launch-template \
  --launch-template-name linnix-template \
  --version-description "Linnix v1" \
  --launch-template-data '{
    "ImageId": "ami-0c7217cdde317cfec",
    "InstanceType": "t3.medium",
    "KeyName": "my-keypair",
    "SecurityGroupIds": ["sg-xxxxxxxx"],
    "UserData": "'$(base64 -w0 docs/examples/install-ec2.sh)'",
    "IamInstanceProfile": {"Name": "linnix-role"},
    "BlockDeviceMappings": [{
      "DeviceName": "/dev/sda1",
      "Ebs": {
        "VolumeSize": 20,
        "VolumeType": "gp3"
      }
    }]
  }'
```

**Create Auto Scaling Group:**
```bash
aws autoscaling create-auto-scaling-group \
  --auto-scaling-group-name linnix-asg \
  --launch-template LaunchTemplateName=linnix-template \
  --min-size 1 \
  --max-size 3 \
  --desired-capacity 1 \
  --vpc-zone-identifier "subnet-xxxxx,subnet-yyyyy"
```

### 2. Docker Deployment on EC2

```bash
# Install Docker
sudo apt-get update
sudo apt-get install -y docker.io
sudo systemctl start docker

# Run Linnix container with privileges
sudo docker run -d \
  --name linnix \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /etc/linnix:/etc/linnix \
  --restart=unless-stopped \
  linnix-os/linnix:latest
```

### 3. Terraform Deployment

Create `main.tf`:

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "linnix" {
  name_prefix = "linnix-"
  description = "Security group for Linnix"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "linnix" {
  ami           = "ami-0c7217cdde317cfec"  # Ubuntu 22.04
  instance_type = var.instance_type
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.linnix.id]

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = file("docs/examples/install-ec2.sh")

  tags = {
    Name = "linnix-server"
  }
}

output "instance_ip" {
  value = aws_instance.linnix.public_ip
}

output "dashboard_url" {
  value = "http://${aws_instance.linnix.public_ip}:3000"
}
```

Deploy:
```bash
terraform init
terraform plan
terraform apply
```

### 4. Multi-Region Deployment

Deploy Linnix across multiple regions for redundancy:

```bash
#!/bin/bash
REGIONS=("us-east-1" "us-west-2" "eu-west-1")

for region in "${REGIONS[@]}"; do
  aws ec2 run-instances \
    --region $region \
    --image-id $(aws ec2 describe-images \
      --region $region \
      --owners 099720109477 \
      --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
      --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
      --output text) \
    --instance-type t3.medium \
    --key-name my-keypair \
    --security-group-ids sg-xxxxxxxx \
    --user-data file://docs/examples/install-ec2.sh \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=linnix-$region}]"
done
```

---

## Cost Optimization

### 1. Use Spot Instances

Save up to 90% with Spot instances:

```bash
aws ec2 run-instances \
  --instance-market-options 'MarketType=spot,SpotOptions={MaxPrice=0.05,SpotInstanceType=persistent}' \
  # ... other parameters
```

### 2. Schedule Start/Stop

Stop instances during off-hours:

```bash
# Stop at night (cron: 0 18 * * *)
aws ec2 stop-instances --instance-ids i-xxxxxxxx

# Start in morning (cron: 0 8 * * 1-5)
aws ec2 start-instances --instance-ids i-xxxxxxxx
```

### 3. Use Smaller Instances for Dev

- Dev/Test: **t3.small** ($0.0208/hour)
- Production: **t3.medium** ($0.0416/hour)
- High performance: **c6a.large** ($0.0765/hour)

---

## Support and Resources

- **Documentation:** https://github.com/linnix-os/linnix/docs
- **Issues:** https://github.com/linnix-os/linnix/issues
- **Discussions:** https://github.com/linnix-os/linnix/discussions
- **License:** AGPL-3.0-or-later

---

**Last Updated:** 2025-01-14
**Version:** 1.0.0
