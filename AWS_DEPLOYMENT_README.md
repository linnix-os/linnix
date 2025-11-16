# AWS EC2 Deployment - Quick Reference

This branch contains complete AWS EC2 deployment tooling for Linnix.

## 📦 What's Included

### 1. One-Command Installation Scripts

**Cognitod Installation:** [install-ec2.sh](install-ec2.sh)
```bash
# Install eBPF monitoring daemon
curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/install-ec2.sh | sudo bash
```

**LLM Installation (Optional):** [install-llm-native.sh](install-llm-native.sh)
```bash
# Install AI-powered insights (requires 16GB disk, 4GB+ RAM)
wget https://raw.githubusercontent.com/linnix-os/linnix/main/install-llm-native.sh
sudo ./install-llm-native.sh
```

See [LLM_INSTALLATION.md](LLM_INSTALLATION.md) for detailed LLM setup guide.

### 2. Complete Documentation
**File:** [docs/AWS_EC2_DEPLOYMENT.md](docs/AWS_EC2_DEPLOYMENT.md)

Comprehensive 900+ line guide covering:
- Prerequisites and instance sizing
- Step-by-step manual installation
- Security configuration
- Monitoring and troubleshooting
- Cost optimization

### 3. Terraform Infrastructure
**Directory:** [terraform/ec2/](terraform/ec2/)

```bash
cd terraform/ec2
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars
terraform init
terraform apply
```

### 4. Packer AMI Builder
**Directory:** [packer/](packer/)

```bash
cd packer
packer init linnix-ami.pkr.hcl
packer build linnix-ami.pkr.hcl
```

## 🚀 Deployment Methods Comparison

| Method | Setup Time | Launch Time | Best For |
|--------|-----------|-------------|----------|
| **install-ec2.sh** | 5-8 min | Manual | Testing, one-off |
| **Terraform** | 5-8 min | Automated | Production, IaC |
| **Packer AMI** | 15-20 min build | 30 sec | Scale, consistency |

## 📋 Instance Recommendations

| Use Case | Instance Type | vCPU | Memory | Storage | Monthly Cost |
|----------|--------------|------|--------|---------|--------------|
| Development/Testing | t3.small | 2 | 2 GB | 20 GB | ~$15 |
| Small Production | t3.medium | 2 | 4 GB | 20 GB | ~$30 |
| Production | t3.large | 2 | 8 GB | 20 GB | ~$60 |
| High Performance | c6a.xlarge | 4 | 8 GB | 20 GB | ~$120 |
| **With LLM (Recommended)** | **m6a.large** | **2** | **8 GB** | **16+ GB** | **~$70** |
| With LLM (High Load) | m6a.xlarge | 4 | 16 GB | 16+ GB | ~$140 |

**Note:** LLM support requires minimum 16GB disk (model is 2.1GB) and 4GB+ RAM. For production LLM deployments, use m6a.large or larger.

## 🔧 Quick Start Examples

### Option 1: Manual Installation on Existing EC2
```bash
# SSH into instance
ssh ubuntu@YOUR_INSTANCE_IP

# Install cognitod (eBPF monitoring)
curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/install-ec2.sh | sudo bash

# (Optional) Install LLM for AI insights
wget https://raw.githubusercontent.com/linnix-os/linnix/main/install-llm-native.sh
sudo ./install-llm-native.sh

# Enable LLM in config (if installed)
sudo sed -i 's/^enabled = false/enabled = true/' /etc/linnix/linnix.toml
sudo systemctl restart linnix-cognitod

# Access dashboard
# Open http://YOUR_INSTANCE_IP:3000/
```

### Option 2: Terraform (Recommended for Production)
```bash
# Clone and setup
git clone https://github.com/linnix-os/linnix.git
cd linnix/terraform/ec2

# Configure
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars  # Edit with your settings

# Deploy
terraform init
terraform apply

# Get dashboard URL
terraform output dashboard_url
```

### Option 3: Packer AMI (Best for Scale)
```bash
# Build AMI (once)
cd packer
packer build linnix-ami.pkr.hcl

# Launch instances (many times)
aws ec2 run-instances \
  --image-id ami-xxxxx \
  --instance-type t3.medium \
  --key-name your-key \
  # ... other params
```

## 🔒 Security Checklist

- [ ] Restrict SSH to your IP in security group
- [ ] Restrict API port (3000) to your IP or VPC CIDR
- [ ] Use SSH tunneling for maximum security
- [ ] Enable CloudWatch Logs for monitoring
- [ ] Set up CloudWatch alarms for CPU and status checks
- [ ] Use IMDSv2 (enforced in Terraform)
- [ ] Enable EBS encryption (default in Terraform)
- [ ] Regular security updates via `apt upgrade`

## 📊 Cost Optimization

1. **Use smaller instances for dev/test** - t3.small ($15/month)
2. **Stop instances during off-hours** - Save 50-75%
3. **Use Spot instances** - Save up to 90%
4. **Right-size your instance** - Monitor and adjust
5. **Delete old snapshots** - From Packer builds

## 🐛 Troubleshooting

### Service Won't Start
```bash
sudo journalctl -u linnix-cognitod -n 50
# Check for BTF, permissions, or port conflicts
```

### Dashboard Not Accessible
```bash
# Check service
sudo systemctl status linnix-cognitod

# Test locally
curl http://localhost:3000/healthz

# Check security group
aws ec2 describe-security-groups --group-ids sg-xxxxx
```

### LLM Issues
```bash
# Check LLM service
sudo systemctl status linnix-llm.service
sudo journalctl -u linnix-llm.service -n 50

# Verify model file (should be ~2.1GB)
ls -lh /var/lib/linnix/models/linnix-3b-distilled-q5_k_m.gguf

# Test LLM health
curl http://localhost:8090/health

# Check insights
curl http://localhost:3000/insights
curl http://localhost:3000/metrics | grep ilm
```

### Disk Space Full
```bash
# Check disk usage
df -h

# Resize EBS volume in AWS Console, then:
sudo growpart /dev/nvme0n1 1
sudo resize2fs /dev/nvme0n1p1
```

### High CPU Usage
```bash
# Increase sampling interval
sudo nano /etc/linnix/linnix.toml
# Set: sample_interval_ms = 5000
sudo systemctl restart linnix-cognitod
```

## 📚 Documentation Links

- **Main Documentation:** [docs/AWS_EC2_DEPLOYMENT.md](docs/AWS_EC2_DEPLOYMENT.md)
- **LLM Installation Guide:** [LLM_INSTALLATION.md](LLM_INSTALLATION.md)
- **Cognitod Install Script:** [install-ec2.sh](install-ec2.sh)
- **LLM Install Script:** [install-llm-native.sh](install-llm-native.sh)
- **Terraform README:** [terraform/ec2/README.md](terraform/ec2/README.md)
- **Packer README:** [packer/README.md](packer/README.md)

## 🎯 Next Steps After Deployment

1. **Access the dashboard:** `http://YOUR_IP:3000/`
2. **Configure alerts:** Edit `/etc/linnix/linnix.toml`
3. **Set up monitoring:** Enable CloudWatch integration
4. **Customize rules:** Edit `/etc/linnix/rules.yaml`
5. **Enable Prometheus:** Set `prometheus.enabled = true`

## 💡 Tips

- **Use SSH tunnel for secure access:**
  ```bash
  ssh -L 3000:localhost:3000 ubuntu@YOUR_IP
  # Then access http://localhost:3000/
  ```

- **Enable Prometheus metrics:**
  ```bash
  # Edit /etc/linnix/linnix.toml
  [prometheus]
  enabled = true
  listen_addr = "0.0.0.0:9090"
  ```

- **Configure alerts:**
  ```bash
  # Edit /etc/linnix/linnix.toml
  [alerts]
  apprise_urls = [
    "slack://xoxb-token/channel",
    "discord://webhook_id/webhook_token"
  ]
  ```

## 🤝 Support

- **Issues:** https://github.com/linnix-os/linnix/issues
- **Discussions:** https://github.com/linnix-os/linnix/discussions
- **Documentation:** https://github.com/linnix-os/linnix/docs

---

**Branch:** `aws-ec2-deployment`
**Status:** Ready for testing and merge
**Files:** 12 new files, 3,403+ lines of code
