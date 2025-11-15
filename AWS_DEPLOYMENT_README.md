# AWS EC2 Deployment - Quick Reference

This branch contains complete AWS EC2 deployment tooling for Linnix.

## 📦 What's Included

### 1. One-Command Installation Script
**File:** [install-ec2.sh](install-ec2.sh)

```bash
# Quick install
curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/install-ec2.sh | sudo bash

# With options
sudo ./install-ec2.sh --with-llm --port 3000
```

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

| Use Case | Instance Type | Memory | Monthly Cost |
|----------|--------------|--------|--------------|
| Development/Testing | t3.small | 2 GB | ~$15 |
| Small Production | t3.medium | 4 GB | ~$30 |
| Production | t3.large | 8 GB | ~$60 |
| High Performance | c6a.xlarge | 8 GB | ~$120 |
| With LLM Support | m6a.xlarge | 16 GB | ~$140 |

## 🔧 Quick Start Examples

### Option 1: Manual Installation on Existing EC2
```bash
# SSH into instance
ssh ubuntu@YOUR_INSTANCE_IP

# Install
curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/install-ec2.sh | sudo bash

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
curl http://localhost:3000/api/healthz

# Check security group
aws ec2 describe-security-groups --group-ids sg-xxxxx
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
- **Terraform README:** [terraform/ec2/README.md](terraform/ec2/README.md)
- **Packer README:** [packer/README.md](packer/README.md)
- **Installation Script:** [install-ec2.sh](install-ec2.sh)

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
