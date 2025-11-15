# Linnix AMI Builder (Packer)

Build pre-configured AWS AMIs with Linnix already installed using HashiCorp Packer.

## What This Does

Creates a custom AMI with:
- ✅ Ubuntu 22.04 LTS base
- ✅ Linnix pre-installed and configured
- ✅ All dependencies installed
- ✅ eBPF programs compiled and ready
- ✅ Systemd service configured
- ✅ First-boot automation for instance-specific setup
- ✅ Optimized and cleaned up

**Benefits:**
- **Fast launch:** Instance is ready in ~30 seconds vs 5-8 minutes
- **Consistent:** Same configuration every time
- **Tested:** AMI is validated during build
- **Cost-effective:** Reduce launch time = lower costs

## Prerequisites

1. **Install Packer** (v1.8+)
   ```bash
   # macOS
   brew install packer

   # Linux
   wget https://releases.hashicorp.com/packer/1.10.0/packer_1.10.0_linux_amd64.zip
   unzip packer_1.10.0_linux_amd64.zip
   sudo mv packer /usr/local/bin/
   ```

2. **AWS Credentials**
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_DEFAULT_REGION="us-east-1"
   ```

3. **AWS Permissions**
   Your IAM user/role needs:
   - `ec2:CreateImage`
   - `ec2:RunInstances`
   - `ec2:TerminateInstances`
   - `ec2:CreateSnapshot`
   - `ec2:DescribeImages`
   - `ec2:DescribeInstances`

## Quick Start

### Build Default AMI

```bash
cd packer
packer init linnix-ami.pkr.hcl
packer build linnix-ami.pkr.hcl
```

Build time: **~15-20 minutes**

### Build with Variables

```bash
# Build in different region
packer build -var 'aws_region=us-west-2' linnix-ami.pkr.hcl

# Build with LLM support
packer build -var 'install_llm=true' linnix-ami.pkr.hcl

# Custom AMI name prefix
packer build -var 'ami_name_prefix=my-linnix' linnix-ami.pkr.hcl

# Build with all custom options
packer build \
  -var 'aws_region=eu-west-1' \
  -var 'instance_type=t3.large' \
  -var 'ami_name_prefix=linnix-prod' \
  -var 'install_llm=true' \
  linnix-ami.pkr.hcl
```

### Use Variables File

Create `variables.pkrvars.hcl`:
```hcl
aws_region      = "us-west-2"
instance_type   = "t3.medium"
ami_name_prefix = "linnix-production"
install_llm     = false
github_repo     = "linnix-os/linnix"
```

Build with variables file:
```bash
packer build -var-file=variables.pkrvars.hcl linnix-ami.pkr.hcl
```

## Available Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `aws_region` | string | `us-east-1` | AWS region to build in |
| `instance_type` | string | `t3.medium` | Instance type for building |
| `ami_name_prefix` | string | `linnix` | Prefix for AMI name |
| `ami_description` | string | See file | AMI description |
| `ssh_username` | string | `ubuntu` | SSH username |
| `github_repo` | string | `linnix-os/linnix` | GitHub repository |
| `install_llm` | bool | `false` | Install LLM support |

## Build Process

The build goes through these steps:

1. **Launch Builder Instance** (t3.medium, Ubuntu 22.04)
2. **Update System** (apt update && upgrade)
3. **Install Kernel Headers** (required for eBPF)
4. **Download Install Script** (from GitHub)
5. **Install Linnix** (runs install-ec2.sh --dev)
6. **Stop Service** (will start on instance launch)
7. **Create Configuration Template**
8. **Clean Up** (logs, history, temp files, SSH keys)
9. **Create First-Boot Script** (instance-specific setup)
10. **Validate Installation** (check binaries and configs)
11. **Create AMI Snapshot**
12. **Terminate Builder Instance**

## Using the AMI

### Find Your AMI

After build completes:

```bash
# AMI ID is in output
# Look for: "AMIs were created:"

# Or find by name
aws ec2 describe-images \
  --owners self \
  --filters "Name=name,Values=linnix-*" \
  --query 'Images[*].[ImageId,Name,CreationDate]' \
  --output table
```

### Launch Instance from AMI

**Using AWS CLI:**
```bash
AMI_ID="ami-xxxxxxxxx"  # From packer output

aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type t3.medium \
  --key-name your-keypair \
  --security-group-ids sg-xxxxxxxx \
  --subnet-id subnet-xxxxxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=linnix-from-ami}]'
```

**Using Terraform:**

Update `terraform/ec2/main.tf`:

```hcl
# Replace the data source with your AMI ID
data "aws_ami" "linnix" {
  owners      = ["self"]
  most_recent = true

  filter {
    name   = "name"
    values = ["linnix-*"]
  }
}

resource "aws_instance" "linnix" {
  ami           = data.aws_ami.linnix.id
  instance_type = var.instance_type
  # ... rest of configuration
}
```

### Verify AMI Launch

```bash
# SSH into instance
ssh -i ~/.ssh/your-key.pem ubuntu@INSTANCE_IP

# Check service (should already be running)
sudo systemctl status linnix-cognitod

# Access dashboard
curl http://localhost:3000/api/healthz
```

**Expected result:** Service is running and responds within 30-60 seconds of instance launch.

## Advanced Usage

### Multi-Region AMI

Build and copy to multiple regions:

```bash
# Build in us-east-1
packer build -var 'aws_region=us-east-1' linnix-ami.pkr.hcl

# Get AMI ID from output
AMI_ID="ami-xxxxxxxxx"

# Copy to other regions
aws ec2 copy-image \
  --source-region us-east-1 \
  --source-image-id $AMI_ID \
  --region us-west-2 \
  --name "linnix-$(date +%s)"

aws ec2 copy-image \
  --source-region us-east-1 \
  --source-image-id $AMI_ID \
  --region eu-west-1 \
  --name "linnix-$(date +%s)"
```

### Automated Multi-Region Build Script

Create `build-all-regions.sh`:

```bash
#!/bin/bash
REGIONS=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")

for region in "${REGIONS[@]}"; do
  echo "Building in $region..."
  packer build -var "aws_region=$region" linnix-ami.pkr.hcl
done
```

### Share AMI with Other Accounts

```bash
AMI_ID="ami-xxxxxxxxx"
OTHER_ACCOUNT_ID="123456789012"

# Grant launch permission
aws ec2 modify-image-attribute \
  --image-id $AMI_ID \
  --launch-permission "Add=[{UserId=$OTHER_ACCOUNT_ID}]"

# Or make public (use cautiously!)
aws ec2 modify-image-attribute \
  --image-id $AMI_ID \
  --launch-permission "Add=[{Group=all}]"
```

### Create AMI Version Tags

```bash
AMI_ID="ami-xxxxxxxxx"

aws ec2 create-tags \
  --resources $AMI_ID \
  --tags \
    Key=Version,Value=1.0.0 \
    Key=Environment,Value=production \
    Key=LLMSupport,Value=false
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/build-ami.yml`:

```yaml
name: Build Linnix AMI

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Packer
        uses: hashicorp/setup-packer@main

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Build AMI
        run: |
          cd packer
          packer init linnix-ami.pkr.hcl
          packer build linnix-ami.pkr.hcl

      - name: Save AMI ID
        run: |
          AMI_ID=$(jq -r '.builds[-1].artifact_id' packer/manifest.json | cut -d':' -f2)
          echo "AMI_ID=$AMI_ID" >> $GITHUB_ENV
          echo "::notice::Built AMI: $AMI_ID"
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
build-ami:
  stage: build
  image: hashicorp/packer:latest
  script:
    - cd packer
    - packer init linnix-ami.pkr.hcl
    - packer build linnix-ami.pkr.hcl
  artifacts:
    paths:
      - packer/manifest.json
  only:
    - tags
```

## Customization

### Modify Installation

Edit `linnix-ami.pkr.hcl` provisioner section:

```hcl
provisioner "shell" {
  inline = [
    "sudo /tmp/install-ec2.sh --with-llm --dev --port 8080",
    "# Add custom configuration",
    "sudo sed -i 's/sample_interval_ms = 1000/sample_interval_ms = 500/' /etc/linnix/linnix.toml"
  ]
}
```

### Add Custom Files

```hcl
provisioner "file" {
  source      = "custom-config.toml"
  destination = "/tmp/custom-config.toml"
}

provisioner "shell" {
  inline = [
    "sudo mv /tmp/custom-config.toml /etc/linnix/custom.toml"
  ]
}
```

### Install Additional Software

```hcl
provisioner "shell" {
  inline = [
    "sudo apt-get install -y htop iotop sysstat",
    "# Configure monitoring tools",
    "sudo systemctl enable sysstat"
  ]
}
```

## Troubleshooting

### Build Fails: Timeout Connecting

**Error:** `Timeout waiting for SSH`

**Solution:**
- Check AWS credentials
- Verify VPC has internet gateway
- Ensure default security group allows SSH (port 22)
- Try different region

### Build Fails: Permission Denied

**Error:** `You are not authorized to perform this operation`

**Solution:**
```bash
# Verify IAM permissions
aws iam get-user
aws ec2 describe-images --owners self --max-items 1
```

### Service Not Starting in AMI

**Check logs:**
```bash
# After launching instance from AMI
ssh ubuntu@INSTANCE_IP
sudo journalctl -u linnix-cognitod -n 100
sudo journalctl -u linnix-first-boot -n 100
```

**Common issues:**
- First-boot script failed
- Configuration template missing
- eBPF programs not compatible with kernel

### Validate Before Building

```bash
# Check syntax
packer fmt linnix-ami.pkr.hcl

# Validate configuration
packer validate linnix-ami.pkr.hcl

# Build with debug mode
PACKER_LOG=1 packer build linnix-ami.pkr.hcl
```

## Cost Estimation

### Build Costs

**Per AMI build:**
- EC2 instance (t3.medium): ~$0.10 (20 minutes)
- EBS snapshot storage: ~$0.05/GB/month
- **Total build cost:** ~$0.10 per build

**Storage costs (ongoing):**
- 30 GB AMI: ~$1.50/month
- Multiple regions: ~$1.50/month per region

**Cost savings:**
- Fast instance launch saves ~$0.05-0.10 per instance
- Break-even: After launching ~20-30 instances

## Maintenance

### Regular Rebuilds

Rebuild AMI monthly or after:
- Kernel updates
- Linnix version updates
- Security patches
- Configuration changes

### Delete Old AMIs

```bash
# List AMIs
aws ec2 describe-images --owners self --query 'Images[*].[ImageId,Name,CreationDate]' --output table

# Deregister AMI
aws ec2 deregister-image --image-id ami-xxxxxxxxx

# Delete associated snapshot
SNAPSHOT_ID=$(aws ec2 describe-images --image-ids ami-xxxxxxxxx --query 'Images[0].BlockDeviceMappings[0].Ebs.SnapshotId' --output text)
aws ec2 delete-snapshot --snapshot-id $SNAPSHOT_ID
```

### Automated Cleanup Script

Create `cleanup-old-amis.sh`:

```bash
#!/bin/bash
# Keep only the 3 most recent AMIs

AMIS=$(aws ec2 describe-images \
  --owners self \
  --filters "Name=name,Values=linnix-*" \
  --query 'sort_by(Images, &CreationDate)[:-3].[ImageId]' \
  --output text)

for ami in $AMIS; do
  echo "Deregistering $ami..."
  aws ec2 deregister-image --image-id $ami
done
```

## Resources

- [Packer Documentation](https://developer.hashicorp.com/packer/docs)
- [AWS AMI Best Practices](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)
- [Linnix Documentation](https://github.com/linnix-os/linnix/docs)

---

**Last Updated:** 2025-01-14
**Version:** 1.0.0
