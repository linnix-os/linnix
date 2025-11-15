# Linnix Terraform Deployment for AWS EC2

This directory contains Terraform configurations for deploying Linnix on AWS EC2.

## Quick Start

### Prerequisites

1. **Install Terraform** (v1.0+)
   ```bash
   # macOS
   brew install terraform

   # Linux
   wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
   unzip terraform_1.6.0_linux_amd64.zip
   sudo mv terraform /usr/local/bin/
   ```

2. **AWS Credentials**
   ```bash
   # Configure AWS CLI
   aws configure

   # Or export credentials
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_DEFAULT_REGION="us-east-1"
   ```

3. **SSH Key Pair**
   ```bash
   # Create new key pair
   aws ec2 create-key-pair --key-name linnix-key --query 'KeyMaterial' --output text > ~/.ssh/linnix-key.pem
   chmod 400 ~/.ssh/linnix-key.pem

   # Or use existing key pair
   aws ec2 describe-key-pairs --key-name your-existing-key
   ```

### Deployment Steps

1. **Clone repository and navigate to terraform directory**
   ```bash
   git clone https://github.com/YOUR_ORG/linnix.git
   cd linnix/terraform/ec2
   ```

2. **Create your variables file**
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   nano terraform.tfvars
   ```

3. **Customize variables** (minimum required)
   ```hcl
   key_name = "linnix-key"
   vpc_id = "vpc-xxxxx"
   subnet_id = "subnet-xxxxx"
   admin_cidr_blocks = ["YOUR.IP.ADDRESS/32"]
   api_cidr_blocks = ["YOUR.IP.ADDRESS/32"]
   ```

4. **Initialize Terraform**
   ```bash
   terraform init
   ```

5. **Preview changes**
   ```bash
   terraform plan
   ```

6. **Deploy infrastructure**
   ```bash
   terraform apply
   ```
   Type `yes` when prompted.

7. **Access your instance**
   ```bash
   # Get outputs
   terraform output

   # SSH into instance
   terraform output -raw ssh_command | bash

   # Or access dashboard
   DASHBOARD_URL=$(terraform output -raw dashboard_url)
   echo "Dashboard: $DASHBOARD_URL"
   ```

### Installation Time

- **Terraform provisioning:** 2-3 minutes
- **Linnix installation (user-data):** 3-5 minutes
- **Total:** ~5-8 minutes

Check installation progress:
```bash
# SSH into instance
ssh -i ~/.ssh/linnix-key.pem ubuntu@$(terraform output -raw instance_public_ip)

# View installation log
sudo tail -f /var/log/user-data.log

# Check service status
sudo systemctl status linnix-cognitod
```

## Configuration Options

### Instance Types

| Instance Type | vCPU | Memory | Use Case | Monthly Cost* |
|--------------|------|--------|----------|---------------|
| t3.small | 2 | 2 GB | Testing/Dev | ~$15 |
| t3.medium | 2 | 4 GB | Small Production | ~$30 |
| t3.large | 2 | 8 GB | Production | ~$60 |
| c6a.xlarge | 4 | 8 GB | High Performance | ~$120 |
| m6a.xlarge | 4 | 16 GB | With LLM | ~$140 |

*Approximate US pricing, varies by region

### Common Scenarios

**Development Environment:**
```hcl
instance_type = "t3.small"
root_volume_size = 20
enable_encryption = false
enable_cloudwatch_logs = false
install_llm = false
```

**Production Environment:**
```hcl
instance_type = "t3.medium"
root_volume_size = 30
enable_encryption = true
enable_cloudwatch_logs = true
enable_cloudwatch_alarms = true
allocate_elastic_ip = true
enable_detailed_monitoring = true
```

**High-Performance Monitoring:**
```hcl
instance_type = "c6a.xlarge"
root_volume_size = 50
enable_prometheus = true
enable_detailed_monitoring = true
```

**With AI/LLM Support:**
```hcl
instance_type = "m6a.xlarge"
root_volume_size = 50
install_llm = true
```

## Networking Setup

### Find Your VPC and Subnet

```bash
# List VPCs
aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0]]' --output table

# List subnets in VPC
VPC_ID="vpc-xxxxx"
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[*].[SubnetId,CidrBlock,AvailabilityZone,Tags[?Key==`Name`].Value|[0]]' --output table

# Get your public IP
curl -s https://checkip.amazonaws.com
```

### Use Default VPC

```bash
# Get default VPC
DEFAULT_VPC=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query 'Vpcs[0].VpcId' --output text)

# Get default subnet
DEFAULT_SUBNET=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$DEFAULT_VPC" --query 'Subnets[0].SubnetId' --output text)

# Update terraform.tfvars
echo "vpc_id = \"$DEFAULT_VPC\"" >> terraform.tfvars
echo "subnet_id = \"$DEFAULT_SUBNET\"" >> terraform.tfvars
```

## Security Configuration

### Restrict Access by IP

```hcl
# SSH only from your IP
admin_cidr_blocks = ["1.2.3.4/32"]

# API access from your office network
api_cidr_blocks = ["10.0.0.0/16"]

# Prometheus from monitoring server
prometheus_cidr_blocks = ["10.0.1.50/32"]
```

### Use SSH Tunneling (Most Secure)

```hcl
# Block public API access
api_cidr_blocks = ["127.0.0.1/32"]
```

Then access via tunnel:
```bash
# Create tunnel
terraform output -raw ssh_tunnel_command | bash

# Access dashboard on localhost
open http://localhost:3000
```

## Advanced Features

### Enable CloudWatch Monitoring

```hcl
enable_cloudwatch_logs = true
enable_cloudwatch_alarms = true
log_retention_days = 30

# Create SNS topic for alerts
alarm_sns_topic_arn = "arn:aws:sns:us-east-1:123456789012:linnix-alerts"
```

Create SNS topic:
```bash
aws sns create-topic --name linnix-alerts
aws sns subscribe --topic-arn arn:aws:sns:us-east-1:123456789012:linnix-alerts --protocol email --notification-endpoint your-email@example.com
```

### Configure DNS with Route53

```hcl
route53_zone_id = "Z1234567890ABC"
route53_record_name = "linnix.example.com"
```

Find your hosted zone:
```bash
aws route53 list-hosted-zones --query 'HostedZones[*].[Id,Name]' --output table
```

### Use Elastic IP

```hcl
allocate_elastic_ip = true
```

Benefits:
- Persistent IP address across instance stop/start
- Easy DNS configuration
- Better for production environments

Cost: ~$3.60/month

## Maintenance

### Update Linnix

```bash
# SSH into instance
ssh -i ~/.ssh/linnix-key.pem ubuntu@$(terraform output -raw instance_public_ip)

# Pull latest code and rebuild
cd /tmp
git clone https://github.com/YOUR_ORG/linnix.git
cd linnix
cargo build --release
sudo cp target/release/cognitod /usr/local/bin/
sudo systemctl restart linnix-cognitod
```

### Scale Instance Type

```bash
# Update terraform.tfvars
instance_type = "t3.large"

# Apply changes (will stop/start instance)
terraform apply
```

### Backup Configuration

```bash
# Create AMI from running instance
INSTANCE_ID=$(terraform output -raw instance_id)
aws ec2 create-image \
  --instance-id $INSTANCE_ID \
  --name "linnix-backup-$(date +%Y%m%d)" \
  --description "Linnix configured instance backup"
```

### Destroy Infrastructure

```bash
# Preview what will be destroyed
terraform plan -destroy

# Destroy all resources
terraform destroy
```

## Troubleshooting

### Instance not accessible

1. **Check security group rules**
   ```bash
   terraform output security_group_id
   aws ec2 describe-security-groups --group-ids sg-xxxxx
   ```

2. **Verify instance is running**
   ```bash
   terraform output instance_id
   aws ec2 describe-instances --instance-ids i-xxxxx --query 'Reservations[0].Instances[0].State'
   ```

3. **Check user-data logs**
   ```bash
   ssh -i ~/.ssh/linnix-key.pem ubuntu@IP
   sudo cat /var/log/user-data.log
   sudo journalctl -u cloud-final -f
   ```

### Service not starting

```bash
# SSH into instance
ssh -i ~/.ssh/linnix-key.pem ubuntu@$(terraform output -raw instance_public_ip)

# Check service status
sudo systemctl status linnix-cognitod

# View logs
sudo journalctl -u linnix-cognitod -n 100 --no-pager

# Check kernel compatibility
uname -r
ls -la /sys/kernel/btf/vmlinux
```

### Terraform errors

**Error: Invalid credentials**
```bash
aws configure list
aws sts get-caller-identity
```

**Error: VPC/Subnet not found**
```bash
# Verify VPC exists
aws ec2 describe-vpcs --vpc-ids vpc-xxxxx

# Verify subnet exists
aws ec2 describe-subnets --subnet-ids subnet-xxxxx
```

**Error: Key pair not found**
```bash
# List available key pairs
aws ec2 describe-key-pairs --query 'KeyPairs[*].KeyName'
```

## Cost Estimation

### Monthly Costs (us-east-1)

**Minimal Setup (t3.small, no extras):**
- EC2 instance: ~$15
- EBS storage (20 GB): ~$2
- **Total: ~$17/month**

**Standard Production (t3.medium + monitoring):**
- EC2 instance: ~$30
- EBS storage (30 GB): ~$3
- Elastic IP: ~$3.60
- CloudWatch Logs (1 GB): ~$0.50
- **Total: ~$37/month**

**High Performance (c6a.xlarge + full monitoring):**
- EC2 instance: ~$120
- EBS storage (50 GB): ~$5
- Elastic IP: ~$3.60
- CloudWatch (detailed): ~$5
- **Total: ~$133/month**

**Cost savings tips:**
- Use Spot instances (up to 90% savings)
- Stop instance during off-hours
- Use t3.small for dev/test
- Disable detailed monitoring if not needed

## Additional Resources

- [AWS EC2 Pricing](https://aws.amazon.com/ec2/pricing/)
- [Terraform AWS Provider Docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Linnix Documentation](https://github.com/YOUR_ORG/linnix/docs)
- [AWS EC2 User Guide](https://docs.aws.amazon.com/ec2/)

## Support

For issues or questions:
- GitHub Issues: https://github.com/YOUR_ORG/linnix/issues
- Documentation: https://github.com/YOUR_ORG/linnix/docs/AWS_EC2_DEPLOYMENT.md
