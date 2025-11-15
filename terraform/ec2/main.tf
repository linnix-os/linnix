# Terraform configuration for deploying Linnix on AWS EC2
# Version: 1.0.0

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Data source for latest Ubuntu 22.04 AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Data source for latest Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Security Group
resource "aws_security_group" "linnix" {
  name_prefix = "linnix-"
  description = "Security group for Linnix eBPF observability platform"
  vpc_id      = var.vpc_id

  # SSH access
  ingress {
    description = "SSH from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks
  }

  # Linnix API and Dashboard
  ingress {
    description = "Linnix API/Dashboard"
    from_port   = var.linnix_port
    to_port     = var.linnix_port
    protocol    = "tcp"
    cidr_blocks = var.api_cidr_blocks
  }

  # Prometheus metrics (optional)
  dynamic "ingress" {
    for_each = var.enable_prometheus ? [1] : []
    content {
      description = "Prometheus metrics"
      from_port   = 9090
      to_port     = 9090
      protocol    = "tcp"
      cidr_blocks = var.prometheus_cidr_blocks
    }
  }

  # Allow all outbound traffic
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-sg"
    }
  )
}

# IAM Role for EC2 instance (CloudWatch, SSM)
resource "aws_iam_role" "linnix" {
  name_prefix = "linnix-instance-role-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM policy for CloudWatch Logs
resource "aws_iam_role_policy" "cloudwatch_logs" {
  name_prefix = "linnix-cloudwatch-"
  role        = aws_iam_role.linnix.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:log-group:/aws/linnix/*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach AWS managed SSM policy for Systems Manager access
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.linnix.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# IAM instance profile
resource "aws_iam_instance_profile" "linnix" {
  name_prefix = "linnix-profile-"
  role        = aws_iam_role.linnix.name

  tags = var.tags
}

# User data script for automated installation
data "template_file" "user_data" {
  template = file("${path.module}/user-data.sh")

  vars = {
    linnix_port    = var.linnix_port
    install_llm    = var.install_llm ? "--with-llm" : ""
    enable_prometheus = var.enable_prometheus
    github_repo    = var.github_repo
  }
}

# EC2 Instance
resource "aws_instance" "linnix" {
  ami           = var.use_amazon_linux ? data.aws_ami.amazon_linux.id : data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name      = var.key_name

  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.linnix.id]
  iam_instance_profile        = aws_iam_instance_profile.linnix.name
  associate_public_ip_address = var.associate_public_ip

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size
    iops                  = 3000
    throughput            = 125
    delete_on_termination = true
    encrypted             = var.enable_encryption

    tags = merge(
      var.tags,
      {
        Name = "${var.project_name}-root-volume"
      }
    )
  }

  user_data = data.template_file.user_data.rendered

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2
    http_put_response_hop_limit = 1
  }

  monitoring = var.enable_detailed_monitoring

  tags = merge(
    var.tags,
    {
      Name = var.project_name
    }
  )

  lifecycle {
    ignore_changes = [ami] # Prevent replacement when AMI updates
  }
}

# Elastic IP (optional)
resource "aws_eip" "linnix" {
  count = var.allocate_elastic_ip ? 1 : 0

  instance = aws_instance.linnix.id
  domain   = "vpc"

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-eip"
    }
  )
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "linnix" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  name              = "/aws/linnix/${var.project_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors EC2 CPU utilization"
  alarm_actions       = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    InstanceId = aws_instance.linnix.id
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "status_check" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-status-check-failed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Maximum"
  threshold           = "0"
  alarm_description   = "This metric monitors EC2 status checks"
  alarm_actions       = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    InstanceId = aws_instance.linnix.id
  }

  tags = var.tags
}

# Route53 DNS record (optional)
resource "aws_route53_record" "linnix" {
  count = var.route53_zone_id != "" ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.route53_record_name
  type    = "A"
  ttl     = "300"
  records = [
    var.allocate_elastic_ip ? aws_eip.linnix[0].public_ip : aws_instance.linnix.public_ip
  ]
}
