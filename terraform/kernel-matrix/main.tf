# Incident Lab kernel/topology matrix -- disposable instances that boot,
# run cognitod with episode_capture on, and self-terminate after ttl_hours.
#
# Why this isn't ../ec2 with a for_each bolted on: that module resolves its
# AMI via `most_recent = true` and is built to survive indefinitely (EIP,
# Route53, CloudWatch alarms, `ignore_changes = [ami]` to avoid replacing a
# running server). A `most_recent` filter re-resolved on every `apply`
# breaks the one thing a kernel matrix needs -- a reproducible cell
# identity, since the AMI (and its actual kernel) can change out from under
# you between runs. Callers must resolve and pin a literal `ami_id` per
# cell (e.g. via `aws ec2 describe-images`) instead.
#
# Why this doesn't build per-cell AMIs with Packer either: Packer bakes
# cognitod into the image at build time, which is the right shape for a
# product release, not for iterating on what gets captured -- rebuilding
# an AMI per code change to the capture path would dominate the loop this
# lab exists to shorten. Cells vary the base image (kernel/arch); cognitod
# itself is installed fresh by user-data on every boot from `main`.

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

locals {
  common_tags = merge(
    var.tags,
    {
      Project   = var.project_name
      Ephemeral = "true"
      ManagedBy = "terraform-kernel-matrix"
      TtlHours  = tostring(var.ttl_hours)
    }
  )

  cells_by_name = { for c in var.cells : c.name => c }
}

# SSH only -- no dashboard/API/Prometheus ports. A matrix instance's only
# job is to capture episodes to disk; nothing needs to reach cognitod's API
# from outside, and this stays true with the k3s injection harness
# (../kernel-matrix/inject.sh): it drives each cell over plain ssh/scp, since
# retrieving episode JSON files is the whole point of a run and SSM would
# need an S3 hop or a tunnel to do that for no benefit over ssh.
resource "aws_security_group" "matrix" {
  name_prefix = "${var.project_name}-"
  description = "SSH-only access for Incident Lab kernel/topology matrix instances"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.project_name}-sg" })
}

resource "aws_iam_role" "matrix" {
  name_prefix = "${var.project_name}-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })

  tags = local.common_tags
}

# SSM as a fallback debugging path if SSH access needs revoking mid-run.
# No ec2:TerminateInstances grant: the TTL self-terminate shuts the guest
# down from the inside (`systemctl poweroff` + instance_initiated_shutdown_
# behavior = "terminate" below), so the instance role never needs the AWS
# API permission to terminate itself.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.matrix.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "matrix" {
  name_prefix = "${var.project_name}-"
  role        = aws_iam_role.matrix.name

  tags = local.common_tags
}

resource "aws_instance" "cell" {
  for_each = local.cells_by_name

  ami           = each.value.ami_id
  instance_type = each.value.instance_type
  key_name      = var.key_name

  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.matrix.id]
  iam_instance_profile        = aws_iam_instance_profile.matrix.name
  associate_public_ip_address = var.associate_public_ip

  # The TTL self-terminate in user-data.sh.tftpl shuts the guest down from
  # the inside (`systemctl poweroff`) using only stock-AMI tools -- no
  # awscli/IMDS credentials needed. That only tears the instance down
  # rather than just stopping it because of this setting.
  instance_initiated_shutdown_behavior = "terminate"

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    delete_on_termination = true
    encrypted             = true

    tags = merge(local.common_tags, { Name = "${var.project_name}-${each.key}-root" })
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2
    http_put_response_hop_limit = 1
  }

  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    github_repo = var.github_repo
    ttl_hours   = var.ttl_hours
    cell_name   = each.key
  })
  # Without this, a change to user-data.sh.tftpl only updates Terraform's
  # state -- the running instance keeps whatever boot script it started
  # with, since cloud-init doesn't re-run user-data on its own.
  user_data_replace_on_change = true

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-${each.key}"
      Cell = each.key
      Arch = each.value.arch
    }
  )

  # Deliberately no `ignore_changes = [ami]` (unlike ../ec2): a cell whose
  # ami_id changes is a different cell and should replace the instance, not
  # keep running the old image under a new name.
}
