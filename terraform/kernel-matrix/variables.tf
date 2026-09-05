# Terraform variables for the Incident Lab kernel/topology matrix.
#
# This module is deliberately separate from ../ec2 (a single-instance,
# long-lived product deployment with Route53/CloudWatch alarms/EIP). The
# matrix is N disposable, short-lived instances whose only job is to run
# cognitod with episode_capture enabled and self-terminate.

variable "aws_region" {
  description = "AWS region to deploy the matrix into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix used for resource names and the Project tag"
  type        = string
  default     = "linnix-kernel-matrix"
}

variable "vpc_id" {
  description = "VPC ID to launch matrix instances into"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID to launch matrix instances into"
  type        = string
}

variable "admin_cidr_blocks" {
  description = "CIDR blocks allowed SSH access to matrix instances"
  type        = list(string)
}

variable "key_name" {
  description = "SSH key pair name for matrix instance access"
  type        = string
}

variable "associate_public_ip" {
  description = "Associate a public IP with each matrix instance (needed for SSH without a bastion/SSM)"
  type        = bool
  default     = true
}

variable "github_repo" {
  description = "GitHub repo to pull install-ec2.sh and the built binaries from"
  type        = string
  default     = "linnix-os/linnix"
}

variable "ttl_hours" {
  description = "Hours after boot before each instance self-terminates, regardless of whether a capture run finished. A safety net, not the primary teardown path -- prefer `terraform destroy` when the run is done."
  type        = number
  default     = 4
}

# Each cell is one disposable instance. `ami_id` must be a pinned, literal
# AMI id (not resolved via a `most_recent` data source) -- see the design
# note in main.tf for why. The actual kernel_release/btf_present/arch a
# cell produces is discovered at runtime by cognitod's own
# `cell::detect_cell()` and stamped onto the captured episode; this module
# only needs to boot genuinely different images, not predict what they'll
# report.
#
# No explicit BTF dimension yet: every stock Ubuntu kernel new enough to
# clear this project's own eBPF floor (5.12+ x86 / 5.18+ arm64, see
# ebpf-kernel-floor memory) ships CONFIG_DEBUG_INFO_BTF=y, so ordinary
# `ami_id` choices can't produce a BTF-absent cell -- that needs a kernel
# deliberately built without it, which nothing here provides. Add a
# `btf_present`-forcing cell (custom AMI/kernel) as a follow-up if the
# missing-BTF fallback path in cognitod ever needs real-VM coverage.
variable "cells" {
  description = "Kernel/topology cells to provision, one instance each"
  type = list(object({
    name          = string
    ami_id        = string
    instance_type = string
    arch          = string # "amd64" or "arm64" -- must match ami_id's arch
  }))

  validation {
    condition     = alltrue([for c in var.cells : contains(["amd64", "arm64"], c.arch)])
    error_message = "Each cell's arch must be \"amd64\" or \"arm64\"."
  }

  validation {
    condition     = length(distinct([for c in var.cells : c.name])) == length(var.cells)
    error_message = "Cell names must be unique."
  }
}

variable "tags" {
  description = "Extra tags applied to every resource, merged over the module's own tags"
  type        = map(string)
  default     = {}
}
