# Terraform variables for Linnix EC2 deployment

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "linnix-server"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"

  validation {
    condition     = can(regex("^[a-z][0-9][a-z]?\\.(nano|micro|small|medium|large|xlarge|[0-9]+xlarge)$", var.instance_type))
    error_message = "Instance type must be a valid EC2 instance type."
  }
}

variable "key_name" {
  description = "SSH key pair name for EC2 access"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where resources will be created"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for EC2 instance"
  type        = string
}

variable "admin_cidr_blocks" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "api_cidr_blocks" {
  description = "CIDR blocks allowed for API/Dashboard access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "prometheus_cidr_blocks" {
  description = "CIDR blocks allowed for Prometheus metrics access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "associate_public_ip" {
  description = "Associate a public IP address with the instance"
  type        = bool
  default     = true
}

variable "allocate_elastic_ip" {
  description = "Allocate and associate an Elastic IP"
  type        = bool
  default     = false
}

variable "root_volume_size" {
  description = "Root volume size in GB"
  type        = number
  default     = 20

  validation {
    condition     = var.root_volume_size >= 20
    error_message = "Root volume size must be at least 20 GB."
  }
}

variable "enable_encryption" {
  description = "Enable EBS volume encryption"
  type        = bool
  default     = true
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = false
}

variable "linnix_port" {
  description = "Port for Linnix API and dashboard"
  type        = number
  default     = 3000

  validation {
    condition     = var.linnix_port > 0 && var.linnix_port < 65536
    error_message = "Port must be between 1 and 65535."
  }
}

variable "enable_prometheus" {
  description = "Enable Prometheus metrics endpoint"
  type        = bool
  default     = false
}

variable "install_llm" {
  description = "Install LLM support for AI-powered insights"
  type        = bool
  default     = false
}

variable "use_amazon_linux" {
  description = "Use Amazon Linux 2023 instead of Ubuntu 22.04"
  type        = bool
  default     = false
}

variable "github_repo" {
  description = "GitHub repository for Linnix (format: owner/repo)"
  type        = string
  default     = "linnix-os/linnix"
}

variable "enable_cloudwatch_logs" {
  description = "Enable CloudWatch Logs integration"
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 7

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for monitoring"
  type        = bool
  default     = false
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for alarm notifications"
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Route53 hosted zone ID for DNS record (leave empty to skip)"
  type        = string
  default     = ""
}

variable "route53_record_name" {
  description = "Route53 DNS record name (e.g., linnix.example.com)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "Linnix"
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}
