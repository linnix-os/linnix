# Terraform outputs for Linnix EC2 deployment

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.linnix.id
}

output "instance_public_ip" {
  description = "Public IP address of the instance"
  value       = aws_instance.linnix.public_ip
}

output "instance_private_ip" {
  description = "Private IP address of the instance"
  value       = aws_instance.linnix.private_ip
}

output "elastic_ip" {
  description = "Elastic IP address (if allocated)"
  value       = var.allocate_elastic_ip ? aws_eip.linnix[0].public_ip : null
}

output "dashboard_url" {
  description = "URL to access Linnix dashboard"
  value       = "http://${var.allocate_elastic_ip ? aws_eip.linnix[0].public_ip : aws_instance.linnix.public_ip}:${var.linnix_port}"
}

output "api_healthz_url" {
  description = "URL to check API health"
  value       = "http://${var.allocate_elastic_ip ? aws_eip.linnix[0].public_ip : aws_instance.linnix.public_ip}:${var.linnix_port}/api/healthz"
}

output "prometheus_url" {
  description = "URL to access Prometheus metrics"
  value       = var.enable_prometheus ? "http://${var.allocate_elastic_ip ? aws_eip.linnix[0].public_ip : aws_instance.linnix.public_ip}:9090/metrics" : null
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = var.use_amazon_linux ? "ssh -i ~/.ssh/${var.key_name}.pem ec2-user@${var.allocate_elastic_ip ? aws_eip.linnix[0].public_ip : aws_instance.linnix.public_ip}" : "ssh -i ~/.ssh/${var.key_name}.pem ubuntu@${var.allocate_elastic_ip ? aws_eip.linnix[0].public_ip : aws_instance.linnix.public_ip}"
}

output "ssh_tunnel_command" {
  description = "SSH tunnel command for secure access"
  value       = var.use_amazon_linux ? "ssh -i ~/.ssh/${var.key_name}.pem -L ${var.linnix_port}:localhost:${var.linnix_port} ec2-user@${var.allocate_elastic_ip ? aws_eip.linnix[0].public_ip : aws_instance.linnix.public_ip}" : "ssh -i ~/.ssh/${var.key_name}.pem -L ${var.linnix_port}:localhost:${var.linnix_port} ubuntu@${var.allocate_elastic_ip ? aws_eip.linnix[0].public_ip : aws_instance.linnix.public_ip}"
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.linnix.id
}

output "iam_role_name" {
  description = "IAM role name"
  value       = aws_iam_role.linnix.name
}

output "iam_role_arn" {
  description = "IAM role ARN"
  value       = aws_iam_role.linnix.arn
}

output "instance_profile_name" {
  description = "IAM instance profile name"
  value       = aws_iam_instance_profile.linnix.name
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name"
  value       = var.enable_cloudwatch_logs ? aws_cloudwatch_log_group.linnix[0].name : null
}

output "dns_name" {
  description = "Route53 DNS name (if configured)"
  value       = var.route53_zone_id != "" ? aws_route53_record.linnix[0].fqdn : null
}

output "ami_id" {
  description = "AMI ID used for the instance"
  value       = aws_instance.linnix.ami
}

output "instance_state" {
  description = "Current state of the instance"
  value       = aws_instance.linnix.instance_state
}

output "availability_zone" {
  description = "Availability zone of the instance"
  value       = aws_instance.linnix.availability_zone
}
