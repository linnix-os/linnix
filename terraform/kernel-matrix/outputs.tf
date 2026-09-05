output "cell_instance_ids" {
  description = "Map of cell name to instance id"
  value       = { for name, inst in aws_instance.cell : name => inst.id }
}

output "cell_public_ips" {
  description = "Map of cell name to public IP (null if associate_public_ip is false)"
  value       = { for name, inst in aws_instance.cell : name => inst.public_ip }
}

output "ssh_commands" {
  description = "Convenience ssh command per cell (assumes associate_public_ip = true)"
  value = {
    for name, inst in aws_instance.cell :
    name => "ssh -i <path-to-${var.key_name}.pem> ubuntu@${inst.public_ip}"
  }
}
