# Packer template for building Linnix AMI
# This creates a pre-configured AMI with Linnix already installed

packer {
  required_plugins {
    amazon = {
      version = ">= 1.2.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

# Variables
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "ami_name_prefix" {
  type    = string
  default = "linnix"
}

variable "ami_description" {
  type    = string
  default = "Linnix eBPF Observability Platform - Pre-configured AMI"
}

variable "ssh_username" {
  type    = string
  default = "ubuntu"
}

variable "github_repo" {
  type    = string
  default = "linnix-os/linnix"
}

variable "install_llm" {
  type    = bool
  default = false
}

# Source AMI - Latest Ubuntu 22.04
data "amazon-ami" "ubuntu" {
  filters = {
    name                = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
    virtualization-type = "hvm"
    root-device-type    = "ebs"
  }
  owners      = ["099720109477"] # Canonical
  most_recent = true
  region      = var.aws_region
}

# Build configuration
source "amazon-ebs" "linnix" {
  ami_name        = "${var.ami_name_prefix}-{{timestamp}}"
  ami_description = var.ami_description
  instance_type   = var.instance_type
  region          = var.aws_region
  source_ami      = data.amazon-ami.ubuntu.id
  ssh_username    = var.ssh_username

  # Storage
  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 30
    volume_type           = "gp3"
    iops                  = 3000
    throughput            = 125
    delete_on_termination = true
    encrypted             = true
  }

  # Metadata options - IMDSv2
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Tags
  tags = {
    Name          = "${var.ami_name_prefix}-{{timestamp}}"
    Project       = "Linnix"
    OS            = "Ubuntu 22.04"
    BuildDate     = "{{timestamp}}"
    BuildTool     = "Packer"
    BaseAMI       = "{{ .SourceAMI }}"
    BaseAMIName   = "{{ .SourceAMIName }}"
  }

  # Snapshot tags
  snapshot_tags = {
    Name      = "${var.ami_name_prefix}-snapshot-{{timestamp}}"
    Project   = "Linnix"
    BuildDate = "{{timestamp}}"
  }
}

# Build steps
build {
  sources = ["source.amazon-ebs.linnix"]

  # Wait for cloud-init to finish
  provisioner "shell" {
    inline = [
      "echo 'Waiting for cloud-init to complete...'",
      "cloud-init status --wait",
      "echo 'Cloud-init completed'"
    ]
  }

  # Update system
  provisioner "shell" {
    inline = [
      "echo 'Updating system packages...'",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y linux-headers-$(uname -r) || sudo apt-get install -y linux-headers-generic"
    ]
  }

  # Download and run Linnix installation script
  provisioner "shell" {
    environment_vars = [
      "GITHUB_REPO=${var.github_repo}",
      "INSTALL_LLM=${var.install_llm}"
    ]
    inline = [
      "echo 'Downloading Linnix installation script...'",
      "curl -fsSL https://raw.githubusercontent.com/${var.github_repo}/main/install-ec2.sh -o /tmp/install-ec2.sh",
      "chmod +x /tmp/install-ec2.sh",
      "echo 'Installing Linnix...'",
      "if [ \"$INSTALL_LLM\" = \"true\" ]; then",
      "  sudo /tmp/install-ec2.sh --with-llm --dev",
      "else",
      "  sudo /tmp/install-ec2.sh --dev",
      "fi",
      "echo 'Linnix installation completed'",
    ]
  }

  # Stop Linnix service (will be started on instance launch)
  provisioner "shell" {
    inline = [
      "echo 'Stopping Linnix service (will start on instance launch)...'",
      "sudo systemctl stop linnix-cognitod || true",
      "sudo systemctl disable linnix-cognitod || true"
    ]
  }

  # Create default configuration template
  provisioner "shell" {
    inline = [
      "echo 'Creating configuration template...'",
      "sudo mkdir -p /etc/linnix/templates",
      "sudo cp /etc/linnix/linnix.toml /etc/linnix/templates/linnix.toml.template || true"
    ]
  }

  # Clean up
  provisioner "shell" {
    inline = [
      "echo 'Cleaning up...'",
      "sudo rm -rf /tmp/*",
      "sudo rm -rf /var/tmp/*",
      "sudo apt-get clean",
      "sudo apt-get autoremove -y",
      "# Clear logs",
      "sudo find /var/log -type f -name '*.log' -exec truncate -s 0 {} \\;",
      "sudo journalctl --vacuum-time=1s",
      "# Clear bash history",
      "history -c",
      "cat /dev/null > ~/.bash_history",
      "sudo rm -f /root/.bash_history",
      "# Clear SSH keys",
      "sudo rm -f /etc/ssh/ssh_host_*",
      "# Clear cloud-init",
      "sudo cloud-init clean --logs --seed",
      "echo 'Cleanup completed'"
    ]
  }

  # Create AMI metadata file
  provisioner "shell" {
    inline = [
      "echo 'Creating AMI metadata...'",
      "sudo tee /etc/linnix/ami-info.txt > /dev/null <<EOF",
      "Linnix AMI",
      "Build Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')",
      "Kernel: $(uname -r)",
      "Linnix Version: $(cognitod --version 2>/dev/null || echo 'unknown')",
      "Base OS: Ubuntu 22.04 LTS",
      "LLM Support: ${var.install_llm}",
      "EOF"
    ]
  }

  # Create first-boot script
  provisioner "file" {
    source      = "${path.root}/scripts/first-boot.sh"
    destination = "/tmp/first-boot.sh"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/first-boot.sh /usr/local/bin/linnix-first-boot.sh",
      "sudo chmod +x /usr/local/bin/linnix-first-boot.sh"
    ]
  }

  # Create systemd service for first-boot
  provisioner "shell" {
    inline = [
      "sudo tee /etc/systemd/system/linnix-first-boot.service > /dev/null <<'EOF'",
      "[Unit]",
      "Description=Linnix First Boot Configuration",
      "After=network.target cloud-final.service",
      "Before=linnix-cognitod.service",
      "",
      "[Service]",
      "Type=oneshot",
      "ExecStart=/usr/local/bin/linnix-first-boot.sh",
      "RemainAfterExit=yes",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",
      "sudo systemctl enable linnix-first-boot.service"
    ]
  }

  # Validate installation
  provisioner "shell" {
    inline = [
      "echo 'Validating Linnix installation...'",
      "which cognitod || (echo 'ERROR: cognitod not found' && exit 1)",
      "which linnix-cli || (echo 'ERROR: linnix-cli not found' && exit 1)",
      "test -f /usr/local/share/linnix/linnix-ai-ebpf-ebpf || (echo 'ERROR: eBPF program not found' && exit 1)",
      "test -f /etc/linnix/linnix.toml || (echo 'ERROR: Config not found' && exit 1)",
      "test -f /etc/systemd/system/linnix-cognitod.service || (echo 'ERROR: Service file not found' && exit 1)",
      "echo 'Validation successful!'"
    ]
  }

  # Create AMI manifest
  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }
}
