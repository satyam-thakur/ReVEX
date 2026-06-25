# Security Group
output "aws_security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.network_sg.id
}

# Instance Information
output "aws_instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.network_instance.id
}

output "aws_instance_public_ip" {
  description = "Public IP address"
  value       = aws_instance.network_instance.public_ip
}

output "aws_instance_private_ip" {
  description = "Private IP address"
  value       = aws_instance.network_instance.private_ip
}

output "aws_instance_state" {
  description = "Instance state"
  value       = aws_ec2_instance_state.instance_state.state
}

output "aws_public_dns" {
  description = "Public DNS name"
  value       = aws_instance.network_instance.public_dns
}

# SSH Connection String
output "aws_ssh_command" {
  description = "SSH connection command"
  value       = "ssh -i ~/.ssh/${var.key_name}.pem ubuntu@${aws_instance.network_instance.public_ip}"
}

# ============================================
# GCP Outputs
# ============================================

output "gcp_instance_public_ip" {
  description = "Public IP address of the GCP instance"
  value       = length(google_compute_instance.network_instance) > 0 ? google_compute_instance.network_instance[0].network_interface[0].access_config[0].nat_ip : null
}

output "gcp_instance_id" {
  description = "GCP Instance ID"
  value       = length(google_compute_instance.network_instance) > 0 ? google_compute_instance.network_instance[0].instance_id : null
}

output "gcp_ssh_command" {
  description = "SSH command for GCP instance"
  value       = length(google_compute_instance.network_instance) > 0 ? "ssh -i ~/.ssh/gcp_key ubuntu@${google_compute_instance.network_instance[0].network_interface[0].access_config[0].nat_ip}" : null
}
