# Security Group - Allow SSH access
resource "aws_security_group" "network_sg" {
  name        = "network-instance-sg"
  description = "Allow SSH access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Change to specific IP for better security
  }

  # Enabling all incoming traffic for test
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "network-instance-sg"
  }
}

# EC2 Instance
resource "aws_instance" "network_instance" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.network_sg.id]

  root_block_device {
    volume_size = var.volume_size
    volume_type = var.volume_type
  }

  # Use the `user_data` variable if provided; otherwise fall back to the bundled script file.
  user_data = var.user_data != "" ? var.user_data : file("${path.module}/user_data.sh")

  tags = {
    Name = var.instance_name
  }
}

# Control instance state (running/stopped)
resource "aws_ec2_instance_state" "instance_state" {
  instance_id = aws_instance.network_instance.id
  state       = var.instance_state
}

# ============================================
# GCP Resources
# ============================================

# GCP Firewall - Allow SSH and all traffic for testing
resource "google_compute_firewall" "network_fw" {
  count   = var.gcp_project != "" ? 1 : 0
  name    = "network-instance-firewall"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # Allow all incoming traffic for testing (similar to AWS config)
  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["network-instance"]
}

# GCP Compute Instance (e2-standard-16)
resource "google_compute_instance" "network_instance" {
  count          = var.gcp_project != "" ? 1 : 0
  name           = var.gcp_instance_name
  machine_type   = var.gcp_machine_type
  zone           = var.gcp_zone
  desired_status = var.gcp_instance_state

  boot_disk {
    auto_delete = false
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = var.gcp_disk_size
      type  = var.gcp_disk_type
    }
  }

  network_interface {
    network = "default"
    access_config {
      // Ephemeral public IP
    }
  }

  scheduling {
    automatic_restart   = var.gcp_max_run_duration != null ? false : true
    on_host_maintenance = "MIGRATE"
    
    # Configure max run duration if variable is set
    # Note: When max_run_duration is set, the instance termination action is effectively DELETE
    # but strictly speaking, max_run_duration works best with specific termination actions.
    # We use a dynamic block or direct assignment if supported.
    # For standard instances, max_run_duration might require instance to be properly configured.
    # Using 'instance_termination_action' is often required with max_run_duration.
    
    max_run_duration {
      seconds = var.gcp_max_run_duration != null ? tonumber(regex("^[0-9]+", var.gcp_max_run_duration)) : 0
      nanos   = 0
    }
    
    instance_termination_action = var.gcp_max_run_duration != null ? "STOP" : null
  }

  tags = ["network-instance"]

  metadata = {
    ssh-keys       = "ubuntu:${file("~/.ssh/gcp_key.pub")}"
    startup-script = var.user_data != "" ? var.user_data : file("${path.module}/user_data.sh")
  }
}
