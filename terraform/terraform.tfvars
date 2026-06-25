# ============================================
# AWS Configuration
# ============================================

aws_region = "us-west-2"
instance_type = "t3a.2xlarge"
ami_id        = "ami-065778886ef8ec7c8"
instance_name = "network-instance"
volume_size = 130
volume_type = "gp3"
instance_state = "stopped" # running or stopped

# ============================================
# GCP Configuration
# ============================================

# Set gcp_project to your GCP project ID to enable GCP instance
# Leave empty ("") to only use AWS
gcp_project      = "gen-lang-client-0699278642"  # Set to your GCP project ID like "my-project-12345"
gcp_region       = "us-west2"
gcp_zone         = "us-west2-a"
gcp_machine_type = "e2-standard-16"
gcp_disk_size    = 100
gcp_disk_type    = "pd-ssd"  # -standard or "pd-ssd" for better performance
gcp_instance_name = "network-instance-gcp"
gcp_instance_state = "TERMINATED"  # Options: "RUNNING" or "TERMINATED"
gcp_max_run_duration = "18000" # in s. Comment out to disable.
