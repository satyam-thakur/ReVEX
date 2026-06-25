variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3a.xlarge"
}

variable "ami_id" {
  description = "AMI ID"
  type        = string
  default     = "ami-065778886ef8ec7c8"
}

variable "volume_size" {
  description = "Root volume size in GB"
  type        = number
  default     = 25
}

variable "volume_type" {
  description = "Volume type"
  type        = string
  default     = "gp3"
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
  default     = "network-automation-key"
}

variable "instance_state" {
  description = "Instance state (running or stopped)"
  type        = string
  default     = "running"
}

variable "instance_name" {
  description = "Instance name"
  type        = string
  default     = "network-instance"
}

variable "user_data" {
  description = "user data script for EC2 instance."
  type        = string
  default     = ""
}

# GCP Variables
variable "gcp_project" {
  description = "GCP project ID"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-west2"
}

variable "gcp_zone" {
  description = "GCP zone"
  type        = string
  default     = "us-west2-a"
}

variable "gcp_machine_type" {
  description = "GCP Compute Engine machine type"
  type        = string
  default     = "e2-standard-16"
}

variable "gcp_disk_size" {
  description = "GCP boot disk size in GB"
  type        = number
  default     = 130
}

variable "gcp_disk_type" {
  description = "GCP disk type"
  type        = string
  default     = "pd-standard"
}

variable "gcp_instance_name" {
  description = "GCP instance name"
  type        = string
  default     = "network-instance-gcp"
}

variable "gcp_instance_state" {
  description = "GCP Instance state (RUNNING or TERMINATED)"
  type        = string
  default     = "RUNNING"
}

variable "gcp_max_run_duration" {
  description = "Maximum runtime duration for GCP instance (e.g., '3600s'). Set to null to disable."
  type        = string
  default     = null
}

variable "gcp_data_disk_size" {
  description = "Size of the persistent data disk in GB"
  type        = number
  default     = 50
}
