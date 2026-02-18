# =============================================================================
# Network Module Variables
# =============================================================================

variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "region" {
  description = "The GCP region for the network resources"
  type        = string
}

variable "environment" {
  description = "Environment name (prod, staging, dev)"
  type        = string
}

variable "network_name" {
  description = "Name prefix for the VPC network"
  type        = string
}

variable "subnet_cidr" {
  description = "Primary CIDR range for the GKE subnet"
  type        = string
}

variable "pods_cidr" {
  description = "Secondary CIDR range for GKE pods"
  type        = string
}

variable "services_cidr" {
  description = "Secondary CIDR range for GKE services"
  type        = string
}

variable "master_cidr" {
  description = "CIDR for GKE master (needed for firewall rules)"
  type        = string
  default     = "172.16.0.0/28"
}

variable "c2_blocked_ports" {
  description = "List of TCP/UDP ports to block (known C2 ports)"
  type        = list(number)
  default     = []
}

variable "c2_blocked_ips" {
  description = "List of known malicious IP ranges to block (CIDR)"
  type        = list(string)
  default     = []
}

variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default     = {}
}
