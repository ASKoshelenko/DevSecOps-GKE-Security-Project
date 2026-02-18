# =============================================================================
# Root Module Variables
# =============================================================================
# All configurable parameters for the DevSecOps infrastructure.
# Variables are organized by resource type for clarity.
# =============================================================================

# -----------------------------------------------------------------------------
# Project & Environment
# -----------------------------------------------------------------------------

variable "project_id" {
  description = "The GCP project ID where all resources will be created"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be 6-30 characters, start with a letter, and contain only lowercase letters, digits, and hyphens."
  }
}

variable "region" {
  description = "The GCP region for resource deployment"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The GCP zone for zonal resources (e.g., GKE nodes)"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment name (e.g., prod, staging, dev). Used for resource naming and tagging."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "Environment must be one of: prod, staging, dev."
  }
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------

variable "network_name" {
  description = "Name of the VPC network"
  type        = string
  default     = "devsecops-vpc"
}

variable "subnet_cidr" {
  description = "Primary CIDR range for the GKE subnet"
  type        = string
  default     = "10.0.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary CIDR range for GKE pods"
  type        = string
  default     = "10.16.0.0/14"
}

variable "services_cidr" {
  description = "Secondary CIDR range for GKE services"
  type        = string
  default     = "10.20.0.0/20"
}

variable "master_cidr" {
  description = "CIDR range for the GKE master (control plane) nodes. Must be /28."
  type        = string
  default     = "172.16.0.0/28"
}

variable "authorized_networks" {
  description = "List of CIDR blocks authorized to access the GKE master endpoint"
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = [
    {
      cidr_block   = "0.0.0.0/0"
      display_name = "All networks (restrict in production)"
    }
  ]
}

# -----------------------------------------------------------------------------
# GKE Cluster
# -----------------------------------------------------------------------------

variable "cluster_name" {
  description = "Name of the GKE cluster"
  type        = string
  default     = "devsecops-gke"
}

variable "gke_version" {
  description = <<-EOT
    Kubernetes version for the GKE cluster.
    NOTE: For the APT demo scenario, we intentionally use an older version
    that has known vulnerabilities (e.g., container escape CVEs).
    In production, always use the latest stable version.
  EOT
  type        = string
  default     = "1.27.16-gke.1287000"
}

variable "node_count" {
  description = "Number of nodes per zone in the default node pool"
  type        = number
  default     = 2

  validation {
    condition     = var.node_count >= 1 && var.node_count <= 10
    error_message = "Node count must be between 1 and 10."
  }
}

variable "node_machine_type" {
  description = "Machine type for GKE worker nodes"
  type        = string
  default     = "e2-standard-4"
}

variable "node_disk_size_gb" {
  description = "Disk size in GB for each GKE node"
  type        = number
  default     = 100
}

variable "max_pods_per_node" {
  description = "Maximum number of pods per node (affects IP allocation)"
  type        = number
  default     = 110
}

# -----------------------------------------------------------------------------
# BigQuery
# -----------------------------------------------------------------------------

variable "bigquery_dataset_id" {
  description = "ID for the BigQuery dataset that stores security scan results"
  type        = string
  default     = "security_findings"
}

variable "bigquery_location" {
  description = "Location for the BigQuery dataset"
  type        = string
  default     = "US"
}

variable "log_retention_days" {
  description = "Number of days to retain vulnerability logs in BigQuery"
  type        = number
  default     = 90
}

# -----------------------------------------------------------------------------
# IAM & Workload Identity
# -----------------------------------------------------------------------------

variable "github_org" {
  description = "GitHub organization name for Workload Identity Federation"
  type        = string
  default     = "devsecops-demo"
}

variable "github_repo" {
  description = "GitHub repository name for Workload Identity Federation"
  type        = string
  default     = "devsecops-project"
}

# -----------------------------------------------------------------------------
# Security - C2 Blocking
# -----------------------------------------------------------------------------

variable "c2_blocked_ports" {
  description = <<-EOT
    List of TCP ports commonly used by C2 (Command & Control) frameworks.
    These ports will be blocked at the firewall level for egress traffic.

    Common C2 ports:
    - 4444: Metasploit default handler
    - 5555: Many RATs and backdoors
    - 6666/6667: IRC-based C2
    - 8443: Cobalt Strike default
    - 9090: Various C2 frameworks
    - 1337: Common backdoor port
    - 31337: Back Orifice / elite backdoor
    - 12345: NetBus
    - 65535: Common exfiltration port
  EOT
  type        = list(number)
  default     = [4444, 5555, 6666, 6667, 8443, 9090, 1337, 31337, 12345, 65535]
}

variable "c2_blocked_ips" {
  description = "List of known C2 IP ranges to block (CIDR notation). Update from threat intel feeds."
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Labels
# -----------------------------------------------------------------------------

variable "labels" {
  description = "Common labels applied to all resources for cost tracking and organization"
  type        = map(string)
  default = {
    managed_by  = "terraform"
    project     = "devsecops-demo"
    security    = "high"
  }
}
