# =============================================================================
# Production Environment Configuration
# =============================================================================
#
# This file defines the production-specific values for the DevSecOps
# infrastructure. It calls the root module with production parameters.
#
# USAGE:
#   cd terraform/environments/prod
#   terraform init
#   terraform plan -out=tfplan
#   terraform apply tfplan
#
# Or via Cloud Build:
#   The cloudbuild-terraform.yaml pipeline handles init/plan/apply automatically.
#
# SECURITY NOTES FOR PRODUCTION:
# - authorized_networks should be restricted to your office/VPN CIDRs
# - GKE version should use release channel REGULAR (not pinned old version)
# - Consider enabling private_endpoint for maximum cluster isolation
# - Review and update c2_blocked_ips from current threat intel feeds
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }

  # Production state stored in dedicated GCS bucket with environment prefix
  backend "gcs" {
    bucket = "devsecops-demo-terraform-state"
    prefix = "terraform/environments/prod"
  }
}

# -----------------------------------------------------------------------------
# Local Variables
# -----------------------------------------------------------------------------

locals {
  environment = "prod"
  project_id  = "devsecops-demo-prod"  # Replace with your actual project ID
  region      = "us-central1"
  zone        = "us-central1-a"
}

# -----------------------------------------------------------------------------
# Root Module Invocation
# -----------------------------------------------------------------------------

module "infrastructure" {
  source = "../../"

  # Project & Environment
  project_id  = local.project_id
  region      = local.region
  zone        = local.zone
  environment = local.environment

  # Networking
  network_name = "devsecops-vpc"
  subnet_cidr  = "10.0.0.0/20"
  pods_cidr    = "10.16.0.0/14"
  services_cidr = "10.20.0.0/20"
  master_cidr  = "172.16.0.0/28"

  # Restrict master access to known networks in production
  authorized_networks = [
    {
      cidr_block   = "10.0.0.0/8"
      display_name = "Internal network"
    },
    # Add your office/VPN CIDRs here:
    # {
    #   cidr_block   = "203.0.113.0/24"
    #   display_name = "Office network"
    # },
  ]

  # GKE Cluster
  cluster_name      = "devsecops-gke"
  node_count        = 2
  node_machine_type = "e2-standard-4"
  node_disk_size_gb = 100
  max_pods_per_node = 110

  # DEMO: Using older version for vulnerability scanning demonstration
  # PRODUCTION: Comment this out and use release_channel = "REGULAR" in the module
  gke_version = "1.27.16-gke.1287000"

  # BigQuery
  bigquery_dataset_id = "security_findings"
  bigquery_location   = "US"
  log_retention_days  = 90

  # IAM & Workload Identity Federation
  github_org  = "devsecops-demo"   # Replace with your GitHub org
  github_repo = "devsecops-project" # Replace with your GitHub repo

  # Security - C2 Port Blocking
  # These ports are commonly used by C2 frameworks and will be blocked at egress
  c2_blocked_ports = [
    4444,   # Metasploit default handler / Meterpreter reverse shell
    5555,   # Android Debug Bridge / various RATs
    6666,   # IRC-based C2 channels
    6667,   # IRC-based C2 channels (standard IRC)
    8443,   # Cobalt Strike default HTTPS listener
    9090,   # Merlin C2 framework / various C2
    1337,   # Common "leet" backdoor port
    31337,  # Back Orifice / elite hackers backdoor
    12345,  # NetBus trojan
    65535,  # Common data exfiltration port
  ]

  # Known malicious IP ranges (update from threat intel feeds)
  # These are example ranges -- replace with actual threat intel
  c2_blocked_ips = [
    # Example: known C2 infrastructure
    # "198.51.100.0/24",
    # "203.0.113.0/24",
  ]

  # Labels for cost tracking and organization
  labels = {
    managed_by  = "terraform"
    project     = "devsecops-demo"
    environment = "prod"
    security    = "high"
    team        = "platform-security"
  }
}

# -----------------------------------------------------------------------------
# Production Outputs
# -----------------------------------------------------------------------------

output "cluster_name" {
  description = "Production GKE cluster name"
  value       = module.infrastructure.cluster_name
}

output "kubectl_command" {
  description = "Command to connect to the production cluster"
  value       = module.infrastructure.kubectl_connection_command
}

output "bigquery_dataset" {
  description = "BigQuery dataset for security findings"
  value       = module.infrastructure.bigquery_dataset_id
}

output "security_summary" {
  description = "Summary of security controls"
  value       = module.infrastructure.security_summary
}

output "workload_identity_provider" {
  description = "WIF provider for GitHub Actions configuration"
  value       = module.infrastructure.workload_identity_provider_name
}
