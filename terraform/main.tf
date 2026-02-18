# =============================================================================
# Root Module - DevSecOps GKE Infrastructure
# =============================================================================
#
# This root module orchestrates the deployment of a security-hardened GKE
# cluster with comprehensive monitoring, vulnerability scanning, and
# threat detection capabilities.
#
# ARCHITECTURE OVERVIEW:
# - Private GKE cluster with Workload Identity and Binary Authorization
# - VPC with firewall rules blocking known C2 ports and suspicious traffic
# - BigQuery dataset for centralized security findings storage
# - IAM with Workload Identity Federation (no service account keys)
# - Cloud Build pipelines for Trivy deployment and Terraform CI/CD
#
# APT SCENARIO DETECTION:
# This infrastructure is designed to detect and prevent common APT tactics:
# 1. Magic files in /tmp       -> Falco rules + Trivy file scanning
# 2. C2 backconnect traffic    -> Firewall egress rules + Suricata IDS
# 3. Stolen service accounts   -> Workload Identity Federation (no keys to steal)
# 4. Crypto mining             -> Network monitoring + resource limits
# 5. Container escape          -> Pod Security Standards + Shielded Nodes
#
# =============================================================================

# -----------------------------------------------------------------------------
# Enable Required GCP APIs
# -----------------------------------------------------------------------------
# These APIs must be enabled before any resources can be created.
# Using google_project_service ensures they are enabled declaratively.
# -----------------------------------------------------------------------------

locals {
  required_apis = [
    "container.googleapis.com",           # GKE
    "compute.googleapis.com",             # Compute Engine (nodes, networking)
    "bigquery.googleapis.com",            # BigQuery
    "cloudbuild.googleapis.com",          # Cloud Build
    "iam.googleapis.com",                 # IAM
    "iamcredentials.googleapis.com",      # IAM Credentials (for WIF)
    "cloudresourcemanager.googleapis.com", # Resource Manager
    "binaryauthorization.googleapis.com", # Binary Authorization
    "containeranalysis.googleapis.com",   # Container Analysis (for vuln scanning)
    "logging.googleapis.com",             # Cloud Logging
    "monitoring.googleapis.com",          # Cloud Monitoring
    "sts.googleapis.com",                 # Security Token Service (for WIF)
  ]
}

resource "google_project_service" "apis" {
  for_each = toset(local.required_apis)

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false

  timeouts {
    create = "10m"
    update = "10m"
  }
}

# -----------------------------------------------------------------------------
# Network Module
# -----------------------------------------------------------------------------
# Creates the VPC, subnets, and firewall rules. The firewall rules include
# egress deny rules for known C2 ports (Metasploit 4444, Cobalt Strike 8443,
# IRC 6666/6667, etc.) to prevent compromised pods from calling home.
# -----------------------------------------------------------------------------

module "network" {
  source = "./modules/network"

  project_id       = var.project_id
  region           = var.region
  environment      = var.environment
  network_name     = var.network_name
  subnet_cidr      = var.subnet_cidr
  pods_cidr        = var.pods_cidr
  services_cidr    = var.services_cidr
  c2_blocked_ports = var.c2_blocked_ports
  c2_blocked_ips   = var.c2_blocked_ips
  labels           = var.labels

  depends_on = [google_project_service.apis]
}

# -----------------------------------------------------------------------------
# GKE Module
# -----------------------------------------------------------------------------
# Deploys a private GKE cluster with security hardening:
# - Private nodes (no public IPs on worker nodes)
# - Workload Identity (pods authenticate as Google SAs without keys)
# - Binary Authorization (only signed/trusted images can run)
# - Network Policy via Calico (microsegmentation between pods)
# - Shielded Nodes (secure boot, vTPM, integrity monitoring)
# - Auto-upgrade DISABLED for demo (uses older version with known CVEs)
# - Logging and monitoring integrated with Cloud Operations
# -----------------------------------------------------------------------------

module "gke" {
  source = "./modules/gke"

  project_id         = var.project_id
  region             = var.region
  zone               = var.zone
  environment        = var.environment
  cluster_name       = var.cluster_name
  gke_version        = var.gke_version
  network_self_link  = module.network.network_self_link
  subnet_self_link   = module.network.subnet_self_link
  pods_range_name    = module.network.pods_range_name
  services_range_name = module.network.services_range_name
  master_cidr        = var.master_cidr
  authorized_networks = var.authorized_networks
  node_count         = var.node_count
  node_machine_type  = var.node_machine_type
  node_disk_size_gb  = var.node_disk_size_gb
  max_pods_per_node  = var.max_pods_per_node
  labels             = var.labels

  depends_on = [
    google_project_service.apis,
    module.network,
  ]
}

# -----------------------------------------------------------------------------
# BigQuery Module
# -----------------------------------------------------------------------------
# Creates a BigQuery dataset with tables for storing security findings:
# - trivy_vulnerabilities: Raw Trivy scan results with full CVE details
# - processed_vulnerabilities: Deduplicated, enriched vulnerability records
# Both tables use time-based partitioning for efficient querying and
# automatic data lifecycle management.
# -----------------------------------------------------------------------------

module "bigquery" {
  source = "./modules/bigquery"

  project_id          = var.project_id
  environment         = var.environment
  dataset_id          = var.bigquery_dataset_id
  location            = var.bigquery_location
  log_retention_days  = var.log_retention_days
  labels              = var.labels

  depends_on = [google_project_service.apis]
}

# -----------------------------------------------------------------------------
# IAM Module
# -----------------------------------------------------------------------------
# Configures Identity and Access Management with a zero-trust approach:
# - Workload Identity Federation pool and GitHub OIDC provider
#   (GitHub Actions authenticate without long-lived service account keys)
# - Trivy SA: Read-only access to GKE + write to BigQuery
# - Cloud Build SA: Deploy to GKE + read from Artifact Registry
# - BigQuery Writer SA: Insert-only access to vulnerability tables
#
# IMPORTANT: No service account keys are generated. All authentication
# uses short-lived tokens via Workload Identity Federation or GKE
# Workload Identity. This eliminates the risk of key theft/exfiltration.
# -----------------------------------------------------------------------------

module "iam" {
  source = "./modules/iam"

  project_id   = var.project_id
  environment  = var.environment
  github_org   = var.github_org
  github_repo  = var.github_repo
  dataset_id   = module.bigquery.dataset_id
  cluster_name = module.gke.cluster_name
  labels       = var.labels

  depends_on = [
    google_project_service.apis,
    module.bigquery,
    module.gke,
  ]
}

# -----------------------------------------------------------------------------
# Cloud Build Module
# -----------------------------------------------------------------------------
# Sets up CI/CD pipelines:
# - Trivy Deployment Pipeline: Builds and deploys Trivy Operator to GKE
#   using Helm, configured to scan all namespaces and export findings
# - Terraform Pipeline: Runs terraform plan on PRs, terraform apply on merge
#   Both pipelines use the least-privilege service account from IAM module
# -----------------------------------------------------------------------------

module "cloudbuild" {
  source = "./modules/cloudbuild"

  project_id                    = var.project_id
  region                        = var.region
  environment                   = var.environment
  github_org                    = var.github_org
  github_repo                   = var.github_repo
  cloudbuild_service_account_id = module.iam.cloudbuild_service_account_id
  labels                        = var.labels

  depends_on = [
    google_project_service.apis,
    module.iam,
  ]
}
