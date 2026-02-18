# =============================================================================
# Root Module Outputs
# =============================================================================
# Exposes key infrastructure values needed by CI/CD pipelines,
# security tooling, and operational procedures.
# =============================================================================

# -----------------------------------------------------------------------------
# GKE Cluster Outputs
# -----------------------------------------------------------------------------

output "cluster_name" {
  description = "The name of the GKE cluster"
  value       = module.gke.cluster_name
}

output "cluster_endpoint" {
  description = "The IP address of the GKE cluster master endpoint"
  value       = module.gke.cluster_endpoint
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "The public certificate authority of the cluster (base64-encoded)"
  value       = module.gke.cluster_ca_certificate
  sensitive   = true
}

output "cluster_location" {
  description = "The location (zone) of the GKE cluster"
  value       = module.gke.cluster_location
}

output "kubectl_connection_command" {
  description = "Command to configure kubectl for this cluster"
  value       = "gcloud container clusters get-credentials ${module.gke.cluster_name} --zone ${var.zone} --project ${var.project_id}"
}

# -----------------------------------------------------------------------------
# Network Outputs
# -----------------------------------------------------------------------------

output "network_name" {
  description = "The name of the VPC network"
  value       = module.network.network_name
}

output "network_self_link" {
  description = "The self link of the VPC network"
  value       = module.network.network_self_link
}

output "subnet_name" {
  description = "The name of the GKE subnet"
  value       = module.network.subnet_name
}

# -----------------------------------------------------------------------------
# BigQuery Outputs
# -----------------------------------------------------------------------------

output "bigquery_dataset_id" {
  description = "The ID of the BigQuery dataset for security findings"
  value       = module.bigquery.dataset_id
}

output "trivy_vulnerabilities_table_id" {
  description = "The full table ID for raw Trivy vulnerability reports"
  value       = module.bigquery.trivy_vulnerabilities_table_id
}

output "processed_vulnerabilities_table_id" {
  description = "The full table ID for processed/deduplicated vulnerabilities"
  value       = module.bigquery.processed_vulnerabilities_table_id
}

# -----------------------------------------------------------------------------
# IAM Outputs
# -----------------------------------------------------------------------------

output "workload_identity_pool_name" {
  description = "The full resource name of the Workload Identity Federation pool"
  value       = module.iam.workload_identity_pool_name
}

output "workload_identity_provider_name" {
  description = "The full resource name of the Workload Identity Federation provider"
  value       = module.iam.workload_identity_provider_name
}

output "trivy_service_account_email" {
  description = "Email of the Trivy operator service account (used with Workload Identity)"
  value       = module.iam.trivy_service_account_email
}

output "cloudbuild_service_account_email" {
  description = "Email of the Cloud Build service account"
  value       = module.iam.cloudbuild_service_account_email
}

output "bigquery_writer_service_account_email" {
  description = "Email of the BigQuery writer service account"
  value       = module.iam.bigquery_writer_service_account_email
}

# -----------------------------------------------------------------------------
# Cloud Build Outputs
# -----------------------------------------------------------------------------

output "trivy_build_trigger_id" {
  description = "The ID of the Cloud Build trigger for Trivy deployment"
  value       = module.cloudbuild.trivy_trigger_id
}

output "terraform_build_trigger_id" {
  description = "The ID of the Cloud Build trigger for Terraform CI/CD"
  value       = module.cloudbuild.terraform_trigger_id
}

# -----------------------------------------------------------------------------
# Security Summary
# -----------------------------------------------------------------------------

output "security_summary" {
  description = "Summary of security configurations applied to the infrastructure"
  value = {
    private_cluster          = true
    workload_identity        = true
    binary_authorization     = true
    network_policy           = true
    shielded_nodes           = true
    c2_ports_blocked         = var.c2_blocked_ports
    service_account_keys     = "NONE - Using Workload Identity Federation only"
    vulnerability_scanning   = "Trivy Operator deployed via Cloud Build"
    security_logging         = "BigQuery dataset: ${module.bigquery.dataset_id}"
  }
}
