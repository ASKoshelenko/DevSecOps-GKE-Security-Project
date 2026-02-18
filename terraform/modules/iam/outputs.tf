# =============================================================================
# IAM Module Outputs
# =============================================================================

# Workload Identity Federation
output "workload_identity_pool_name" {
  description = "The full resource name of the Workload Identity Federation pool"
  value       = google_iam_workload_identity_pool.github_pool.name
}

output "workload_identity_pool_id" {
  description = "The ID of the Workload Identity Federation pool"
  value       = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
}

output "workload_identity_provider_name" {
  description = "The full resource name of the Workload Identity Federation provider"
  value       = google_iam_workload_identity_pool_provider.github_provider.name
}

# Trivy Service Account
output "trivy_service_account_email" {
  description = "Email of the Trivy operator service account"
  value       = google_service_account.trivy_operator.email
}

output "trivy_service_account_id" {
  description = "ID of the Trivy operator service account"
  value       = google_service_account.trivy_operator.id
}

# Cloud Build Service Account
output "cloudbuild_service_account_email" {
  description = "Email of the Cloud Build deployer service account"
  value       = google_service_account.cloudbuild.email
}

output "cloudbuild_service_account_id" {
  description = "ID of the Cloud Build deployer service account"
  value       = google_service_account.cloudbuild.id
}

# BigQuery Writer Service Account
output "bigquery_writer_service_account_email" {
  description = "Email of the BigQuery vulnerability writer service account"
  value       = google_service_account.bigquery_writer.email
}

output "bigquery_writer_service_account_id" {
  description = "ID of the BigQuery vulnerability writer service account"
  value       = google_service_account.bigquery_writer.id
}

# Falco Service Account
output "falco_service_account_email" {
  description = "Email of the Falco runtime monitor service account"
  value       = google_service_account.falco.email
}

# GitHub Actions WIF Configuration Output
# This output provides the exact values needed in GitHub Actions workflows
output "github_actions_wif_config" {
  description = "Configuration values for GitHub Actions Workload Identity Federation"
  value = {
    workload_identity_provider = google_iam_workload_identity_pool_provider.github_provider.name
    service_account_email      = google_service_account.cloudbuild.email
    instructions               = "Use google-github-actions/auth@v2 with these values in your GitHub Actions workflow"
  }
}
