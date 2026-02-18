# =============================================================================
# Cloud Build Module Outputs
# =============================================================================

output "trivy_trigger_id" {
  description = "The ID of the Trivy deployment Cloud Build trigger"
  value       = google_cloudbuild_trigger.trivy_deploy.trigger_id
}

output "trivy_trigger_name" {
  description = "The name of the Trivy deployment Cloud Build trigger"
  value       = google_cloudbuild_trigger.trivy_deploy.name
}

output "terraform_plan_trigger_id" {
  description = "The ID of the Terraform plan Cloud Build trigger"
  value       = google_cloudbuild_trigger.terraform_plan.trigger_id
}

output "terraform_apply_trigger_id" {
  description = "The ID of the Terraform apply Cloud Build trigger"
  value       = google_cloudbuild_trigger.terraform_apply.trigger_id
}

output "terraform_trigger_id" {
  description = "The ID of the Terraform apply trigger (alias for backward compat)"
  value       = google_cloudbuild_trigger.terraform_apply.trigger_id
}
