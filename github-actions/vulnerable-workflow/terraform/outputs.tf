# =============================================================================
# Outputs
# =============================================================================
#
# These outputs are displayed during terraform plan/apply and are stored in
# the Terraform state file. Be cautious about outputting sensitive values -
# they will be visible in:
#   1. CI/CD logs (plan output)
#   2. PR comments (if the workflow posts plan output)
#   3. Terraform state file (stored in GCS)
# =============================================================================

output "app_data_bucket_name" {
  description = "Name of the application data GCS bucket"
  value       = google_storage_bucket.app_data.name
}

output "app_data_bucket_url" {
  description = "URL of the application data GCS bucket"
  value       = google_storage_bucket.app_data.url
}

output "app_data_bucket_self_link" {
  description = "Self-link of the application data GCS bucket"
  value       = google_storage_bucket.app_data.self_link
}

output "notification_topic_name" {
  description = "Pub/Sub topic name for bucket notifications"
  value       = google_pubsub_topic.bucket_notifications.name
}

output "notification_topic_id" {
  description = "Pub/Sub topic ID for bucket notifications"
  value       = google_pubsub_topic.bucket_notifications.id
}
