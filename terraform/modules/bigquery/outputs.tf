# =============================================================================
# BigQuery Module Outputs
# =============================================================================

output "dataset_id" {
  description = "The ID of the BigQuery dataset"
  value       = google_bigquery_dataset.security_findings.dataset_id
}

output "dataset_self_link" {
  description = "The self link of the BigQuery dataset"
  value       = google_bigquery_dataset.security_findings.self_link
}

output "trivy_vulnerabilities_table_id" {
  description = "The full table ID for raw Trivy vulnerability reports"
  value       = "${var.project_id}.${google_bigquery_dataset.security_findings.dataset_id}.${google_bigquery_table.trivy_vulnerabilities.table_id}"
}

output "processed_vulnerabilities_table_id" {
  description = "The full table ID for processed vulnerability records"
  value       = "${var.project_id}.${google_bigquery_dataset.security_findings.dataset_id}.${google_bigquery_table.processed_vulnerabilities.table_id}"
}

output "trivy_vulnerabilities_table_name" {
  description = "The table name for raw Trivy vulnerabilities"
  value       = google_bigquery_table.trivy_vulnerabilities.table_id
}

output "processed_vulnerabilities_table_name" {
  description = "The table name for processed vulnerabilities"
  value       = google_bigquery_table.processed_vulnerabilities.table_id
}
