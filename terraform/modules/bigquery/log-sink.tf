# =============================================================================
# BigQuery Log Sink for Trivy Operator
# =============================================================================
# Creates a Google Cloud Logging sink that routes Trivy Operator logs from
# GKE to the existing BigQuery security findings dataset.
#
# This configuration:
#   - Creates a dedicated BigQuery dataset for streaming operator logs
#   - Creates a log sink filtered for trivy-operator namespace logs
#   - Creates a second log sink for structured scan results only
#   - Grants the log sink service accounts write access to BigQuery
#   - Optionally grants the security team read access
#
# NOTE: This file integrates with the existing BigQuery module variables
# defined in variables.tf (project_id, dataset_id, log_retention_days, labels).
# Only new variables specific to log sinks are declared here.
#
# PREREQUISITES:
#   - Google Cloud project with Logging and BigQuery APIs enabled
#   - Terraform service account with roles:
#     - roles/logging.configWriter
#     - roles/bigquery.dataEditor
#     - roles/iam.serviceAccountAdmin
# =============================================================================

# -----------------------------------------------------------------------------
# Additional Variables (log-sink-specific)
# -----------------------------------------------------------------------------
# Variables shared with the module (project_id, dataset_id, log_retention_days,
# location, labels) are declared in variables.tf.
# -----------------------------------------------------------------------------

variable "gke_cluster_name" {
  description = "The name of the GKE cluster running Trivy Operator"
  type        = string
  default     = ""
}

variable "gke_cluster_location" {
  description = "The location (region/zone) of the GKE cluster"
  type        = string
  default     = ""
}

variable "enable_trivy_log_sink" {
  description = "Whether to create the Trivy Operator log sinks. Set to false to skip."
  type        = bool
  default     = true
}

variable "security_team_group" {
  description = "Google Group email for the security team (e.g., security-team@example.com). Leave empty to skip."
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# BigQuery Dataset for Trivy Operator Streaming Logs
# -----------------------------------------------------------------------------
# A separate dataset for streaming operator logs from Cloud Logging.
# This is distinct from the security_findings dataset (in main.tf) which
# stores structured scan results ingested via pipeline.
#
# Streaming logs include:
#   - Operator controller lifecycle events (reconciliation, errors)
#   - Scan job stdout/stderr (DB downloads, scan progress)
#   - Trivy scanner output (CVE matches, timing)
#
# Partitioned by ingestion time for efficient querying and auto-cleanup.
# -----------------------------------------------------------------------------
resource "google_bigquery_dataset" "trivy_operator_logs" {
  count = var.enable_trivy_log_sink ? 1 : 0

  dataset_id    = "trivy_operator_logs_${var.environment}"
  project       = var.project_id
  friendly_name = "Trivy Operator Streaming Logs (${var.environment})"
  description   = "GKE container logs from the trivy-system namespace streamed via Cloud Logging sink. Includes operator events, scan job output, and scanner results."
  location      = var.location

  # Auto-expire log tables after the retention period.
  # Streaming logs are operational data, not long-term compliance records.
  default_table_expiration_ms    = var.log_retention_days * 24 * 3600 * 1000
  default_partition_expiration_ms = var.log_retention_days * 24 * 3600 * 1000

  labels = merge(var.labels, {
    dataset   = "trivy-operator-logs"
    data_type = "streaming-logs"
  })

  # Prevent accidental deletion of production log data
  delete_contents_on_destroy = false
}

# -----------------------------------------------------------------------------
# Log Sink: Trivy Operator Logs to BigQuery
# -----------------------------------------------------------------------------
# Routes all container logs from the trivy-system namespace to BigQuery.
# The filter captures:
#   - Operator controller logs (reconciliation events, errors)
#   - Scan job logs (vulnerability findings, DB updates)
#   - Trivy scanner output (CVE matches, SBOM generation)
#
# Log entries are streamed to BigQuery in near real-time using the
# BigQuery Streaming API.
# -----------------------------------------------------------------------------
resource "google_logging_project_sink" "trivy_operator_logs" {
  count = var.enable_trivy_log_sink ? 1 : 0

  name        = "trivy-operator-bigquery-sink-${var.environment}"
  project     = var.project_id
  description = "Routes Trivy Operator logs from GKE to BigQuery for security analysis and compliance reporting"

  # Destination is the dedicated log dataset
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.trivy_operator_logs[0].dataset_id}"

  # ---------------------------------------------------------------------------
  # Log Filter
  # ---------------------------------------------------------------------------
  # This filter captures all logs from the trivy-system namespace in the
  # specified GKE cluster. The filter uses Cloud Logging's advanced filter
  # syntax to match on:
  #   1. Resource type: GKE container logs
  #   2. Cluster name: The specific GKE cluster
  #   3. Namespace: trivy-system (where the operator and scan jobs run)
  #
  # Additional severity filter ensures we capture INFO and above to avoid
  # excessive DEBUG log volume in BigQuery.
  # ---------------------------------------------------------------------------
  filter = <<-EOT
    resource.type="k8s_container"
    resource.labels.cluster_name="${var.gke_cluster_name}"
    resource.labels.namespace_name="trivy-system"
    severity >= INFO
    OR (
      resource.type="k8s_container"
      resource.labels.cluster_name="${var.gke_cluster_name}"
      resource.labels.namespace_name="trivy-system"
      jsonPayload.controller="vulnerabilityreport"
    )
    OR (
      resource.type="k8s_container"
      resource.labels.cluster_name="${var.gke_cluster_name}"
      resource.labels.namespace_name="trivy-system"
      jsonPayload.controller="configauditreport"
    )
  EOT

  # Use partitioned tables for better query performance and cost efficiency.
  # Logs are partitioned by ingestion time (day granularity).
  bigquery_options {
    use_partitioned_tables = true
  }

  # Unique writer identity creates a dedicated service account for this sink.
  # This is required for BigQuery destinations to grant proper write access.
  unique_writer_identity = true
}

# -----------------------------------------------------------------------------
# Log Sink: Trivy Scan Results (Structured)
# -----------------------------------------------------------------------------
# A second, more targeted sink that captures only vulnerability scan results
# and config audit findings. This produces a cleaner dataset for security
# dashboards and alerting.
# -----------------------------------------------------------------------------
resource "google_logging_project_sink" "trivy_scan_results" {
  count = var.enable_trivy_log_sink ? 1 : 0

  name        = "trivy-scan-results-bigquery-sink-${var.environment}"
  project     = var.project_id
  description = "Routes Trivy scan result logs (vulnerabilities, config audits, exposed secrets) to BigQuery"

  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.trivy_operator_logs[0].dataset_id}"

  # Filter specifically for scan result log entries.
  # Trivy Operator emits structured JSON logs with specific fields
  # when scan results are processed.
  filter = <<-EOT
    resource.type="k8s_container"
    resource.labels.cluster_name="${var.gke_cluster_name}"
    resource.labels.namespace_name="trivy-system"
    (
      jsonPayload.msg=~"^Reconciled (VulnerabilityReport|ConfigAuditReport|ExposedSecretReport|SbomReport|ClusterComplianceReport)"
      OR jsonPayload.msg=~"^Found vulnerabilities"
      OR jsonPayload.msg=~"^Scan completed"
      OR severity >= WARNING
    )
  EOT

  bigquery_options {
    use_partitioned_tables = true
  }

  unique_writer_identity = true
}

# -----------------------------------------------------------------------------
# IAM: Grant Log Sink Service Accounts BigQuery Access
# -----------------------------------------------------------------------------
# Each log sink with unique_writer_identity=true creates a Google-managed
# service account. This service account needs bigquery.dataEditor role
# on the dataset to write log entries.
# -----------------------------------------------------------------------------
resource "google_bigquery_dataset_iam_member" "trivy_logs_writer" {
  count = var.enable_trivy_log_sink ? 1 : 0

  project    = var.project_id
  dataset_id = google_bigquery_dataset.trivy_operator_logs[0].dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.trivy_operator_logs[0].writer_identity
}

resource "google_bigquery_dataset_iam_member" "trivy_scan_results_writer" {
  count = var.enable_trivy_log_sink ? 1 : 0

  project    = var.project_id
  dataset_id = google_bigquery_dataset.trivy_operator_logs[0].dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.trivy_scan_results[0].writer_identity
}

# -----------------------------------------------------------------------------
# IAM: Grant Security Team Read Access to Log Dataset
# -----------------------------------------------------------------------------
# Allow the security team to query Trivy operator logs in BigQuery for
# incident response and operational analysis.
# -----------------------------------------------------------------------------
resource "google_bigquery_dataset_iam_member" "trivy_logs_security_team_viewer" {
  count = var.enable_trivy_log_sink && var.security_team_group != "" ? 1 : 0

  project    = var.project_id
  dataset_id = google_bigquery_dataset.trivy_operator_logs[0].dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "group:${var.security_team_group}"
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "trivy_logs_dataset_id" {
  description = "The BigQuery dataset ID containing Trivy operator streaming logs"
  value       = var.enable_trivy_log_sink ? google_bigquery_dataset.trivy_operator_logs[0].dataset_id : ""
}

output "trivy_logs_dataset_self_link" {
  description = "The self link of the Trivy logs BigQuery dataset"
  value       = var.enable_trivy_log_sink ? google_bigquery_dataset.trivy_operator_logs[0].self_link : ""
}

output "trivy_operator_log_sink_name" {
  description = "The name of the log sink for Trivy operator logs"
  value       = var.enable_trivy_log_sink ? google_logging_project_sink.trivy_operator_logs[0].name : ""
}

output "trivy_operator_log_sink_writer_identity" {
  description = "The service account identity of the log sink (for additional IAM grants)"
  value       = var.enable_trivy_log_sink ? google_logging_project_sink.trivy_operator_logs[0].writer_identity : ""
}

output "trivy_scan_results_sink_name" {
  description = "The name of the log sink for Trivy scan results"
  value       = var.enable_trivy_log_sink ? google_logging_project_sink.trivy_scan_results[0].name : ""
}

output "trivy_scan_results_sink_writer_identity" {
  description = "The service account identity of the scan results log sink"
  value       = var.enable_trivy_log_sink ? google_logging_project_sink.trivy_scan_results[0].writer_identity : ""
}
