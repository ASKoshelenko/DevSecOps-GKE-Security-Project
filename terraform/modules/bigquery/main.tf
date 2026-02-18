# =============================================================================
# BigQuery Module - Security Findings Data Warehouse
# =============================================================================
#
# Creates a BigQuery dataset and tables for storing and analyzing security
# findings from Trivy vulnerability scans, Falco runtime alerts, and
# other security tools.
#
# TABLES:
# 1. trivy_vulnerabilities: Raw vulnerability scan results from Trivy Operator
#    - Ingested via Cloud Build pipeline or CronJob
#    - Contains full CVE details, CVSS scores, affected packages
#    - Partitioned by scan timestamp for efficient time-range queries
#
# 2. processed_vulnerabilities: Deduplicated and enriched vulnerability records
#    - Populated by scheduled queries or Cloud Functions
#    - Includes remediation status, SLA tracking, risk scoring
#    - Used for dashboards and compliance reporting
#
# DATA LIFECYCLE:
# - Raw data retained for configurable period (default 90 days)
# - Processed data retained indefinitely for compliance
# - Partitioning reduces query costs by scanning only relevant data
# =============================================================================

# -----------------------------------------------------------------------------
# BigQuery Dataset
# -----------------------------------------------------------------------------

resource "google_bigquery_dataset" "security_findings" {
  dataset_id    = "${var.dataset_id}_${var.environment}"
  project       = var.project_id
  friendly_name = "Security Findings (${var.environment})"
  description   = "Centralized storage for vulnerability scans, runtime alerts, and security findings"
  location      = var.location

  # Default table expiration (optional; individual tables can override)
  # Not set here because processed_vulnerabilities should be retained longer
  # default_table_expiration_ms = var.log_retention_days * 24 * 3600 * 1000

  # Default partition expiration for time-partitioned tables
  default_partition_expiration_ms = var.log_retention_days * 24 * 3600 * 1000

  # Access controls are managed via IAM bindings in the IAM module.
  # Dataset-level access here is for the default setup only.

  labels = merge(var.labels, {
    dataset = var.dataset_id
  })

  # Prevent accidental deletion of production data
  delete_contents_on_destroy = false
}

# -----------------------------------------------------------------------------
# Table: trivy_vulnerabilities (Raw Scan Results)
# -----------------------------------------------------------------------------
# Stores raw vulnerability scan results from the Trivy Operator.
# Each row represents a single vulnerability found in a container image.
#
# Schema design considerations:
# - scan_id: Groups all vulns from a single scan for correlation
# - image_ref: Full image reference including digest for traceability
# - cvss_score: Numeric score for severity-based filtering
# - fixed_version: Identifies if a fix is available (critical for SLA)
# - resource_namespace/name: Links vuln to the K8s workload
# -----------------------------------------------------------------------------

resource "google_bigquery_table" "trivy_vulnerabilities" {
  dataset_id          = google_bigquery_dataset.security_findings.dataset_id
  table_id            = "trivy_vulnerabilities"
  project             = var.project_id
  friendly_name       = "Trivy Vulnerability Scan Results"
  description         = "Raw vulnerability findings from Trivy Operator scans of container images"
  deletion_protection = false

  # Partition by scan timestamp for efficient time-range queries
  time_partitioning {
    type          = "DAY"
    field         = "scan_timestamp"
    expiration_ms = var.log_retention_days * 24 * 3600 * 1000
  }

  # Cluster by severity and namespace for common query patterns
  clustering = ["severity", "resource_namespace", "vulnerability_id"]

  labels = merge(var.labels, {
    table = "trivy-vulnerabilities"
  })

  schema = jsonencode([
    {
      name        = "scan_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Unique identifier for the scan run"
    },
    {
      name        = "scan_timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Timestamp when the scan was performed"
    },
    {
      name        = "vulnerability_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "CVE identifier (e.g., CVE-2024-21626)"
    },
    {
      name        = "severity"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Vulnerability severity: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN"
    },
    {
      name        = "cvss_score"
      type        = "FLOAT64"
      mode        = "NULLABLE"
      description = "CVSS v3 base score (0.0 - 10.0)"
    },
    {
      name        = "title"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Short description of the vulnerability"
    },
    {
      name        = "description"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Detailed description of the vulnerability"
    },
    {
      name        = "resource_namespace"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Kubernetes namespace of the affected workload"
    },
    {
      name        = "resource_name"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Kubernetes resource name (deployment, pod, etc.)"
    },
    {
      name        = "resource_kind"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Kubernetes resource kind (Deployment, StatefulSet, DaemonSet, etc.)"
    },
    {
      name        = "container_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Name of the container within the pod spec"
    },
    {
      name        = "image_ref"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Full container image reference including registry, repository, and tag/digest"
    },
    {
      name        = "image_digest"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Container image SHA256 digest for immutable identification"
    },
    {
      name        = "package_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Name of the vulnerable OS or application package"
    },
    {
      name        = "installed_version"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Currently installed version of the vulnerable package"
    },
    {
      name        = "fixed_version"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Version that fixes the vulnerability (empty if no fix available)"
    },
    {
      name        = "primary_url"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Primary reference URL for the vulnerability (NVD, vendor advisory, etc.)"
    },
    {
      name        = "target"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Scan target (e.g., OS package, language-specific library)"
    },
    {
      name        = "class"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Vulnerability class (os-pkgs, lang-pkgs, config, secret)"
    },
    {
      name        = "cluster_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Name of the GKE cluster where the scan was performed"
    },
  ])
}

# -----------------------------------------------------------------------------
# Table: processed_vulnerabilities (Enriched & Deduplicated)
# -----------------------------------------------------------------------------
# Stores processed vulnerability records with additional context:
# - Deduplication across multiple scans
# - SLA tracking (first_seen, last_seen, days_open)
# - Remediation status tracking
# - Risk scoring combining CVSS + exploitability + exposure
#
# This table powers dashboards and compliance reports.
# It is populated by scheduled queries or Cloud Functions that process
# the raw trivy_vulnerabilities table.
# -----------------------------------------------------------------------------

resource "google_bigquery_table" "processed_vulnerabilities" {
  dataset_id          = google_bigquery_dataset.security_findings.dataset_id
  table_id            = "processed_vulnerabilities"
  project             = var.project_id
  friendly_name       = "Processed Vulnerability Records"
  description         = "Deduplicated and enriched vulnerability records with SLA tracking and remediation status"
  deletion_protection = false

  # Partition by first_seen date
  time_partitioning {
    type  = "DAY"
    field = "first_seen"
    # No expiration - compliance data retained indefinitely
  }

  # Cluster by status and severity for dashboard queries
  clustering = ["remediation_status", "severity", "resource_namespace"]

  labels = merge(var.labels, {
    table = "processed-vulnerabilities"
  })

  schema = jsonencode([
    {
      name        = "vulnerability_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "CVE identifier (e.g., CVE-2024-21626)"
    },
    {
      name        = "severity"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Vulnerability severity: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN"
    },
    {
      name        = "cvss_score"
      type        = "FLOAT64"
      mode        = "NULLABLE"
      description = "CVSS v3 base score (0.0 - 10.0)"
    },
    {
      name        = "risk_score"
      type        = "FLOAT64"
      mode        = "NULLABLE"
      description = "Composite risk score combining CVSS, exploitability, and exposure (0.0 - 10.0)"
    },
    {
      name        = "title"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Short description of the vulnerability"
    },
    {
      name        = "resource_namespace"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Kubernetes namespace of the affected workload"
    },
    {
      name        = "resource_name"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Kubernetes resource name"
    },
    {
      name        = "image_ref"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Full container image reference"
    },
    {
      name        = "package_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Name of the vulnerable package"
    },
    {
      name        = "installed_version"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Currently installed version"
    },
    {
      name        = "fixed_version"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Version that fixes the vulnerability"
    },
    {
      name        = "fix_available"
      type        = "BOOLEAN"
      mode        = "REQUIRED"
      description = "Whether a fix is available for the vulnerability"
    },
    {
      name        = "first_seen"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Timestamp when this vulnerability was first detected"
    },
    {
      name        = "last_seen"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Timestamp of the most recent scan that found this vulnerability"
    },
    {
      name        = "days_open"
      type        = "INTEGER"
      mode        = "NULLABLE"
      description = "Number of days since first detection (for SLA tracking)"
    },
    {
      name        = "remediation_status"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Status: OPEN, IN_PROGRESS, MITIGATED, RESOLVED, ACCEPTED_RISK, FALSE_POSITIVE"
    },
    {
      name        = "remediation_notes"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Free-text notes about remediation progress or risk acceptance"
    },
    {
      name        = "sla_breach"
      type        = "BOOLEAN"
      mode        = "NULLABLE"
      description = "Whether the vulnerability has exceeded the SLA for its severity"
    },
    {
      name        = "cluster_name"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Name of the GKE cluster"
    },
    {
      name        = "last_updated"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Timestamp of the last update to this record"
    },
  ])
}

# -----------------------------------------------------------------------------
# Scheduled Query: Process Raw Vulnerabilities (Optional)
# -----------------------------------------------------------------------------
# This scheduled query deduplicates and enriches raw Trivy scan data
# into the processed_vulnerabilities table. Runs daily.
#
# NOTE: Uncomment to enable. Requires the BigQuery Data Transfer Service API.
# -----------------------------------------------------------------------------

# resource "google_bigquery_data_transfer_config" "process_vulnerabilities" {
#   display_name           = "Process Raw Vulnerabilities"
#   project                = var.project_id
#   location               = var.location
#   data_source_id         = "scheduled_query"
#   schedule               = "every 24 hours"
#   destination_dataset_id = google_bigquery_dataset.security_findings.dataset_id
#
#   params = {
#     query = <<-EOQ
#       MERGE `${var.project_id}.${google_bigquery_dataset.security_findings.dataset_id}.processed_vulnerabilities` T
#       USING (
#         SELECT
#           vulnerability_id,
#           severity,
#           MAX(cvss_score) as cvss_score,
#           ANY_VALUE(title) as title,
#           resource_namespace,
#           resource_name,
#           ANY_VALUE(image_ref) as image_ref,
#           ANY_VALUE(package_name) as package_name,
#           ANY_VALUE(installed_version) as installed_version,
#           ANY_VALUE(fixed_version) as fixed_version,
#           IF(ANY_VALUE(fixed_version) IS NOT NULL AND ANY_VALUE(fixed_version) != '', TRUE, FALSE) as fix_available,
#           MIN(scan_timestamp) as first_seen,
#           MAX(scan_timestamp) as last_seen,
#           ANY_VALUE(cluster_name) as cluster_name
#         FROM `${var.project_id}.${google_bigquery_dataset.security_findings.dataset_id}.trivy_vulnerabilities`
#         WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
#         GROUP BY vulnerability_id, severity, resource_namespace, resource_name
#       ) S
#       ON T.vulnerability_id = S.vulnerability_id
#         AND T.resource_namespace = S.resource_namespace
#         AND T.resource_name = S.resource_name
#       WHEN MATCHED THEN
#         UPDATE SET
#           last_seen = S.last_seen,
#           days_open = DATE_DIFF(CURRENT_DATE(), DATE(T.first_seen), DAY),
#           sla_breach = CASE
#             WHEN T.severity = 'CRITICAL' AND DATE_DIFF(CURRENT_DATE(), DATE(T.first_seen), DAY) > 7 THEN TRUE
#             WHEN T.severity = 'HIGH' AND DATE_DIFF(CURRENT_DATE(), DATE(T.first_seen), DAY) > 30 THEN TRUE
#             WHEN T.severity = 'MEDIUM' AND DATE_DIFF(CURRENT_DATE(), DATE(T.first_seen), DAY) > 90 THEN TRUE
#             ELSE FALSE
#           END,
#           last_updated = CURRENT_TIMESTAMP()
#       WHEN NOT MATCHED THEN
#         INSERT (vulnerability_id, severity, cvss_score, risk_score, title, resource_namespace,
#                 resource_name, image_ref, package_name, installed_version, fixed_version,
#                 fix_available, first_seen, last_seen, days_open, remediation_status,
#                 sla_breach, cluster_name, last_updated)
#         VALUES (S.vulnerability_id, S.severity, S.cvss_score, S.cvss_score, S.title,
#                 S.resource_namespace, S.resource_name, S.image_ref, S.package_name,
#                 S.installed_version, S.fixed_version, S.fix_available, S.first_seen,
#                 S.last_seen, 0, 'OPEN', FALSE, S.cluster_name, CURRENT_TIMESTAMP())
#     EOQ
#     destination_table_name_template = "processed_vulnerabilities"
#     write_disposition               = "WRITE_APPEND"
#   }
# }
