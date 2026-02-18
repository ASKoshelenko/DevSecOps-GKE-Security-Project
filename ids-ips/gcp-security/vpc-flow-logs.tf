# =============================================================================
# VPC Flow Logs Configuration for Network Analysis
# =============================================================================
#
# VPC Flow Logs capture a sample of network flows sent and received by
# GKE node instances. For APT detection, flow logs provide:
#
#   - Visibility into C2 callback traffic patterns (outbound connections
#     to suspicious ports/IPs)
#   - Data exfiltration detection (large outbound data transfers)
#   - Lateral movement tracking (pod-to-pod communication patterns)
#   - Network reconnaissance detection (port scanning behavior)
#
# Flow logs are exported to both Cloud Logging and BigQuery for:
#   - Real-time analysis via Cloud Logging (alerting)
#   - Historical analysis via BigQuery (threat hunting)
#
# Note: Flow logs are per-subnet. Enable on the GKE subnet to capture
# all pod network traffic.
#
# =============================================================================

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
variable "network_name" {
  description = "VPC network name"
  type        = string
  default     = "devsecops-vpc"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "flow_log_sampling" {
  description = <<-EOT
    Sampling rate for VPC flow logs (0.0 to 1.0).
    - 1.0 = capture all flows (maximum visibility, higher cost)
    - 0.5 = capture 50% of flows (balanced)
    - 0.1 = capture 10% of flows (cost-optimized)

    For APT detection, we recommend 0.5 or higher to avoid missing
    low-volume C2 traffic which might be sampled out at lower rates.
  EOT
  type        = number
  default     = 0.5

  validation {
    condition     = var.flow_log_sampling >= 0.0 && var.flow_log_sampling <= 1.0
    error_message = "Flow log sampling rate must be between 0.0 and 1.0."
  }
}

variable "flow_log_interval" {
  description = <<-EOT
    Aggregation interval for VPC flow logs.
    Options: INTERVAL_5_SEC, INTERVAL_30_SEC, INTERVAL_1_MIN,
             INTERVAL_5_MIN, INTERVAL_10_MIN, INTERVAL_15_MIN

    Shorter intervals provide faster detection but generate more data.
    INTERVAL_5_SEC is recommended for security monitoring.
  EOT
  type        = string
  default     = "INTERVAL_5_SEC"
}

variable "labels" {
  description = "Common labels for all resources"
  type        = map(string)
  default = {
    managed_by = "terraform"
    purpose    = "security-monitoring"
  }
}

# -----------------------------------------------------------------------------
# Enable Required APIs
# -----------------------------------------------------------------------------
resource "google_project_service" "logging_api" {
  project = var.project_id
  service = "logging.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "bigquery_api" {
  project = var.project_id
  service = "bigquery.googleapis.com"

  disable_on_destroy = false
}

# -----------------------------------------------------------------------------
# VPC Flow Logs - GKE Subnet
# -----------------------------------------------------------------------------
# Enable flow logs on the GKE subnet with security-optimized settings.
# This captures all network flows to/from GKE nodes and pods.
# -----------------------------------------------------------------------------
resource "google_compute_subnetwork" "gke_subnet_flow_logs" {
  project = var.project_id
  name    = "${var.network_name}-gke-subnet-${var.environment}"
  region  = var.region
  network = "projects/${var.project_id}/global/networks/${var.network_name}"

  # Note: This is a data source reference. In practice, you would either:
  # 1. Add flow log config to your existing subnet resource
  # 2. Use google_compute_subnetwork data source + separate log config

  # VPC Flow Log configuration
  log_config {
    # Aggregation interval - 5 seconds for near-real-time detection
    aggregation_interval = var.flow_log_interval

    # Sampling rate - capture 50% of flows for cost/visibility balance
    flow_sampling = var.flow_log_sampling

    # Include metadata for enriched analysis
    metadata = "INCLUDE_ALL_METADATA"

    # Filter expression - capture all traffic (no filter = all flows)
    # To reduce volume, you could filter to only external traffic:
    # filter_expr = "!intra_vpc"
  }

  lifecycle {
    # Prevent accidental destruction of the subnet
    prevent_destroy = false
    # Only manage log_config, not other subnet attributes
    ignore_changes = [
      ip_cidr_range,
      secondary_ip_range,
      private_ip_google_access,
    ]
  }
}

# -----------------------------------------------------------------------------
# Log Sink - Export Flow Logs to BigQuery
# -----------------------------------------------------------------------------
# Export VPC flow logs to BigQuery for historical threat hunting and analysis.
# BigQuery enables SQL-based queries for patterns like:
#   - "Show all flows to port 4444 in the last 30 days"
#   - "Find pods with unusual outbound data volume"
#   - "Identify connections to IPs in specific countries"
# -----------------------------------------------------------------------------
resource "google_bigquery_dataset" "flow_logs" {
  project    = var.project_id
  dataset_id = "vpc_flow_logs_${var.environment}"
  location   = "US"

  description = "VPC flow logs for security analysis and APT detection"

  # Retain flow logs for 90 days (adjust based on compliance requirements)
  default_table_expiration_ms     = 7776000000  # 90 days in milliseconds
  default_partition_expiration_ms = 7776000000

  labels = var.labels

  access {
    role          = "OWNER"
    special_group = "projectOwners"
  }

  access {
    role          = "READER"
    special_group = "projectReaders"
  }
}

resource "google_logging_project_sink" "flow_logs_to_bigquery" {
  project = var.project_id
  name    = "vpc-flow-logs-to-bigquery-${var.environment}"

  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.flow_logs.dataset_id}"

  # Filter for VPC flow logs only
  filter = <<-FILTER
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
  FILTER

  # Use partitioned tables for efficient querying
  bigquery_options {
    use_partitioned_tables = true
  }

  # Create the destination dataset before the sink
  unique_writer_identity = true
}

# Grant the log sink service account write access to BigQuery
resource "google_bigquery_dataset_iam_member" "flow_logs_writer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.flow_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.flow_logs_to_bigquery.writer_identity
}

# -----------------------------------------------------------------------------
# Log Sink - Export Security-Relevant Flow Logs to Pub/Sub
# -----------------------------------------------------------------------------
# Export flow logs that match suspicious patterns to Pub/Sub for
# real-time processing. This filters for flows to C2 ports and
# high-risk destinations.
# -----------------------------------------------------------------------------
resource "google_pubsub_topic" "suspicious_flows" {
  project = var.project_id
  name    = "suspicious-flow-logs-${var.environment}"

  labels = var.labels
}

resource "google_logging_project_sink" "suspicious_flows_sink" {
  project = var.project_id
  name    = "suspicious-flows-to-pubsub-${var.environment}"

  destination = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.suspicious_flows.name}"

  # Filter for suspicious flow patterns:
  # - Connections to known C2 ports
  # - Large outbound data transfers (potential exfiltration)
  filter = <<-FILTER
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    (
      jsonPayload.connection.dest_port=4444 OR
      jsonPayload.connection.dest_port=5555 OR
      jsonPayload.connection.dest_port=8443 OR
      jsonPayload.connection.dest_port=9001 OR
      jsonPayload.connection.dest_port=6666 OR
      jsonPayload.connection.dest_port=6667 OR
      jsonPayload.connection.dest_port=1337 OR
      jsonPayload.connection.dest_port=31337 OR
      jsonPayload.connection.dest_port=12345 OR
      jsonPayload.connection.dest_port=65535 OR
      jsonPayload.bytes_sent > 104857600
    )
  FILTER

  unique_writer_identity = true
}

# Grant the suspicious flows sink write access to Pub/Sub
resource "google_pubsub_topic_iam_member" "suspicious_flows_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.suspicious_flows.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.suspicious_flows_sink.writer_identity
}

# -----------------------------------------------------------------------------
# Log-Based Metric - C2 Port Connection Attempts
# -----------------------------------------------------------------------------
# Create a Cloud Monitoring metric from flow logs to track the number
# of outbound connection attempts to known C2 ports over time.
# This metric can be used for alerting and dashboards.
# -----------------------------------------------------------------------------
resource "google_logging_metric" "c2_port_connections" {
  project = var.project_id
  name    = "c2-port-connection-attempts"

  description = "Count of outbound connections to known C2 ports detected in VPC flow logs"

  filter = <<-FILTER
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    (
      jsonPayload.connection.dest_port=4444 OR
      jsonPayload.connection.dest_port=5555 OR
      jsonPayload.connection.dest_port=8443 OR
      jsonPayload.connection.dest_port=9001 OR
      jsonPayload.connection.dest_port=1337 OR
      jsonPayload.connection.dest_port=31337
    )
  FILTER

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "dest_port"
      value_type  = "INT64"
      description = "Destination port of the connection attempt"
    }
    labels {
      key         = "src_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }

  label_extractors = {
    "dest_port" = "EXTRACT(jsonPayload.connection.dest_port)"
    "src_ip"    = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

# -----------------------------------------------------------------------------
# Log-Based Metric - Large Outbound Transfers
# -----------------------------------------------------------------------------
resource "google_logging_metric" "large_outbound_transfers" {
  project = var.project_id
  name    = "large-outbound-data-transfers"

  description = "Count of large outbound data transfers (>100MB) that may indicate data exfiltration"

  filter = <<-FILTER
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.bytes_sent > 104857600
    jsonPayload.connection.dest_ip!~"^10\." AND
    jsonPayload.connection.dest_ip!~"^172\.(1[6-9]|2[0-9]|3[01])\." AND
    jsonPayload.connection.dest_ip!~"^192\.168\."
  FILTER

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "flow_logs_dataset" {
  description = "BigQuery dataset for VPC flow logs"
  value       = google_bigquery_dataset.flow_logs.dataset_id
}

output "suspicious_flows_topic" {
  description = "Pub/Sub topic for suspicious flow log events"
  value       = google_pubsub_topic.suspicious_flows.id
}

output "c2_metric_name" {
  description = "Cloud Monitoring metric for C2 port connections"
  value       = google_logging_metric.c2_port_connections.name
}
