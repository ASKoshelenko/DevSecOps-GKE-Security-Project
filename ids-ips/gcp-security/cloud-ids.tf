# =============================================================================
# GCP Cloud IDS (Intrusion Detection System)
# =============================================================================
#
# Cloud IDS is a managed network-based threat detection service powered by
# Palo Alto Networks threat intelligence. It provides:
#
#   - Deep packet inspection for network threats
#   - Palo Alto Networks threat signatures (updated automatically)
#   - Detection of malware, spyware, C2 traffic, and exploits
#   - Vulnerability exploitation detection
#   - Integration with Cloud Logging for centralized alerting
#
# Cloud IDS complements Suricata by providing:
#   - Commercial-grade threat intelligence (vs community rules)
#   - Managed service (no rule updates to maintain)
#   - Palo Alto's threat research team signatures
#
# Architecture:
#   VPC traffic -> Packet Mirroring -> Cloud IDS Endpoint -> Cloud Logging
#
# NOTE: Cloud IDS requires:
#   1. Service Networking API enabled
#   2. Private services access configured on the VPC
#   3. The VPC peering range for Cloud IDS endpoints
#
# =============================================================================

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
variable "cloud_ids_severity" {
  description = <<-EOT
    Minimum alert severity for Cloud IDS.
    Options: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL

    For APT detection, use MEDIUM to capture reconnaissance and
    initial access attempts, not just active exploitation.
  EOT
  type    = string
  default = "MEDIUM"
}

variable "cloud_ids_network" {
  description = "VPC network self-link for Cloud IDS endpoint"
  type        = string
  default     = ""
}

variable "zone" {
  description = "GCP zone for Cloud IDS endpoint"
  type        = string
  default     = "us-central1-a"
}

# -----------------------------------------------------------------------------
# Enable Required APIs
# -----------------------------------------------------------------------------
resource "google_project_service" "ids_api" {
  project = var.project_id
  service = "ids.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "service_networking_api" {
  project = var.project_id
  service = "servicenetworking.googleapis.com"

  disable_on_destroy = false
}

# -----------------------------------------------------------------------------
# Cloud IDS Endpoint
# -----------------------------------------------------------------------------
# The Cloud IDS endpoint is a managed Palo Alto Networks appliance that
# inspects mirrored traffic from the VPC. It runs in a Google-managed
# tenant project and peers with our VPC.
# -----------------------------------------------------------------------------
resource "google_cloud_ids_endpoint" "apt_detection" {
  project  = var.project_id
  name     = "apt-detection-ids-${var.environment}"
  location = var.zone
  network  = var.cloud_ids_network != "" ? var.cloud_ids_network : "projects/${var.project_id}/global/networks/${var.network_name}"

  # Severity threshold - alerts below this level are suppressed
  severity = var.cloud_ids_severity

  # Threat exceptions - suppress known false positives by threat ID
  # Uncomment and add specific threat IDs if needed:
  # threat_exceptions = ["12345", "67890"]

  description = "Cloud IDS endpoint for APT detection - inspects GKE cluster traffic using Palo Alto Networks threat intelligence"

  depends_on = [
    google_project_service.ids_api,
    google_project_service.service_networking_api,
  ]
}

# -----------------------------------------------------------------------------
# Packet Mirroring Policy
# -----------------------------------------------------------------------------
# Mirror all traffic from the GKE subnet to the Cloud IDS endpoint.
# This sends a copy of every packet to Cloud IDS for deep inspection
# without affecting the original traffic flow (passive monitoring).
# -----------------------------------------------------------------------------
resource "google_compute_packet_mirroring" "gke_to_ids" {
  project     = var.project_id
  name        = "gke-to-cloud-ids-${var.environment}"
  region      = var.region
  description = "Mirror GKE subnet traffic to Cloud IDS for APT detection"

  network {
    url = "projects/${var.project_id}/global/networks/${var.network_name}"
  }

  # Collector: the Cloud IDS endpoint's forwarding rule
  collector_ilb {
    url = google_cloud_ids_endpoint.apt_detection.endpoint_forwarding_rule
  }

  # Mirror traffic from the GKE subnet
  mirrored_resources {
    subnetworks {
      url = "projects/${var.project_id}/regions/${var.region}/subnetworks/${var.network_name}-gke-subnet-${var.environment}"
    }
  }

  # Mirror configuration
  filter {
    # Mirror all protocols and ports for complete visibility
    # To reduce cost, you could filter to specific ports:
    # cidr_ranges = ["0.0.0.0/0"]
    ip_protocols = ["tcp", "udp", "icmp"]
    direction    = "BOTH"
  }
}

# -----------------------------------------------------------------------------
# Cloud IDS Log Sink - Export to BigQuery for Threat Hunting
# -----------------------------------------------------------------------------
# Export Cloud IDS threat findings to BigQuery for historical analysis
# and correlation with other security data sources.
# -----------------------------------------------------------------------------
resource "google_bigquery_dataset" "cloud_ids_logs" {
  project    = var.project_id
  dataset_id = "cloud_ids_findings_${var.environment}"
  location   = "US"

  description = "Cloud IDS threat findings for security analysis"

  default_table_expiration_ms = 7776000000  # 90 days

  labels = {
    managed_by  = "terraform"
    environment = var.environment
    purpose     = "threat-detection"
  }
}

resource "google_logging_project_sink" "cloud_ids_to_bigquery" {
  project = var.project_id
  name    = "cloud-ids-to-bigquery-${var.environment}"

  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.cloud_ids_logs.dataset_id}"

  # Filter for Cloud IDS threat logs
  filter = <<-FILTER
    resource.type="ids.googleapis.com/Endpoint"
    logName="projects/${var.project_id}/logs/ids.googleapis.com%2Fthreat"
  FILTER

  bigquery_options {
    use_partitioned_tables = true
  }

  unique_writer_identity = true
}

resource "google_bigquery_dataset_iam_member" "cloud_ids_writer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cloud_ids_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.cloud_ids_to_bigquery.writer_identity
}

# -----------------------------------------------------------------------------
# Cloud Monitoring Alert for Cloud IDS Critical Findings
# -----------------------------------------------------------------------------
# Alert when Cloud IDS detects high or critical severity threats.
# This provides immediate notification of network-level attacks
# detected by Palo Alto's threat intelligence.
# -----------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "cloud_ids_critical" {
  project      = var.project_id
  display_name = "Cloud IDS - Critical Threat Detection"
  combiner     = "OR"

  conditions {
    display_name = "Cloud IDS Critical/High Severity Alert"

    condition_matched_log {
      filter = <<-FILTER
        resource.type="ids.googleapis.com/Endpoint"
        logName="projects/${var.project_id}/logs/ids.googleapis.com%2Fthreat"
        (jsonPayload.alert_severity="CRITICAL" OR jsonPayload.alert_severity="HIGH")
      FILTER
    }
  }

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "604800s"
  }

  documentation {
    content   = <<-DOC
      ## Cloud IDS Critical Threat Detection

      A CRITICAL or HIGH severity network threat has been detected by GCP Cloud IDS
      (powered by Palo Alto Networks threat intelligence).

      ### Immediate Actions:
      1. Check the Cloud IDS findings in Cloud Logging for full threat details
      2. Identify the affected GKE pod/node from the source IP
      3. If confirmed malicious, run the quarantine-pod.sh script
      4. If C2 traffic, run the block-ip.sh script to block the destination
      5. Escalate to the incident response team

      ### Investigation:
      - Cloud Logging: `resource.type="ids.googleapis.com/Endpoint"`
      - BigQuery: `SELECT * FROM cloud_ids_findings_${var.environment}.threat_logs WHERE severity IN ('CRITICAL', 'HIGH')`
    DOC
    mime_type = "text/markdown"
  }

  # Notification channels would be configured separately
  # notification_channels = [google_monitoring_notification_channel.pagerduty.id]
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "cloud_ids_endpoint_id" {
  description = "Cloud IDS endpoint ID"
  value       = google_cloud_ids_endpoint.apt_detection.id
}

output "cloud_ids_endpoint_name" {
  description = "Cloud IDS endpoint name"
  value       = google_cloud_ids_endpoint.apt_detection.name
}

output "cloud_ids_bigquery_dataset" {
  description = "BigQuery dataset for Cloud IDS findings"
  value       = google_bigquery_dataset.cloud_ids_logs.dataset_id
}
