# =============================================================================
# GCP Security Command Center (SCC) Premium Configuration
# =============================================================================
#
# Security Command Center is GCP's native security posture management and
# threat detection platform. The Premium tier provides:
#
#   - Event Threat Detection (ETD): Real-time threat detection using Google's
#     threat intelligence for crypto mining, malware, data exfiltration, etc.
#   - Container Threat Detection (CTD): Detects suspicious container activity
#     including reverse shells, added binaries, and library loading.
#   - Security Health Analytics (SHA): Misconfiguration detection.
#   - Web Security Scanner: OWASP Top 10 scanning for web applications.
#
# For APT detection, SCC Premium provides:
#   - Crypto mining detection via ETD (complements Falco + Suricata)
#   - Service account anomalous usage detection
#   - Unusual API call detection
#   - Brute force SSH detection
#   - Container escape detection via CTD
#
# =============================================================================

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "org_id" {
  description = "GCP organization ID for org-level SCC enablement"
  type        = string
  default     = ""
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "notification_emails" {
  description = "Email addresses for SCC finding notifications"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Enable Security Command Center API
# -----------------------------------------------------------------------------
resource "google_project_service" "scc_api" {
  project = var.project_id
  service = "securitycenter.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "container_threat_detection_api" {
  project = var.project_id
  service = "containerthreatdetection.googleapis.com"

  disable_on_destroy = false
}

# -----------------------------------------------------------------------------
# SCC Notification Config - Critical Findings
# -----------------------------------------------------------------------------
# Creates a Pub/Sub notification channel for SCC findings that match
# APT-related criteria. This enables real-time alerting when SCC detects
# crypto mining, service account abuse, or container threats.
# -----------------------------------------------------------------------------
resource "google_pubsub_topic" "scc_notifications" {
  project = var.project_id
  name    = "scc-critical-findings-${var.environment}"

  labels = {
    environment = var.environment
    managed_by  = "terraform"
    purpose     = "security-alerting"
  }
}

resource "google_pubsub_subscription" "scc_push" {
  project = var.project_id
  name    = "scc-findings-push-${var.environment}"
  topic   = google_pubsub_topic.scc_notifications.name

  # Push to our alert processing endpoint
  # In production, this would be a Cloud Function or Cloud Run service
  ack_deadline_seconds = 60

  # Retain unacknowledged messages for 24 hours
  message_retention_duration = "86400s"

  # Retry policy for failed deliveries
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  # Dead letter policy for messages that repeatedly fail
  # dead_letter_policy {
  #   dead_letter_topic     = google_pubsub_topic.scc_dead_letter.id
  #   max_delivery_attempts = 10
  # }

  labels = {
    environment = var.environment
    managed_by  = "terraform"
  }
}

# SCC Notification Config - filters for APT-related findings
# This filter captures:
#   - All CRITICAL and HIGH severity findings
#   - Crypto mining detections
#   - Service account anomalies
#   - Container threat detections
resource "google_scc_project_notification_config" "apt_findings" {
  project      = var.project_id
  config_id    = "apt-detection-notifications"
  description  = "Notifications for APT-related SCC findings including crypto mining, SA abuse, and container threats"

  pubsub_topic = google_pubsub_topic.scc_notifications.id

  streaming_config {
    filter = <<-FILTER
      (severity = "CRITICAL" OR severity = "HIGH") OR
      category = "CRYPTO_MINING" OR
      category = "CRYPTO_MINING_POOL" OR
      category = "MALWARE_CRYPTO_MINING" OR
      category = "ADDED_BINARY_EXECUTED" OR
      category = "ADDED_LIBRARY_LOADED" OR
      category = "REVERSE_SHELL" OR
      category = "EXECUTION_ADDED_BINARY_EXECUTED" OR
      category = "EXECUTION_ADDED_LIBRARY_LOADED" OR
      category = "EXECUTION_MODIFIED_BINARY_EXECUTED" OR
      category = "PRIVILEGE_ESCALATION_CONTAINER" OR
      category = "ANOMALOUS_SERVICE_ACCOUNT_USAGE" OR
      category = "SA_KEY_ANOMALOUS_USAGE" OR
      category = "UNUSUAL_API_CALL" OR
      category = "BRUTE_FORCE_SSH" OR
      category = "DATA_EXFILTRATION" OR
      category = "MALWARE_BAD_DOMAIN" OR
      category = "MALWARE_BAD_IP" OR
      category = "PERSISTENCE_NEW_USER_ACCOUNT" OR
      category = "PERSISTENCE_IAM_GRANT"
    FILTER
  }

  depends_on = [
    google_project_service.scc_api,
  ]
}

# -----------------------------------------------------------------------------
# SCC Notification Config - All Container Threat Detection Findings
# -----------------------------------------------------------------------------
# Separate notification channel specifically for Container Threat Detection
# findings, which are highly relevant for our GKE-focused APT scenario.
# -----------------------------------------------------------------------------
resource "google_scc_project_notification_config" "container_threats" {
  project      = var.project_id
  config_id    = "container-threat-notifications"
  description  = "Notifications for all Container Threat Detection findings in GKE"

  pubsub_topic = google_pubsub_topic.scc_notifications.id

  streaming_config {
    filter = <<-FILTER
      source_properties.detection_service = "Container Threat Detection" OR
      category = "ADDED_BINARY_EXECUTED" OR
      category = "ADDED_LIBRARY_LOADED" OR
      category = "REVERSE_SHELL" OR
      category = "MALICIOUS_SCRIPT_EXECUTED" OR
      category = "MALICIOUS_URL_OBSERVED"
    FILTER
  }

  depends_on = [
    google_project_service.scc_api,
  ]
}

# -----------------------------------------------------------------------------
# Cloud Function for SCC Finding Processing (trigger definition)
# -----------------------------------------------------------------------------
# This defines the Pub/Sub trigger for a Cloud Function that processes
# SCC findings and forwards them to our ELK stack and alerting pipeline.
# The actual function code would be deployed separately.
# -----------------------------------------------------------------------------
resource "google_pubsub_topic" "scc_to_elk" {
  project = var.project_id
  name    = "scc-to-elk-forwarder-${var.environment}"

  labels = {
    environment = var.environment
    managed_by  = "terraform"
    purpose     = "elk-integration"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "scc_notification_topic" {
  description = "Pub/Sub topic for SCC finding notifications"
  value       = google_pubsub_topic.scc_notifications.id
}

output "scc_elk_topic" {
  description = "Pub/Sub topic for SCC-to-ELK forwarding"
  value       = google_pubsub_topic.scc_to_elk.id
}
