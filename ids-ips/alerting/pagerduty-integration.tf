# =============================================================================
# PagerDuty Integration for Security Alerting
# =============================================================================
#
# Routes security alerts from GCP Cloud Monitoring to PagerDuty for
# on-call incident response. Alert routing is severity-based:
#
#   EMERGENCY/CRITICAL -> P1 (immediate page, phone call)
#   HIGH               -> P2 (urgent, Slack + push notification)
#   MEDIUM             -> P3 (standard, email + Slack)
#   LOW                -> P4 (informational, email only)
#
# Integration architecture:
#   Falco/Suricata -> Cloud Logging -> Alert Policies -> PagerDuty
#   SCC Findings -> Pub/Sub -> Cloud Function -> PagerDuty Events API
#
# =============================================================================

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
variable "pagerduty_service_key" {
  description = <<-EOT
    PagerDuty service integration key (Events API v2).
    Create a new service in PagerDuty and use the Integration Key.
    This is a sensitive value - pass via TF_VAR_pagerduty_service_key
    environment variable or a secrets manager.
  EOT
  type      = string
  sensitive = true
  default   = ""
}

variable "pagerduty_service_key_high" {
  description = "PagerDuty integration key for high-severity security alerts"
  type        = string
  sensitive   = true
  default     = ""
}

# -----------------------------------------------------------------------------
# Notification Channel - PagerDuty (Critical/Emergency)
# -----------------------------------------------------------------------------
# This channel routes CRITICAL and EMERGENCY alerts to PagerDuty,
# triggering immediate on-call pages.
# -----------------------------------------------------------------------------
resource "google_monitoring_notification_channel" "pagerduty_critical" {
  project      = var.project_id
  display_name = "PagerDuty - Security Critical (P1)"
  type         = "pagerduty"
  description  = "Routes critical security alerts to PagerDuty for immediate incident response"

  labels = {
    "service_key" = var.pagerduty_service_key
  }

  sensitive_labels {
    service_key = var.pagerduty_service_key
  }

  user_labels = {
    severity    = "critical"
    team        = "security"
    managed_by  = "terraform"
    environment = var.environment
  }

  enabled = var.pagerduty_service_key != "" ? true : false
}

# -----------------------------------------------------------------------------
# Notification Channel - PagerDuty (High Severity)
# -----------------------------------------------------------------------------
resource "google_monitoring_notification_channel" "pagerduty_high" {
  project      = var.project_id
  display_name = "PagerDuty - Security High (P2)"
  type         = "pagerduty"
  description  = "Routes high-severity security alerts to PagerDuty"

  labels = {
    "service_key" = var.pagerduty_service_key_high
  }

  sensitive_labels {
    service_key = var.pagerduty_service_key_high
  }

  user_labels = {
    severity    = "high"
    team        = "security"
    managed_by  = "terraform"
    environment = var.environment
  }

  enabled = var.pagerduty_service_key_high != "" ? true : false
}

# -----------------------------------------------------------------------------
# Alert Policy - APT Detection Composite Alert
# -----------------------------------------------------------------------------
# This composite alert fires when multiple APT indicators are detected
# within a short time window, indicating a high-confidence APT intrusion.
# Routes to PagerDuty P1 for immediate response.
# -----------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "apt_composite" {
  project      = var.project_id
  display_name = "APT ALERT - Multiple APT Indicators Detected (P1)"
  combiner     = "AND"

  conditions {
    display_name = "Magic file detected in /tmp"

    condition_matched_log {
      filter = <<-FILTER
        jsonPayload.rule="APT Magic File Created in /tmp"
        OR textPayload=~"magic.*file.*created"
        OR jsonPayload.output=~"magic"
      FILTER

      label_extractors = {
        "pod_name"  = "EXTRACT(jsonPayload.output_fields.k8s_pod)"
        "namespace" = "EXTRACT(jsonPayload.output_fields.k8s_ns)"
      }
    }
  }

  notification_channels = [
    google_monitoring_notification_channel.pagerduty_critical.id,
  ]

  alert_strategy {
    notification_rate_limit {
      period = "60s"
    }
    auto_close = "86400s"
  }

  documentation {
    content   = <<-DOC
      ## CRITICAL: APT Activity Confirmed

      Multiple indicators of Russian APT activity have been detected.
      This is a HIGH-CONFIDENCE detection requiring IMMEDIATE response.

      ### Indicators Detected:
      - "Magic" file created in /tmp (APT marker file)
      - Additional correlated APT indicators from Falco/Suricata

      ### IMMEDIATE ACTIONS (within 15 minutes):
      1. **DO NOT** terminate the affected pods immediately (preserve evidence)
      2. Quarantine affected pod: `./auto-response/quarantine-pod.sh <ns> <pod>`
      3. Block C2 IPs: `./auto-response/block-ip.sh <c2-ip>`
      4. Disable compromised SA: `./auto-response/revoke-sa.sh <sa-email>`
      5. Capture memory dump and filesystem image for forensics
      6. Notify CISO and activate incident response plan

      ### Follow the Incident Response Playbook:
      See `incident-response-playbook.md` for complete procedures.
    DOC
    mime_type = "text/markdown"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "pagerduty_critical_channel_id" {
  description = "PagerDuty notification channel ID for critical alerts"
  value       = google_monitoring_notification_channel.pagerduty_critical.id
}

output "pagerduty_high_channel_id" {
  description = "PagerDuty notification channel ID for high-severity alerts"
  value       = google_monitoring_notification_channel.pagerduty_high.id
}
