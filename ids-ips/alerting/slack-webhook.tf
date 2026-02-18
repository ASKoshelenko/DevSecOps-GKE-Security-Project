# =============================================================================
# Slack Webhook Integration for Security Notifications
# =============================================================================
#
# Configures Slack as a notification channel for security alerts.
# Slack provides real-time visibility into security events for the team.
#
# Channel mapping:
#   #security-critical  -> EMERGENCY/CRITICAL severity events
#   #security-alerts    -> HIGH/MEDIUM severity events
#   #security-info      -> LOW severity and informational events
#
# =============================================================================

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
variable "slack_webhook_url_critical" {
  description = <<-EOT
    Slack incoming webhook URL for the #security-critical channel.
    Create at: https://api.slack.com/messaging/webhooks
    This is a sensitive value - pass via environment variable.
  EOT
  type      = string
  sensitive = true
  default   = ""
}

variable "slack_webhook_url_alerts" {
  description = "Slack incoming webhook URL for the #security-alerts channel"
  type        = string
  sensitive   = true
  default     = ""
}

variable "slack_auth_token" {
  description = <<-EOT
    Slack API auth token for the notification channel.
    Required by GCP Monitoring Slack notification channel type.
  EOT
  type      = string
  sensitive = true
  default   = ""
}

variable "slack_channel_critical" {
  description = "Slack channel name for critical alerts"
  type        = string
  default     = "#security-critical"
}

variable "slack_channel_alerts" {
  description = "Slack channel name for general security alerts"
  type        = string
  default     = "#security-alerts"
}

# -----------------------------------------------------------------------------
# Notification Channel - Slack Critical
# -----------------------------------------------------------------------------
resource "google_monitoring_notification_channel" "slack_critical" {
  project      = var.project_id
  display_name = "Slack - Security Critical (${var.slack_channel_critical})"
  type         = "slack"
  description  = "Slack notifications for critical/emergency security events"

  labels = {
    "channel_name" = var.slack_channel_critical
  }

  sensitive_labels {
    auth_token = var.slack_auth_token
  }

  user_labels = {
    severity    = "critical"
    team        = "security"
    managed_by  = "terraform"
    environment = var.environment
  }

  enabled = var.slack_auth_token != "" ? true : false
}

# -----------------------------------------------------------------------------
# Notification Channel - Slack Alerts
# -----------------------------------------------------------------------------
resource "google_monitoring_notification_channel" "slack_alerts" {
  project      = var.project_id
  display_name = "Slack - Security Alerts (${var.slack_channel_alerts})"
  type         = "slack"
  description  = "Slack notifications for high/medium severity security events"

  labels = {
    "channel_name" = var.slack_channel_alerts
  }

  sensitive_labels {
    auth_token = var.slack_auth_token
  }

  user_labels = {
    severity    = "high"
    team        = "security"
    managed_by  = "terraform"
    environment = var.environment
  }

  enabled = var.slack_auth_token != "" ? true : false
}

# -----------------------------------------------------------------------------
# Notification Channel - Email (fallback)
# -----------------------------------------------------------------------------
# Email notification as a fallback in case Slack/PagerDuty are unavailable.
# Uses a team distribution list rather than individual emails.
# -----------------------------------------------------------------------------
resource "google_monitoring_notification_channel" "email_security" {
  project      = var.project_id
  display_name = "Email - Security Team"
  type         = "email"
  description  = "Email fallback for security notifications"

  labels = {
    "email_address" = length(var.notification_emails) > 0 ? var.notification_emails[0] : "security-team@example.com"
  }

  user_labels = {
    team        = "security"
    managed_by  = "terraform"
    environment = var.environment
  }
}

# -----------------------------------------------------------------------------
# Alert Policy - C2 Connection Alert (Slack + PagerDuty)
# -----------------------------------------------------------------------------
# Routes C2 connection detection alerts to both Slack and PagerDuty.
# C2 connections are a critical indicator requiring immediate response.
# -----------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "c2_connection_alert" {
  project      = var.project_id
  display_name = "IDS/IPS - C2 Connection Detected"
  combiner     = "OR"

  conditions {
    display_name = "Falco C2 Port Alert"

    condition_matched_log {
      filter = <<-FILTER
        jsonPayload.rule="Outbound Connection to C2 Port"
        OR jsonPayload.output=~"C2 CALLBACK"
      FILTER
    }
  }

  conditions {
    display_name = "Suricata C2 Alert"

    condition_matched_log {
      filter = <<-FILTER
        jsonPayload.alert.signature=~"APT C2"
      FILTER
    }
  }

  notification_channels = [
    google_monitoring_notification_channel.slack_critical.id,
    google_monitoring_notification_channel.pagerduty_critical.id,
    google_monitoring_notification_channel.email_security.id,
  ]

  alert_strategy {
    notification_rate_limit {
      period = "60s"
    }
    auto_close = "604800s"
  }

  documentation {
    content   = <<-DOC
      ## C2 Connection Detected

      An outbound connection to a known Command & Control port has been
      detected from a GKE pod. This is a critical indicator of active
      compromise.

      ### Detected Ports and Tools:
      | Port  | Framework          | Priority |
      |-------|--------------------|----------|
      | 4444  | Metasploit         | P1       |
      | 5555  | Custom RAT         | P1       |
      | 8443  | Cobalt Strike      | P1       |
      | 9001  | TOR / Custom C2    | P1       |
      | 6666  | IRC Botnet         | P2       |
      | 1337  | Generic Backdoor   | P2       |

      ### Immediate Actions:
      1. Block the destination IP: `./auto-response/block-ip.sh <dest-ip>`
      2. Quarantine the source pod: `./auto-response/quarantine-pod.sh <ns> <pod>`
      3. Check for reverse shell indicators in Falco alerts
      4. Analyze the full connection in Suricata eve.json
      5. Run `kubectl logs <pod>` to capture any attacker output
    DOC
    mime_type = "text/markdown"
  }
}

# -----------------------------------------------------------------------------
# Alert Policy - Reverse Shell Detection
# -----------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "reverse_shell_alert" {
  project      = var.project_id
  display_name = "IDS/IPS - Reverse Shell Detected"
  combiner     = "OR"

  conditions {
    display_name = "Falco Reverse Shell Detection"

    condition_matched_log {
      filter = <<-FILTER
        jsonPayload.rule="Reverse Shell Detected in Container"
        OR jsonPayload.output=~"REVERSE SHELL"
      FILTER
    }
  }

  notification_channels = [
    google_monitoring_notification_channel.slack_critical.id,
    google_monitoring_notification_channel.pagerduty_critical.id,
    google_monitoring_notification_channel.email_security.id,
  ]

  alert_strategy {
    notification_rate_limit {
      period = "60s"
    }
    auto_close = "604800s"
  }

  documentation {
    content   = <<-DOC
      ## EMERGENCY: Reverse Shell Detected

      A reverse shell has been detected in a GKE container. An attacker
      has active, interactive access to the compromised pod.

      ### THIS IS AN ACTIVE INTRUSION - ACT IMMEDIATELY

      1. Quarantine the pod NOW: `./auto-response/quarantine-pod.sh <ns> <pod>`
      2. Block the C2 destination: `./auto-response/block-ip.sh <dest-ip>`
      3. DO NOT delete the pod yet - preserve evidence
      4. Capture: `kubectl logs <pod>` and `kubectl describe pod <pod>`
      5. Check for container escape attempts in Falco alerts
      6. Escalate to incident response team immediately
    DOC
    mime_type = "text/markdown"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "slack_critical_channel_id" {
  description = "Slack notification channel ID for critical alerts"
  value       = google_monitoring_notification_channel.slack_critical.id
}

output "slack_alerts_channel_id" {
  description = "Slack notification channel ID for general alerts"
  value       = google_monitoring_notification_channel.slack_alerts.id
}

output "email_channel_id" {
  description = "Email notification channel ID"
  value       = google_monitoring_notification_channel.email_security.id
}
