# =============================================================================
# Cloud Monitoring Alert: Service Account Key Authentication Usage
# =============================================================================
#
# PURPOSE:
# Detects any authentication event that uses a service account key instead of
# Workload Identity Federation or GKE Workload Identity. After the migration
# to WIF, there should be ZERO SA key authentications. Any key-based auth
# indicates either:
#   1. A missed migration (legitimate service still using keys)
#   2. A compromised key being used by an attacker
#   3. A newly created key (policy violation)
#
# This alert fires on ANY SA key authentication, treating it as a potential
# security incident until proven otherwise (assume breach).
#
# LOG FILTER:
# Matches Cloud Audit Log entries where the authentication method is a
# service account key (identified by the presence of serviceAccountKeyName
# in the authentication info).
#
# =============================================================================

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "monitoring_project_id" {
  description = "GCP project ID for monitoring resources"
  type        = string
}

variable "alert_notification_channels" {
  description = <<-EOT
    List of notification channel IDs for security alerts.
    Create channels via: gcloud beta monitoring channels create ...
    Recommended: PagerDuty for P1, Slack for P2, Email for P3.
  EOT
  type        = list(string)
  default     = []
}

variable "alert_email_addresses" {
  description = "Email addresses to notify for security alerts"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Email Notification Channels
# -----------------------------------------------------------------------------

resource "google_monitoring_notification_channel" "email" {
  for_each = toset(var.alert_email_addresses)

  project      = var.monitoring_project_id
  display_name = "Security Alert - ${each.value}"
  type         = "email"

  labels = {
    email_address = each.value
  }

  user_labels = {
    severity = "critical"
    team     = "security"
  }
}

# -----------------------------------------------------------------------------
# Log-Based Metric: SA Key Authentication Events
# -----------------------------------------------------------------------------
# This metric counts every authentication event that uses a SA key.
# The metric is used by the alert policy to trigger notifications.
#
# The filter matches audit log entries where:
# - The log is an activity or data_access audit log
# - The authentication info contains a service account key name
# - The key name matches the pattern for user-managed keys
# -----------------------------------------------------------------------------

resource "google_logging_metric" "sa_key_authentication" {
  project = var.monitoring_project_id
  name    = "sa-key-authentication-events"

  description = <<-EOT
    Counts authentication events using service account keys.
    After WIF migration, this should be zero. Any non-zero value
    indicates a security risk requiring immediate investigation.
  EOT

  filter = <<-EOT
    resource.type="audited_resource" OR resource.type="gce_instance" OR resource.type="k8s_cluster"
    protoPayload.authenticationInfo.serviceAccountKeyName!=""
    protoPayload.authenticationInfo.serviceAccountKeyName!~"system-managed"
    severity>="NOTICE"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "service_account"
      value_type  = "STRING"
      description = "The service account email that was authenticated"
    }

    labels {
      key         = "key_id"
      value_type  = "STRING"
      description = "The service account key ID used for authentication"
    }

    labels {
      key         = "method"
      value_type  = "STRING"
      description = "The API method that was called"
    }

    labels {
      key         = "caller_ip"
      value_type  = "STRING"
      description = "The IP address of the caller"
    }
  }

  label_extractors = {
    "service_account" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "key_id"          = "REGEXP_EXTRACT(protoPayload.authenticationInfo.serviceAccountKeyName, \"keys/(.+)$\")"
    "method"          = "EXTRACT(protoPayload.methodName)"
    "caller_ip"       = "EXTRACT(protoPayload.requestMetadata.callerIp)"
  }
}

# -----------------------------------------------------------------------------
# Alert Policy: SA Key Authentication Detected
# -----------------------------------------------------------------------------
# Severity: P1 (Critical)
# This alert fires immediately on any SA key authentication event.
# The threshold is 0 - even a single event triggers the alert.
#
# Response: Treat as potential compromise. Follow the incident response
# runbook in README.md.
# -----------------------------------------------------------------------------

resource "google_monitoring_alert_policy" "sa_key_authentication_alert" {
  project      = var.monitoring_project_id
  display_name = "[P1-CRITICAL] Service Account Key Authentication Detected"

  documentation {
    content = <<-EOT
      ## Alert: Service Account Key Authentication Detected

      **Severity**: P1 - Critical
      **Category**: Identity & Access Management

      ### What Happened
      A GCP API call was authenticated using a service account key instead of
      Workload Identity Federation. After the WIF migration, ALL authentication
      should use short-lived OIDC tokens. Any key-based authentication is either:

      1. **Compromised key**: An attacker is using a stolen SA key
      2. **Missed migration**: A legitimate service was not migrated to WIF
      3. **Policy violation**: Someone created a new SA key

      ### Immediate Actions
      1. Identify the SA key: Check the alert labels for `service_account` and `key_id`
      2. Check the caller IP: Is it from a known network?
      3. Disable the key immediately:
         ```
         gcloud iam service-accounts keys disable KEY_ID --iam-account=SA_EMAIL
         ```
      4. Check audit logs for the full scope of actions taken with this key
      5. Escalate to the security team if the caller IP is unknown

      ### Investigation Queries
      ```
      # All actions by this SA in the last 24 hours
      gcloud logging read 'protoPayload.authenticationInfo.principalEmail="SA_EMAIL"' \
        --freshness=24h --format=json

      # Check if new resources were created
      gcloud logging read 'protoPayload.authenticationInfo.principalEmail="SA_EMAIL" AND protoPayload.methodName=~"create|insert|set"' \
        --freshness=24h
      ```

      ### Runbook
      See: federation/README.md > Incident Response: Compromised SA Key
    EOT
    mime_type = "text/markdown"
  }

  combiner = "OR"

  conditions {
    display_name = "SA key authentication count > 0"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_authentication.name}\" AND resource.type=\"audited_resource\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"  # Fire immediately, do not wait

      trigger {
        count = 1
      }

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  # Alert on every notification channel configured
  notification_channels = concat(
    var.alert_notification_channels,
    [for channel in google_monitoring_notification_channel.email : channel.name]
  )

  # Alert auto-closes after 1 hour of no further events
  alert_strategy {
    auto_close = "3600s"

    notification_rate_limit {
      period = "300s"  # Max 1 notification per 5 minutes to prevent spam
    }
  }

  severity = "CRITICAL"

  user_labels = {
    team        = "security"
    category    = "iam"
    compliance  = "cis-gcp"
    incident    = "inc-2026-0042"
    auto_action = "investigate"
  }

  enabled = true
}

# -----------------------------------------------------------------------------
# Dashboard: SA Key Usage Overview
# -----------------------------------------------------------------------------
# Provides a visual overview of SA key authentication events for the
# security team to monitor during and after the WIF migration.
# -----------------------------------------------------------------------------

resource "google_monitoring_dashboard" "sa_key_dashboard" {
  project        = var.monitoring_project_id
  dashboard_json = jsonencode({
    displayName = "Service Account Key Usage Monitor"
    labels = {
      team = "security"
    }
    mosaicLayout = {
      tiles = [
        {
          width  = 6
          height = 4
          widget = {
            title = "SA Key Authentication Events (Should Be Zero)"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_authentication.name}\""
                    aggregation = {
                      alignmentPeriod  = "300s"
                      perSeriesAligner = "ALIGN_SUM"
                    }
                  }
                }
                plotType   = "LINE"
                legendTemplate = "$${metric.labels.service_account}"
              }]
              yAxis = {
                label = "Events"
                scale = "LINEAR"
              }
              timeshiftDuration = "0s"
            }
          }
        },
        {
          xPos   = 6
          width  = 6
          height = 4
          widget = {
            title = "SA Key Auth by Service Account"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_authentication.name}\""
                    aggregation = {
                      alignmentPeriod    = "3600s"
                      perSeriesAligner   = "ALIGN_SUM"
                      crossSeriesReducer = "REDUCE_SUM"
                      groupByFields      = ["metric.label.service_account"]
                    }
                  }
                }
                plotType = "STACKED_BAR"
              }]
            }
          }
        },
        {
          yPos   = 4
          width  = 12
          height = 4
          widget = {
            title = "SA Key Auth by Caller IP"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_authentication.name}\""
                    aggregation = {
                      alignmentPeriod    = "3600s"
                      perSeriesAligner   = "ALIGN_SUM"
                      crossSeriesReducer = "REDUCE_SUM"
                      groupByFields      = ["metric.label.caller_ip"]
                    }
                  }
                }
                plotType = "STACKED_BAR"
              }]
            }
          }
        }
      ]
    }
  })
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "sa_key_auth_metric_name" {
  description = "Name of the log-based metric for SA key authentication"
  value       = google_logging_metric.sa_key_authentication.name
}

output "sa_key_auth_alert_name" {
  description = "Name of the SA key authentication alert policy"
  value       = google_monitoring_alert_policy.sa_key_authentication_alert.display_name
}
