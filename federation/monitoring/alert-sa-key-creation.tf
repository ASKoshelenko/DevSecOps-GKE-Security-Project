# =============================================================================
# Cloud Monitoring Alert: Service Account Key Creation Attempts
# =============================================================================
#
# PURPOSE:
# Detects attempts to create or upload service account keys. After deploying
# org-policies.tf, these attempts will be blocked by the organization policy
# constraint. However, the attempts themselves are significant security events:
#
# 1. A developer may not know about the WIF migration and needs guidance
# 2. An attacker may be probing for ways to establish persistence
# 3. An automation script may be trying to create keys (needs migration)
# 4. A Terraform configuration may include google_service_account_key
#
# This alert fires on ATTEMPTS, not successes. The org policy blocks the
# actual creation, but we want to know about the attempts.
#
# =============================================================================

# -----------------------------------------------------------------------------
# Log-Based Metric: SA Key Creation Attempts
# -----------------------------------------------------------------------------
# Matches audit log entries for the IAM API methods that create or upload keys.
# These methods are:
#   - google.iam.admin.v1.CreateServiceAccountKey (create new key)
#   - google.iam.admin.v1.UploadServiceAccountKey (upload public key)
#   - SetIamPolicy (when granting SA key-related permissions)
#
# The metric captures both successful and failed attempts. With org policies
# in place, most should be failures (PERMISSION_DENIED).
# -----------------------------------------------------------------------------

resource "google_logging_metric" "sa_key_creation_attempts" {
  project = var.monitoring_project_id
  name    = "sa-key-creation-attempts"

  description = <<-EOT
    Counts attempts to create or upload service account keys.
    With org policies enforced, these should all fail. The attempts
    themselves indicate either misconfiguration or malicious activity.
  EOT

  filter = <<-EOT
    resource.type="service_account"
    protoPayload.methodName=("google.iam.admin.v1.CreateServiceAccountKey" OR "google.iam.admin.v1.UploadServiceAccountKey")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "caller_email"
      value_type  = "STRING"
      description = "Identity that attempted to create/upload the key"
    }

    labels {
      key         = "target_service_account"
      value_type  = "STRING"
      description = "Service account targeted for key creation"
    }

    labels {
      key         = "method"
      value_type  = "STRING"
      description = "The API method (create or upload)"
    }

    labels {
      key         = "status_code"
      value_type  = "STRING"
      description = "HTTP status code (200=success, 403=blocked by policy)"
    }

    labels {
      key         = "caller_ip"
      value_type  = "STRING"
      description = "IP address of the caller"
    }
  }

  label_extractors = {
    "caller_email"           = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "target_service_account" = "EXTRACT(protoPayload.resourceName)"
    "method"                 = "EXTRACT(protoPayload.methodName)"
    "status_code"            = "EXTRACT(protoPayload.status.code)"
    "caller_ip"              = "EXTRACT(protoPayload.requestMetadata.callerIp)"
  }
}

# -----------------------------------------------------------------------------
# Alert Policy: SA Key Creation Attempt Detected
# -----------------------------------------------------------------------------
# Severity: P2 (High)
# Fires on any attempt to create or upload a SA key.
# The org policy should block the attempt, but the attempt itself needs
# investigation to understand why it happened.
# -----------------------------------------------------------------------------

resource "google_monitoring_alert_policy" "sa_key_creation_alert" {
  project      = var.monitoring_project_id
  display_name = "[P2-HIGH] Service Account Key Creation Attempt"

  documentation {
    content = <<-EOT
      ## Alert: Service Account Key Creation Attempt

      **Severity**: P2 - High
      **Category**: Identity & Access Management

      ### What Happened
      Someone or something attempted to create or upload a service account key.
      If the organization policy is correctly enforced, this attempt was BLOCKED.
      However, the attempt itself requires investigation.

      ### Why This Matters
      - If the attempt succeeded (status 200): The org policy is not enforced.
        This is a **P1 escalation** - apply org-policies.tf immediately.
      - If the attempt failed (status 403): The policy is working, but someone
        is either unaware of the WIF migration or probing for weaknesses.

      ### Immediate Actions
      1. Check the alert labels:
         - `caller_email`: Who attempted the creation?
         - `target_service_account`: Which SA was targeted?
         - `status_code`: Did it succeed or fail?
         - `caller_ip`: Where did the request come from?

      2. If status_code is 200 (SUCCESS):
         - **ESCALATE TO P1 IMMEDIATELY**
         - Disable the created key:
           ```
           gcloud iam service-accounts keys list --iam-account=TARGET_SA
           gcloud iam service-accounts keys disable KEY_ID --iam-account=TARGET_SA
           ```
         - Verify org policy enforcement:
           ```
           gcloud org-policies describe constraints/iam.disableServiceAccountKeyCreation \
             --project=PROJECT_ID
           ```

      3. If status_code is 7 (PERMISSION_DENIED):
         - Contact the caller to explain WIF migration
         - Direct them to the federation/README.md documentation
         - Check if they have a legitimate use case that needs WIF setup

      ### Root Cause Investigation
      ```
      # See all key creation attempts in the last 7 days
      gcloud logging read \
        'protoPayload.methodName=~"ServiceAccountKey"' \
        --project=PROJECT_ID \
        --freshness=7d \
        --format='table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.methodName, protoPayload.status.code)'
      ```
    EOT
    mime_type = "text/markdown"
  }

  combiner = "OR"

  conditions {
    display_name = "SA key creation attempt count > 0"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_creation_attempts.name}\" AND resource.type=\"service_account\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

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

  notification_channels = concat(
    var.alert_notification_channels,
    [for channel in google_monitoring_notification_channel.email : channel.name]
  )

  alert_strategy {
    auto_close = "3600s"

    notification_rate_limit {
      period = "300s"
    }
  }

  severity = "ERROR"

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
# Log-Based Metric: SA Key Disable/Delete Events
# -----------------------------------------------------------------------------
# Tracks when SA keys are disabled or deleted (part of the migration process).
# This is informational, not an alert - it helps verify migration progress.
# -----------------------------------------------------------------------------

resource "google_logging_metric" "sa_key_lifecycle" {
  project = var.monitoring_project_id
  name    = "sa-key-lifecycle-events"

  description = <<-EOT
    Tracks service account key lifecycle events (disable, enable, delete).
    Used to monitor migration progress and detect unauthorized key management.
  EOT

  filter = <<-EOT
    resource.type="service_account"
    protoPayload.methodName=("google.iam.admin.v1.DeleteServiceAccountKey" OR "google.iam.admin.v1.DisableServiceAccountKey" OR "google.iam.admin.v1.EnableServiceAccountKey")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "caller_email"
      value_type  = "STRING"
      description = "Identity that performed the action"
    }

    labels {
      key         = "action"
      value_type  = "STRING"
      description = "The lifecycle action (delete, disable, enable)"
    }
  }

  label_extractors = {
    "caller_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "action"       = "EXTRACT(protoPayload.methodName)"
  }
}

# -----------------------------------------------------------------------------
# Alert: SA Key Re-enabled After Disable
# -----------------------------------------------------------------------------
# Severity: P1 (Critical)
# If a key is re-enabled after being disabled during migration, it could
# indicate an attacker re-activating a disabled key for persistence.
# -----------------------------------------------------------------------------

resource "google_monitoring_alert_policy" "sa_key_reenable_alert" {
  project      = var.monitoring_project_id
  display_name = "[P1-CRITICAL] Service Account Key Re-enabled"

  documentation {
    content = <<-EOT
      ## Alert: Service Account Key Re-enabled

      **Severity**: P1 - Critical

      A previously disabled service account key has been re-enabled. During the
      WIF migration, keys are disabled as a safety measure before deletion.
      Re-enabling a key could indicate:

      1. An attacker re-activating a disabled key for persistence
      2. A rollback due to service breakage (legitimate but needs WIF migration)

      ### Immediate Actions
      1. Identify who re-enabled the key (check caller_email label)
      2. If unauthorized: disable the key immediately and investigate
      3. If legitimate: work with the team to migrate to WIF urgently
    EOT
    mime_type = "text/markdown"
  }

  combiner = "OR"

  conditions {
    display_name = "SA key enable event detected"

    condition_threshold {
      filter = <<-EOT
        metric.type="logging.googleapis.com/user/${google_logging_metric.sa_key_lifecycle.name}"
        AND resource.type="service_account"
        AND metric.labels.action="google.iam.admin.v1.EnableServiceAccountKey"
      EOT

      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

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

  notification_channels = concat(
    var.alert_notification_channels,
    [for channel in google_monitoring_notification_channel.email : channel.name]
  )

  alert_strategy {
    auto_close = "3600s"

    notification_rate_limit {
      period = "60s"  # More aggressive notification for P1
    }
  }

  severity = "CRITICAL"

  user_labels = {
    team        = "security"
    category    = "iam"
    auto_action = "disable-key"
  }

  enabled = true
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "sa_key_creation_metric_name" {
  description = "Name of the log-based metric for SA key creation attempts"
  value       = google_logging_metric.sa_key_creation_attempts.name
}

output "sa_key_creation_alert_name" {
  description = "Name of the SA key creation alert policy"
  value       = google_monitoring_alert_policy.sa_key_creation_alert.display_name
}

output "sa_key_lifecycle_metric_name" {
  description = "Name of the log-based metric for SA key lifecycle events"
  value       = google_logging_metric.sa_key_lifecycle.name
}

output "sa_key_reenable_alert_name" {
  description = "Name of the SA key re-enable alert policy"
  value       = google_monitoring_alert_policy.sa_key_reenable_alert.display_name
}
