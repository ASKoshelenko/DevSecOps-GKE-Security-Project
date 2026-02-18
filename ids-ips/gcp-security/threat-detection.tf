# =============================================================================
# Event Threat Detection (ETD) - GCP Native Threat Detection
# =============================================================================
#
# Event Threat Detection is part of SCC Premium and provides real-time
# detection of threats by analyzing Cloud Logging data, including:
#
#   - Crypto mining detection (based on DNS queries, network patterns)
#   - Service account key anomalous usage
#   - Unusual API calls
#   - Brute force SSH
#   - Data exfiltration to external storage
#   - Privilege escalation via IAM
#   - Malware downloads
#
# This file configures:
#   1. Custom Cloud Monitoring alert policies based on ETD findings
#   2. Log-based metrics for tracking APT-related threat detections
#   3. Notification channels for alerting
#
# ETD itself is enabled through SCC Premium (see security-command-center.tf).
# This file creates the alerting and monitoring layer on top of ETD.
#
# =============================================================================

# -----------------------------------------------------------------------------
# Alert Policy - Crypto Mining Detection
# -----------------------------------------------------------------------------
# Triggers when ETD or Container Threat Detection detects crypto mining
# activity. This includes:
#   - DNS queries to known mining pool domains
#   - Stratum protocol detection
#   - High CPU usage patterns consistent with mining
#   - Known mining binary execution
# -----------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "crypto_mining" {
  project      = var.project_id
  display_name = "ETD - Crypto Mining Detected"
  combiner     = "OR"

  conditions {
    display_name = "Crypto Mining Finding in SCC"

    condition_matched_log {
      filter = <<-FILTER
        resource.type="threat_detector"
        (
          jsonPayload.findingCategory="CRYPTO_MINING" OR
          jsonPayload.findingCategory="CRYPTO_MINING_POOL" OR
          jsonPayload.findingCategory="MALWARE_CRYPTO_MINING"
        )
      FILTER
    }
  }

  conditions {
    display_name = "Mining Pool DNS Query"

    condition_matched_log {
      filter = <<-FILTER
        resource.type="dns_query"
        (
          jsonPayload.queryName=~".*pool\\..*" OR
          jsonPayload.queryName=~".*mining\\..*" OR
          jsonPayload.queryName=~".*xmr.*" OR
          jsonPayload.queryName=~".*nicehash.*" OR
          jsonPayload.queryName=~".*nanopool.*" OR
          jsonPayload.queryName=~".*supportxmr.*" OR
          jsonPayload.queryName=~".*hashvault.*" OR
          jsonPayload.queryName=~".*minergate.*"
        )
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
      ## Crypto Mining Detected

      Google's Event Threat Detection has identified cryptocurrency mining
      activity in the GKE cluster. This is a high-confidence detection
      using Google's threat intelligence.

      ### Common APT Pattern:
      Russian APT groups deploy crypto miners (especially XMRig for Monero)
      after gaining initial access. Mining is a secondary monetization
      strategy alongside data theft.

      ### Immediate Actions:
      1. Identify the affected pod/node from the finding details
      2. Check Falco alerts for the "Crypto Mining Process Detected" rule
      3. Check Suricata alerts for Stratum protocol connections
      4. Quarantine the affected pod: `./auto-response/quarantine-pod.sh <namespace> <pod>`
      5. Investigate the container image for compromise indicators
      6. Check for other APT indicators (magic file, C2 connections)

      ### Investigation Queries:
      - Falco: `falco.rule:"Crypto Mining Process Detected"`
      - Suricata: `suricata.alert.signature:*MINING*`
      - K8s: `kubectl top pods --all-namespaces --sort-by=cpu`
    DOC
    mime_type = "text/markdown"
  }
}

# -----------------------------------------------------------------------------
# Alert Policy - Service Account Key Anomalous Usage
# -----------------------------------------------------------------------------
# Detects when a service account key is used from an unusual location or
# in an unusual pattern, which may indicate key theft by APT actors.
# -----------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "sa_key_abuse" {
  project      = var.project_id
  display_name = "ETD - Service Account Key Anomalous Usage"
  combiner     = "OR"

  conditions {
    display_name = "SA Key Anomalous Usage"

    condition_matched_log {
      filter = <<-FILTER
        resource.type="threat_detector"
        (
          jsonPayload.findingCategory="SA_KEY_ANOMALOUS_USAGE" OR
          jsonPayload.findingCategory="ANOMALOUS_SERVICE_ACCOUNT_USAGE" OR
          jsonPayload.findingCategory="SERVICE_ACCOUNT_KEY_CREATED"
        )
      FILTER
    }
  }

  conditions {
    display_name = "SA Key Used from Unusual IP"

    condition_matched_log {
      filter = <<-FILTER
        protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
        protoPayload.authenticationInfo.serviceAccountKeyName!=""
        protoPayload.requestMetadata.callerIp!~"^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"
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
      ## Service Account Key Anomalous Usage

      A GCP service account key is being used in a suspicious manner.
      This may indicate that an APT group has stolen a service account
      key and is using it from external infrastructure.

      ### Why This Matters:
      Russian APT groups target service account keys as part of their
      persistence strategy. Stolen keys provide long-lived access to
      GCP resources without needing to maintain a foothold in the cluster.

      ### Immediate Actions:
      1. Identify the affected service account from the finding
      2. Check if the key was used from an expected location
      3. If compromised, immediately disable the key:
         `./auto-response/revoke-sa.sh <service-account-email>`
      4. Rotate all keys for the affected service account
      5. Audit all actions performed with the key since compromise
      6. Review IAM policies for over-privileged service accounts

      ### Prevention:
      - Use Workload Identity instead of SA keys
      - Enable SA key creation constraints via Org Policy
      - Monitor SA key creation events in Cloud Audit Logs
    DOC
    mime_type = "text/markdown"
  }
}

# -----------------------------------------------------------------------------
# Alert Policy - Unusual API Calls
# -----------------------------------------------------------------------------
# Detects unusual GCP API calls that may indicate post-compromise
# reconnaissance or privilege escalation.
# -----------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "unusual_api_calls" {
  project      = var.project_id
  display_name = "ETD - Unusual API Calls Detected"
  combiner     = "OR"

  conditions {
    display_name = "Unusual API Call Pattern"

    condition_matched_log {
      filter = <<-FILTER
        resource.type="threat_detector"
        (
          jsonPayload.findingCategory="UNUSUAL_API_CALL" OR
          jsonPayload.findingCategory="API_KEY_ANOMALOUS_USAGE"
        )
      FILTER
    }
  }

  alert_strategy {
    notification_rate_limit {
      period = "600s"
    }
    auto_close = "604800s"
  }

  documentation {
    content   = <<-DOC
      ## Unusual API Calls Detected

      Event Threat Detection has identified API calls that deviate from
      the normal pattern for this project. This may indicate:
      - Post-compromise reconnaissance
      - Privilege escalation attempts
      - Data access by compromised credentials

      ### Investigation Steps:
      1. Review the specific API calls in Cloud Audit Logs
      2. Identify the caller identity and source IP
      3. Check if the activity correlates with known APT indicators
      4. Verify with the team if the activity is expected
    DOC
    mime_type = "text/markdown"
  }
}

# -----------------------------------------------------------------------------
# Alert Policy - Container Threat Detection Findings
# -----------------------------------------------------------------------------
# Container Threat Detection (CTD) is a GKE-specific feature that detects
# runtime threats in containers including reverse shells, added binaries,
# and modified binaries.
# -----------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "container_threats" {
  project      = var.project_id
  display_name = "CTD - Container Runtime Threat Detected"
  combiner     = "OR"

  conditions {
    display_name = "Container Threat Detection Finding"

    condition_matched_log {
      filter = <<-FILTER
        resource.type="threat_detector"
        (
          jsonPayload.findingCategory="ADDED_BINARY_EXECUTED" OR
          jsonPayload.findingCategory="ADDED_LIBRARY_LOADED" OR
          jsonPayload.findingCategory="REVERSE_SHELL" OR
          jsonPayload.findingCategory="EXECUTION_ADDED_BINARY_EXECUTED" OR
          jsonPayload.findingCategory="EXECUTION_MODIFIED_BINARY_EXECUTED" OR
          jsonPayload.findingCategory="MALICIOUS_SCRIPT_EXECUTED" OR
          jsonPayload.findingCategory="MALICIOUS_URL_OBSERVED" OR
          jsonPayload.findingCategory="PRIVILEGE_ESCALATION_CONTAINER"
        )
      FILTER
    }
  }

  alert_strategy {
    notification_rate_limit {
      period = "60s"
    }
    auto_close = "604800s"
  }

  documentation {
    content   = <<-DOC
      ## Container Runtime Threat Detected

      GCP Container Threat Detection has identified a runtime threat in
      a GKE container. This is a high-confidence detection.

      ### Finding Categories:
      - **ADDED_BINARY_EXECUTED**: A binary not in the original image was run
      - **ADDED_LIBRARY_LOADED**: A library not in the original image was loaded
      - **REVERSE_SHELL**: A reverse shell connection was detected
      - **MALICIOUS_SCRIPT_EXECUTED**: A known malicious script was executed
      - **PRIVILEGE_ESCALATION_CONTAINER**: Container privilege escalation detected

      ### Immediate Actions:
      1. Identify the affected pod and container from the finding
      2. Quarantine immediately: `./auto-response/quarantine-pod.sh <ns> <pod>`
      3. Capture forensic evidence before terminating
      4. Check Falco alerts for correlated runtime detections
      5. Review the container image for supply chain compromise
      6. Escalate to incident response team
    DOC
    mime_type = "text/markdown"
  }
}

# -----------------------------------------------------------------------------
# Log-Based Metric - IAM Policy Changes
# -----------------------------------------------------------------------------
# Track IAM policy modifications that could indicate privilege escalation.
# APT groups modify IAM policies to maintain persistence and expand access.
# -----------------------------------------------------------------------------
resource "google_logging_metric" "iam_policy_changes" {
  project = var.project_id
  name    = "iam-policy-modifications"

  description = "Count of IAM policy modifications that may indicate privilege escalation"

  filter = <<-FILTER
    protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
    (
      protoPayload.methodName="SetIamPolicy" OR
      protoPayload.methodName="google.iam.admin.v1.CreateRole" OR
      protoPayload.methodName="google.iam.admin.v1.UpdateRole" OR
      protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
    )
  FILTER

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "method"
      value_type  = "STRING"
      description = "The IAM method that was called"
    }
    labels {
      key         = "caller"
      value_type  = "STRING"
      description = "The identity that made the IAM change"
    }
  }

  label_extractors = {
    "method" = "EXTRACT(protoPayload.methodName)"
    "caller" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# -----------------------------------------------------------------------------
# Log-Based Metric - GKE Admin Activity
# -----------------------------------------------------------------------------
# Track administrative actions on GKE clusters that could indicate
# APT activity (creating privileged pods, modifying RBAC, etc.)
# -----------------------------------------------------------------------------
resource "google_logging_metric" "gke_admin_activity" {
  project = var.project_id
  name    = "gke-suspicious-admin-activity"

  description = "Count of suspicious GKE administrative actions"

  filter = <<-FILTER
    resource.type="k8s_cluster"
    protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
    (
      protoPayload.methodName="io.k8s.core.v1.pods.create" OR
      protoPayload.methodName="io.k8s.core.v1.secrets.get" OR
      protoPayload.methodName="io.k8s.core.v1.secrets.list" OR
      protoPayload.methodName=~"io.k8s.authorization.*" OR
      protoPayload.methodName="io.k8s.core.v1.pods.exec.create" OR
      protoPayload.methodName="io.k8s.core.v1.pods.attach.create"
    )
  FILTER

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "method"
      value_type  = "STRING"
      description = "K8s API method"
    }
  }

  label_extractors = {
    "method" = "EXTRACT(protoPayload.methodName)"
  }
}

# -----------------------------------------------------------------------------
# Alert Policy - SA Key Creation (Prevention)
# -----------------------------------------------------------------------------
# Alert on any service account key creation. In a well-configured GKE
# environment using Workload Identity, no SA keys should be created.
# Any key creation is suspicious and may indicate an attacker establishing
# persistence.
# -----------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "sa_key_creation" {
  project      = var.project_id
  display_name = "IAM - Service Account Key Created"
  combiner     = "OR"

  conditions {
    display_name = "SA Key Creation Event"

    condition_matched_log {
      filter = <<-FILTER
        protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
        protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
      FILTER
    }
  }

  alert_strategy {
    notification_rate_limit {
      period = "60s"
    }
    auto_close = "604800s"
  }

  documentation {
    content   = <<-DOC
      ## Service Account Key Created

      A new service account key has been created. In this environment,
      Workload Identity is used for all authentication, so SA key
      creation should not occur during normal operations.

      ### This Could Indicate:
      - An attacker creating keys for persistent access
      - Unauthorized manual configuration changes
      - Compromised admin credentials

      ### Immediate Actions:
      1. Identify WHO created the key (check caller identity)
      2. Identify WHICH service account got a new key
      3. If unauthorized, delete the key immediately
      4. If attacker activity, disable the entire service account:
         `./auto-response/revoke-sa.sh <sa-email>`
      5. Audit all recent actions by the caller identity
    DOC
    mime_type = "text/markdown"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "crypto_mining_alert_policy" {
  description = "Alert policy ID for crypto mining detection"
  value       = google_monitoring_alert_policy.crypto_mining.name
}

output "sa_abuse_alert_policy" {
  description = "Alert policy ID for service account abuse detection"
  value       = google_monitoring_alert_policy.sa_key_abuse.name
}

output "container_threat_alert_policy" {
  description = "Alert policy ID for container threat detection"
  value       = google_monitoring_alert_policy.container_threats.name
}
