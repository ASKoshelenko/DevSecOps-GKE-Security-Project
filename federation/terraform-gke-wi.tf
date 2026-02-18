# =============================================================================
# GKE Workload Identity - Pod-Level Identity Configuration
# =============================================================================
#
# PURPOSE:
# Configures GKE Workload Identity so that pods authenticate to GCP services
# using Kubernetes service accounts (KSAs) mapped to Google Cloud service
# accounts (GSAs). This eliminates the need for service account key files
# mounted as secrets in pods.
#
# HOW GKE WORKLOAD IDENTITY WORKS:
#
#   Pod (KSA: trivy-sa) --> GKE Metadata Server --> GCP IAM --> GCP SA Token
#                           (intercepts metadata     (validates    (short-lived
#                            server requests)         KSA->GSA      OAuth2
#                                                     binding)      token)
#
# Instead of the pod reaching the real GCE metadata server (169.254.169.254),
# GKE injects a metadata proxy that intercepts requests and returns tokens
# scoped to the mapped GSA. The pod code does not need any changes - standard
# Google Cloud client libraries work transparently.
#
# SECURITY PROPERTIES:
# - No service account keys stored in Kubernetes secrets
# - Tokens are automatically rotated (1-hour lifetime)
# - Per-pod identity: different pods can have different GSA mappings
# - Metadata server hardening: prevents SSRF-based token theft
# - Full audit trail: every token request is logged in Cloud Audit Logs
#
# =============================================================================

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "gke_wi_project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "gke_wi_environment" {
  description = "Environment name (prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "gke_wi_cluster_name" {
  description = "Name of the GKE cluster where Workload Identity is enabled"
  type        = string
  default     = "devsecops-gke"
}

variable "gke_wi_location" {
  description = "GKE cluster location (zone or region)"
  type        = string
  default     = "us-central1-a"
}

# -----------------------------------------------------------------------------
# Local Values - Workload Identity Mappings
# -----------------------------------------------------------------------------
# Define all KSA-to-GSA mappings centrally. Each entry represents a
# Kubernetes service account that needs to access GCP services.
#
# PRINCIPLE OF LEAST PRIVILEGE:
# Each GSA gets only the IAM roles it absolutely needs. No GSA has
# roles/editor or roles/owner. All access is scoped to specific resources.
# -----------------------------------------------------------------------------

locals {
  # Namespace where security tooling runs
  security_namespace = "security-tools"

  # Namespace for application workloads
  app_namespace = "default"

  # All workload identity mappings
  workload_identity_mappings = {
    # ----- Security Tooling -----

    trivy_operator = {
      ksa_name      = "trivy-operator"
      ksa_namespace = local.security_namespace
      gsa_id        = "trivy-operator-wi-${var.gke_wi_environment}"
      gsa_display   = "Trivy Operator Workload Identity (${var.gke_wi_environment})"
      gsa_description = "GSA for Trivy Operator running in GKE. Scans container images and writes vulnerability findings to BigQuery."
      roles = [
        "roles/bigquery.dataEditor",          # Write scan results to BigQuery
        "roles/artifactregistry.reader",      # Pull images from Artifact Registry for scanning
        "roles/containeranalysis.notes.viewer", # Read vulnerability notes
      ]
    }

    falco = {
      ksa_name      = "falco"
      ksa_namespace = local.security_namespace
      gsa_id        = "falco-wi-${var.gke_wi_environment}"
      gsa_display   = "Falco Workload Identity (${var.gke_wi_environment})"
      gsa_description = "GSA for Falco runtime security. Publishes security events to Cloud Pub/Sub and writes alerts to BigQuery."
      roles = [
        "roles/pubsub.publisher",            # Publish security events
        "roles/bigquery.dataEditor",          # Write runtime alerts
        "roles/logging.logWriter",            # Write to Cloud Logging
      ]
    }

    suricata = {
      ksa_name      = "suricata"
      ksa_namespace = local.security_namespace
      gsa_id        = "suricata-wi-${var.gke_wi_environment}"
      gsa_display   = "Suricata IDS Workload Identity (${var.gke_wi_environment})"
      gsa_description = "GSA for Suricata IDS. Writes network intrusion alerts to BigQuery and Cloud Logging."
      roles = [
        "roles/bigquery.dataEditor",          # Write IDS alerts
        "roles/logging.logWriter",            # Write to Cloud Logging
      ]
    }

    # ----- Application Workloads -----

    bigquery_exporter = {
      ksa_name      = "bq-exporter"
      ksa_namespace = local.app_namespace
      gsa_id        = "bq-exporter-wi-${var.gke_wi_environment}"
      gsa_display   = "BigQuery Exporter Workload Identity (${var.gke_wi_environment})"
      gsa_description = "GSA for the BigQuery exporter service that aggregates and processes security findings."
      roles = [
        "roles/bigquery.dataEditor",          # Read/write security findings
        "roles/bigquery.jobUser",             # Run BigQuery jobs
      ]
    }

    log_shipper = {
      ksa_name      = "log-shipper"
      ksa_namespace = local.app_namespace
      gsa_id        = "log-shipper-wi-${var.gke_wi_environment}"
      gsa_display   = "Log Shipper Workload Identity (${var.gke_wi_environment})"
      gsa_description = "GSA for the log shipping service that exports pod logs to Cloud Storage for long-term retention."
      roles = [
        "roles/storage.objectCreator",        # Write log archives to GCS
        "roles/logging.viewer",               # Read from Cloud Logging
      ]
    }
  }
}

# -----------------------------------------------------------------------------
# Google Cloud Service Accounts (GSAs)
# -----------------------------------------------------------------------------
# One GSA per workload. No keys are created - authentication is exclusively
# via the GKE metadata server's Workload Identity integration.
# -----------------------------------------------------------------------------

resource "google_service_account" "workload_identity" {
  for_each = local.workload_identity_mappings

  project      = var.gke_wi_project_id
  account_id   = each.value.gsa_id
  display_name = each.value.gsa_display
  description  = each.value.gsa_description
}

# -----------------------------------------------------------------------------
# IAM Role Bindings for GSAs
# -----------------------------------------------------------------------------
# Grant each GSA its required roles. Uses for_each with flattened map
# to create one binding per (service_account, role) pair.
# -----------------------------------------------------------------------------

resource "google_project_iam_member" "workload_identity_roles" {
  for_each = {
    for pair in flatten([
      for wi_key, wi_config in local.workload_identity_mappings : [
        for role in wi_config.roles : {
          key  = "${wi_key}-${replace(role, "/", "_")}"
          role = role
          wi   = wi_key
        }
      ]
    ]) : pair.key => pair
  }

  project = var.gke_wi_project_id
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.workload_identity[each.value.wi].email}"
}

# -----------------------------------------------------------------------------
# Workload Identity IAM Binding (KSA -> GSA)
# -----------------------------------------------------------------------------
# This is the critical binding that allows a Kubernetes service account
# to act as a Google Cloud service account. The binding uses the
# roles/iam.workloadIdentityUser role.
#
# Format of the member:
#   serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/KSA_NAME]
#
# This tells GCP IAM: "When a KSA named X in namespace Y presents a token
# via the GKE metadata server, treat it as this GSA."
# -----------------------------------------------------------------------------

resource "google_service_account_iam_member" "workload_identity_binding" {
  for_each = local.workload_identity_mappings

  service_account_id = google_service_account.workload_identity[each.key].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.gke_wi_project_id}.svc.id.goog[${each.value.ksa_namespace}/${each.value.ksa_name}]"
}

# -----------------------------------------------------------------------------
# Kubernetes Namespaces
# -----------------------------------------------------------------------------
# Create the required namespaces if they do not already exist.
# The security-tools namespace is isolated from application workloads.
# -----------------------------------------------------------------------------

resource "kubernetes_namespace" "security_tools" {
  metadata {
    name = local.security_namespace

    labels = {
      name                          = local.security_namespace
      "app.kubernetes.io/managed-by" = "terraform"
      # Enforce restricted pod security standards
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }

    annotations = {
      "purpose" = "Security tooling (Trivy, Falco, Suricata) with Workload Identity"
    }
  }
}

# -----------------------------------------------------------------------------
# Kubernetes Service Accounts (KSAs)
# -----------------------------------------------------------------------------
# Each KSA is annotated with the GSA email it maps to.
# This annotation is what the GKE metadata server uses to determine
# which GSA tokens to issue when a pod requests credentials.
#
# IMPORTANT: The annotation MUST match the IAM binding above, or the
# metadata server will return "permission denied" errors.
# -----------------------------------------------------------------------------

resource "kubernetes_service_account" "workload_identity" {
  for_each = local.workload_identity_mappings

  metadata {
    name      = each.value.ksa_name
    namespace = each.value.ksa_namespace

    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "app.kubernetes.io/component"  = each.key
      "iam.gke.io/gcp-sa"           = google_service_account.workload_identity[each.key].email
    }

    # This annotation is the key link between KSA and GSA
    annotations = {
      "iam.gke.io/gcp-service-account" = google_service_account.workload_identity[each.key].email
    }
  }

  # Disable automatic secret token mounting
  # Workload Identity uses projected service account tokens instead
  automount_service_account_token = false

  depends_on = [
    kubernetes_namespace.security_tools,
    google_service_account_iam_member.workload_identity_binding,
  ]
}

# -----------------------------------------------------------------------------
# GKE Cluster Configuration - Workload Identity Must Be Enabled
# -----------------------------------------------------------------------------
# NOTE: This data source validates that the target GKE cluster has
# Workload Identity enabled. If not, the KSA->GSA binding will not work.
# Workload Identity is configured at the cluster level in the GKE module.
# -----------------------------------------------------------------------------

data "google_container_cluster" "target" {
  name     = var.gke_wi_cluster_name
  location = var.gke_wi_location
  project  = var.gke_wi_project_id
}

# -----------------------------------------------------------------------------
# Validation: Ensure Workload Identity is enabled on the cluster
# -----------------------------------------------------------------------------

resource "null_resource" "validate_workload_identity" {
  lifecycle {
    precondition {
      condition     = data.google_container_cluster.target.workload_identity_config != null
      error_message = "GKE cluster '${var.gke_wi_cluster_name}' does not have Workload Identity enabled. Enable it in the GKE module before configuring pod-level Workload Identity."
    }
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "workload_identity_mappings" {
  description = "Map of all KSA-to-GSA Workload Identity bindings"
  value = {
    for key, config in local.workload_identity_mappings : key => {
      ksa           = "${config.ksa_namespace}/${config.ksa_name}"
      gsa_email     = google_service_account.workload_identity[key].email
      roles         = config.roles
    }
  }
}

output "security_namespace" {
  description = "Namespace where security tooling is deployed"
  value       = local.security_namespace
}

output "trivy_operator_ksa" {
  description = "Name of the Trivy operator Kubernetes service account"
  value       = kubernetes_service_account.workload_identity["trivy_operator"].metadata[0].name
}

output "falco_ksa" {
  description = "Name of the Falco Kubernetes service account"
  value       = kubernetes_service_account.workload_identity["falco"].metadata[0].name
}
