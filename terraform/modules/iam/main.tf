# =============================================================================
# IAM Module - Workload Identity Federation & Service Accounts
# =============================================================================
#
# Implements a zero-trust identity model with NO service account keys.
#
# ARCHITECTURE:
# 1. Workload Identity Federation Pool + GitHub OIDC Provider
#    - GitHub Actions authenticate via OIDC tokens (short-lived, no secrets)
#    - Token exchange: GitHub OIDC -> Google STS -> Google Access Token
#    - Scoped to specific GitHub org/repo for security
#
# 2. Service Accounts (with minimal privileges):
#    - Trivy SA: Reads GKE cluster info, writes scan results to BigQuery
#    - Cloud Build SA: Deploys to GKE, reads from Artifact Registry
#    - BigQuery Writer SA: Insert-only access to vulnerability tables
#
# SECURITY PRINCIPLES:
# - NO service account keys are generated (zero key exposure risk)
# - All authentication uses short-lived tokens via federation
# - Each SA has minimal IAM roles (principle of least privilege)
# - Workload Identity binds K8s SAs to Google SAs (no key injection)
#
# APT SCENARIO RELEVANCE:
# Traditional attacks often steal service account key files from compromised
# containers. With Workload Identity Federation:
# - There are no key files to steal
# - Tokens are short-lived (1 hour) and non-exportable
# - Token theft is detectable via audit logs
# - Impersonation requires compromising the K8s SA binding
# =============================================================================

# -----------------------------------------------------------------------------
# Workload Identity Federation Pool
# -----------------------------------------------------------------------------
# A pool is a logical grouping of identity providers. Each pool can have
# multiple providers (e.g., GitHub, GitLab, AWS).
# We create one pool for CI/CD automation.
# -----------------------------------------------------------------------------

resource "google_iam_workload_identity_pool" "github_pool" {
  project                   = var.project_id
  workload_identity_pool_id = "github-actions-pool-${var.environment}"
  display_name              = "GitHub Actions Pool (${var.environment})"
  description               = "Workload Identity Pool for GitHub Actions CI/CD pipelines. Eliminates need for service account keys."
  disabled                  = false
}

# -----------------------------------------------------------------------------
# Workload Identity Federation Provider (GitHub OIDC)
# -----------------------------------------------------------------------------
# Configures GitHub as an OIDC identity provider.
#
# SECURITY:
# - attribute_condition restricts which GitHub repos can authenticate
# - Only tokens from the specified org/repo are accepted
# - The assertion.sub attribute maps to the GitHub repository
# - Token issuer is validated against GitHub's OIDC endpoint
#
# HOW IT WORKS:
# 1. GitHub Actions workflow requests an OIDC token from GitHub
# 2. Token is sent to Google STS (Security Token Service)
# 3. STS validates the token against GitHub's OIDC discovery document
# 4. If attribute_condition matches, STS issues a short-lived Google token
# 5. The Google token is used to authenticate API calls
# -----------------------------------------------------------------------------

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc-provider"
  display_name                       = "GitHub OIDC Provider"
  description                        = "OIDC provider for GitHub Actions. Validates tokens from ${var.github_org}/${var.github_repo}."

  # Restrict to specific GitHub org and repo
  # This prevents other repos from authenticating to this project
  attribute_condition = "assertion.repository_owner == '${var.github_org}'"

  # Map GitHub token claims to Google attributes
  attribute_mapping = {
    # Standard OIDC subject claim (repo:org/repo:ref:refs/heads/main)
    "google.subject" = "assertion.sub"
    # Custom attributes for fine-grained access control
    "attribute.actor"            = "assertion.actor"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
    "attribute.ref"              = "assertion.ref"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# =============================================================================
# SERVICE ACCOUNTS
# =============================================================================
# Each service account follows the principle of least privilege.
# No keys are created for any service account.
# =============================================================================

# -----------------------------------------------------------------------------
# Trivy Operator Service Account
# -----------------------------------------------------------------------------
# Used by the Trivy Operator running in GKE to:
# - Read cluster information for scanning
# - Write vulnerability results to BigQuery
#
# Bound to a Kubernetes service account via Workload Identity.
# Pod: trivy-operator in trivy-system namespace
# KSA: trivy-operator -> GSA: trivy-operator@project.iam.gserviceaccount.com
# -----------------------------------------------------------------------------

resource "google_service_account" "trivy_operator" {
  account_id   = "trivy-operator-${var.environment}"
  project      = var.project_id
  display_name = "Trivy Operator SA (${var.environment})"
  description  = "Service account for Trivy vulnerability scanner. NO keys generated - uses Workload Identity."
}

# Trivy needs to read container images for scanning
resource "google_project_iam_member" "trivy_artifact_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.trivy_operator.email}"
}

# Trivy needs to read GKE cluster information
resource "google_project_iam_member" "trivy_container_viewer" {
  project = var.project_id
  role    = "roles/container.viewer"
  member  = "serviceAccount:${google_service_account.trivy_operator.email}"
}

# Trivy writes scan results to BigQuery
resource "google_project_iam_member" "trivy_bigquery_editor" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = "serviceAccount:${google_service_account.trivy_operator.email}"
}

# BigQuery job execution (needed to run INSERT queries)
resource "google_project_iam_member" "trivy_bigquery_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.trivy_operator.email}"
}

# Workload Identity binding: K8s SA -> Google SA
# This allows pods with the "trivy-operator" K8s SA in "trivy-system" namespace
# to authenticate as the Google SA without any keys.
resource "google_service_account_iam_member" "trivy_workload_identity" {
  service_account_id = google_service_account.trivy_operator.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[trivy-system/trivy-operator]"
}

# -----------------------------------------------------------------------------
# Cloud Build Service Account
# -----------------------------------------------------------------------------
# Used by Cloud Build to:
# - Deploy Helm charts to GKE (Trivy, Falco, Suricata)
# - Run Terraform plan/apply
# - Read from Artifact Registry
#
# This SA is used by Cloud Build triggers, NOT by Workload Identity.
# It's referenced by the Cloud Build trigger configuration.
# -----------------------------------------------------------------------------

resource "google_service_account" "cloudbuild" {
  account_id   = "cloudbuild-deployer-${var.environment}"
  project      = var.project_id
  display_name = "Cloud Build Deployer SA (${var.environment})"
  description  = "Service account for Cloud Build CI/CD pipelines. NO keys generated."
}

# Cloud Build needs to deploy to GKE
resource "google_project_iam_member" "cloudbuild_gke_developer" {
  project = var.project_id
  role    = "roles/container.developer"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Cloud Build needs to read images from Artifact Registry
resource "google_project_iam_member" "cloudbuild_artifact_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Cloud Build needs to run builds
resource "google_project_iam_member" "cloudbuild_builder" {
  project = var.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Cloud Build needs to write logs
resource "google_project_iam_member" "cloudbuild_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Cloud Build needs to manage GKE resources (for Terraform)
resource "google_project_iam_member" "cloudbuild_gke_admin" {
  project = var.project_id
  role    = "roles/container.admin"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Cloud Build needs compute network access for Terraform
resource "google_project_iam_member" "cloudbuild_compute_admin" {
  project = var.project_id
  role    = "roles/compute.networkAdmin"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Cloud Build SA can impersonate itself (needed for Terraform backend)
resource "google_service_account_iam_member" "cloudbuild_self_impersonate" {
  service_account_id = google_service_account.cloudbuild.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Allow GitHub Actions to impersonate Cloud Build SA via WIF
resource "google_service_account_iam_member" "cloudbuild_github_wif" {
  service_account_id = google_service_account.cloudbuild.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}

# -----------------------------------------------------------------------------
# BigQuery Writer Service Account
# -----------------------------------------------------------------------------
# Minimal-privilege SA specifically for writing vulnerability data to BigQuery.
# Used by the vulnerability export CronJob or Cloud Function.
#
# SECURITY: This SA can ONLY insert data into the security_findings dataset.
# It cannot read, update, or delete existing data.
# -----------------------------------------------------------------------------

resource "google_service_account" "bigquery_writer" {
  account_id   = "bq-vuln-writer-${var.environment}"
  project      = var.project_id
  display_name = "BigQuery Vulnerability Writer SA (${var.environment})"
  description  = "Minimal-privilege SA for writing vulnerability data to BigQuery. Insert-only access."
}

# BigQuery data editor on the specific dataset only
resource "google_bigquery_dataset_iam_member" "writer_dataset_access" {
  project    = var.project_id
  dataset_id = var.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.bigquery_writer.email}"
}

# BigQuery job user (needed to execute INSERT queries)
resource "google_project_iam_member" "writer_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.bigquery_writer.email}"
}

# Workload Identity binding for BQ writer
# Allows the "bq-writer" K8s SA in "trivy-system" namespace to use this GSA
resource "google_service_account_iam_member" "bigquery_writer_workload_identity" {
  service_account_id = google_service_account.bigquery_writer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[trivy-system/bq-writer]"
}

# Allow GitHub Actions to impersonate BQ writer SA via WIF
resource "google_service_account_iam_member" "bigquery_writer_github_wif" {
  service_account_id = google_service_account.bigquery_writer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}

# -----------------------------------------------------------------------------
# Falco Service Account (for runtime security monitoring)
# -----------------------------------------------------------------------------
# Used by Falco for runtime threat detection. Needs minimal permissions
# since it primarily reads system calls and writes alerts.
# -----------------------------------------------------------------------------

resource "google_service_account" "falco" {
  account_id   = "falco-runtime-${var.environment}"
  project      = var.project_id
  display_name = "Falco Runtime Monitor SA (${var.environment})"
  description  = "Service account for Falco runtime security monitoring."
}

# Falco needs to write alerts to Cloud Logging
resource "google_project_iam_member" "falco_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.falco.email}"
}

# Falco needs to publish alerts to Pub/Sub (for alerting pipeline)
resource "google_project_iam_member" "falco_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.falco.email}"
}

# Workload Identity binding for Falco
resource "google_service_account_iam_member" "falco_workload_identity" {
  service_account_id = google_service_account.falco.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[falco-system/falco]"
}
