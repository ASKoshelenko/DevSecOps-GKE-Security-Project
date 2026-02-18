# =============================================================================
# Cloud Build Module - CI/CD Pipeline Triggers
# =============================================================================
#
# Creates Cloud Build triggers for automated deployment pipelines:
#
# 1. Trivy Deployment Pipeline:
#    - Triggered on changes to helm/trivy-operator/ or cloudbuild/cloudbuild-trivy.yaml
#    - Deploys/upgrades the Trivy Operator via Helm to the GKE cluster
#    - Configures Trivy to scan all namespaces and export findings to BigQuery
#
# 2. Terraform Plan/Apply Pipeline:
#    - Plan: Triggered on pull requests to main branch
#    - Apply: Triggered on merges to main branch
#    - Uses the least-privilege Cloud Build service account
#    - State is stored in GCS backend
#
# SECURITY:
# - All triggers use a dedicated service account (not the default Cloud Build SA)
# - Service account has minimal IAM roles defined in the IAM module
# - No secrets are stored in trigger substitutions (uses WIF for auth)
# - Build logs are retained for audit purposes
# =============================================================================

# -----------------------------------------------------------------------------
# Cloud Build Trigger: Trivy Operator Deployment
# -----------------------------------------------------------------------------
# Deploys the Trivy Operator to GKE when Helm chart or build config changes.
# The pipeline:
# 1. Authenticates to GKE cluster
# 2. Installs/upgrades Trivy Operator via Helm
# 3. Configures vulnerability report export to BigQuery
# 4. Verifies deployment health
# -----------------------------------------------------------------------------

resource "google_cloudbuild_trigger" "trivy_deploy" {
  project     = var.project_id
  name        = "deploy-trivy-operator-${var.environment}"
  description = "Deploys Trivy Operator to GKE for container vulnerability scanning"
  location    = var.region

  # Use the dedicated Cloud Build service account
  service_account = var.cloudbuild_service_account_id

  # GitHub repository connection
  github {
    owner = var.github_org
    name  = var.github_repo

    push {
      branch = "^main$"
    }
  }

  # Only trigger on changes to relevant files
  included_files = [
    "helm/trivy-operator/**",
    "cloudbuild/cloudbuild-trivy.yaml",
    "scripts/deploy-trivy.sh",
  ]

  # Cloud Build configuration file location
  filename = "cloudbuild/cloudbuild-trivy.yaml"

  # Substitution variables passed to the build
  substitutions = {
    _CLUSTER_NAME = "devsecops-gke-${var.environment}"
    _CLUSTER_ZONE = "us-central1-a"
    _ENVIRONMENT  = var.environment
    _NAMESPACE    = "trivy-system"
  }

  # Include build logs for debugging
  include_build_logs = "INCLUDE_BUILD_LOGS_WITH_STATUS"

  tags = ["trivy", "security", var.environment]
}

# -----------------------------------------------------------------------------
# Cloud Build Trigger: Terraform Plan (Pull Requests)
# -----------------------------------------------------------------------------
# Runs terraform plan on pull requests targeting the main branch.
# The plan output is posted as a PR comment for review.
# This trigger does NOT apply changes -- it only shows what would change.
# -----------------------------------------------------------------------------

resource "google_cloudbuild_trigger" "terraform_plan" {
  project     = var.project_id
  name        = "terraform-plan-${var.environment}"
  description = "Runs terraform plan on pull requests for infrastructure review"
  location    = var.region

  service_account = var.cloudbuild_service_account_id

  github {
    owner = var.github_org
    name  = var.github_repo

    pull_request {
      branch          = "^main$"
      comment_control = "COMMENTS_ENABLED"
    }
  }

  included_files = [
    "terraform/**",
    "cloudbuild/cloudbuild-terraform.yaml",
  ]

  filename = "cloudbuild/cloudbuild-terraform.yaml"

  substitutions = {
    _TF_ACTION    = "plan"
    _ENVIRONMENT  = var.environment
    _TF_DIR       = "terraform"
  }

  include_build_logs = "INCLUDE_BUILD_LOGS_WITH_STATUS"

  tags = ["terraform", "plan", var.environment]
}

# -----------------------------------------------------------------------------
# Cloud Build Trigger: Terraform Apply (Main Branch)
# -----------------------------------------------------------------------------
# Runs terraform apply on pushes to the main branch (after PR merge).
# This trigger applies the planned infrastructure changes.
#
# SAFETY:
# - Only triggers on the main branch (not feature branches)
# - Uses auto-approve since changes were reviewed in the PR plan step
# - Service account has scoped permissions from the IAM module
# - State locking prevents concurrent applies
# -----------------------------------------------------------------------------

resource "google_cloudbuild_trigger" "terraform_apply" {
  project     = var.project_id
  name        = "terraform-apply-${var.environment}"
  description = "Applies Terraform changes when merged to main branch"
  location    = var.region

  service_account = var.cloudbuild_service_account_id

  github {
    owner = var.github_org
    name  = var.github_repo

    push {
      branch = "^main$"
    }
  }

  included_files = [
    "terraform/**",
    "cloudbuild/cloudbuild-terraform.yaml",
  ]

  filename = "cloudbuild/cloudbuild-terraform.yaml"

  substitutions = {
    _TF_ACTION    = "apply"
    _ENVIRONMENT  = var.environment
    _TF_DIR       = "terraform"
  }

  include_build_logs = "INCLUDE_BUILD_LOGS_WITH_STATUS"

  tags = ["terraform", "apply", var.environment]
}
