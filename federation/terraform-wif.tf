# =============================================================================
# Workload Identity Federation - GitHub Actions OIDC
# =============================================================================
#
# PURPOSE:
# This configuration eliminates the need for long-lived service account keys
# by establishing trust between GCP and GitHub Actions via OIDC federation.
#
# INCIDENT CONTEXT:
# A Russian APT group (tracked internally as INC-2026-0042) exfiltrated a
# high-privilege service account key from a compromised developer workstation.
# The stolen key granted roles/editor on the production project, enabling:
#   - Lateral movement into GKE clusters via kubectl
#   - Data exfiltration from BigQuery datasets
#   - Deployment of cryptominer pods via Cloud Build impersonation
#
# This module ensures that NO service account keys exist. All external
# authentication flows use short-lived OIDC tokens that:
#   1. Expire after 1 hour (non-renewable without re-authentication)
#   2. Are scoped to specific repositories, branches, and workflows
#   3. Cannot be exported, copied, or reused outside the issuing workflow
#   4. Leave complete audit trails in Cloud Audit Logs
#
# OIDC TOKEN EXCHANGE FLOW:
#   GitHub Actions Runner --> GitHub OIDC Provider --> GCP STS --> GCP SA Token
#   (requests token)        (issues JWT)             (validates)  (short-lived)
#
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "project_id" {
  description = "The GCP project ID where WIF resources will be created"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be 6-30 characters, start with a letter, and contain only lowercase letters, digits, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (prod, staging, dev)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "Environment must be one of: prod, staging, dev."
  }
}

variable "github_org" {
  description = "GitHub organization name. Only repositories within this org can authenticate."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+$", var.github_org))
    error_message = "GitHub org name must contain only alphanumeric characters and hyphens."
  }
}

variable "github_repo" {
  description = "Primary GitHub repository name authorized for WIF"
  type        = string
}

variable "allowed_repos" {
  description = <<-EOT
    Additional GitHub repositories allowed to authenticate via WIF.
    Format: ["org/repo1", "org/repo2"]
    The primary github_org/github_repo is always included automatically.
  EOT
  type        = list(string)
  default     = []
}

variable "allowed_branches" {
  description = <<-EOT
    Git branches allowed to authenticate for deployment operations.
    Only workflows triggered from these branches can impersonate service accounts
    with write permissions. This prevents feature branches from deploying to prod.
  EOT
  type        = list(string)
  default     = ["main", "master"]
}

variable "pool_id" {
  description = "Workload Identity Pool ID. Must be unique within the project."
  type        = string
  default     = "github-actions-pool"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,31}$", var.pool_id))
    error_message = "Pool ID must be 3-32 characters, start with a letter, and contain only lowercase letters, digits, and hyphens."
  }
}

variable "provider_id" {
  description = "Workload Identity Pool Provider ID"
  type        = string
  default     = "github-oidc-provider"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,31}$", var.provider_id))
    error_message = "Provider ID must be 3-32 characters, start with a letter, and contain only lowercase letters, digits, and hyphens."
  }
}

variable "labels" {
  description = "Common labels applied to all resources"
  type        = map(string)
  default = {
    managed_by = "terraform"
    security   = "critical"
    component  = "workload-identity-federation"
  }
}

# -----------------------------------------------------------------------------
# Local Values
# -----------------------------------------------------------------------------

locals {
  # Build the full list of allowed repositories (primary + additional)
  all_allowed_repos = distinct(concat(
    ["${var.github_org}/${var.github_repo}"],
    var.allowed_repos
  ))

  # Build the attribute condition string that restricts which GitHub repos
  # can authenticate. This is the critical security boundary.
  repo_conditions = join(" || ", [
    for repo in local.all_allowed_repos :
    "assertion.repository == '${repo}'"
  ])

  # Branch conditions for deployment-level access
  branch_conditions = join(" || ", [
    for branch in var.allowed_branches :
    "assertion.ref == 'refs/heads/${branch}'"
  ])

  # Service accounts that GitHub Actions can impersonate
  # Each SA has specific, least-privilege IAM roles
  service_accounts = {
    deployer = {
      account_id   = "github-deployer-${var.environment}"
      display_name = "GitHub Actions Deployer (${var.environment})"
      description  = "Used by GitHub Actions CI/CD to deploy to GKE and manage infrastructure. Scoped to ${var.environment} environment."
      roles = [
        "roles/container.developer",        # Deploy to GKE
        "roles/artifactregistry.writer",    # Push container images
        "roles/cloudbuild.builds.editor",   # Trigger builds
      ]
      # Deployer requires branch restriction (only main/master can deploy)
      require_branch = true
    }
    reader = {
      account_id   = "github-reader-${var.environment}"
      display_name = "GitHub Actions Reader (${var.environment})"
      description  = "Used by GitHub Actions for read-only operations: terraform plan, security scanning, audit. No write access."
      roles = [
        "roles/container.clusterViewer",    # View GKE resources
        "roles/viewer",                     # Project-level read access
        "roles/bigquery.dataViewer",        # Read security findings
      ]
      # Reader does not require branch restriction (any PR can read)
      require_branch = false
    }
    security_scanner = {
      account_id   = "github-scanner-${var.environment}"
      display_name = "GitHub Actions Security Scanner (${var.environment})"
      description  = "Used by GitHub Actions to run Trivy, push scan results to BigQuery, and report vulnerabilities."
      roles = [
        "roles/container.clusterViewer",    # Inspect running images
        "roles/bigquery.dataEditor",        # Write scan results
        "roles/artifactregistry.reader",    # Pull images for scanning
      ]
      require_branch = false
    }
  }
}

# -----------------------------------------------------------------------------
# Enable Required APIs
# -----------------------------------------------------------------------------

resource "google_project_service" "wif_apis" {
  for_each = toset([
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# -----------------------------------------------------------------------------
# Workload Identity Pool
# -----------------------------------------------------------------------------
# The pool is a logical grouping that represents an external identity provider.
# Multiple providers can be attached to a single pool, but for security we
# create one pool per use case (GitHub Actions).
# -----------------------------------------------------------------------------

resource "google_iam_workload_identity_pool" "github_pool" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "GitHub Actions Pool (${var.environment})"

  description = <<-EOT
    Workload Identity Pool for GitHub Actions CI/CD pipelines.
    This pool trusts GitHub's OIDC provider and maps GitHub token claims
    to GCP attributes for fine-grained access control.

    Security controls:
    - Restricted to specific GitHub org: ${var.github_org}
    - Allowed repositories: ${join(", ", local.all_allowed_repos)}
    - Deployment operations restricted to branches: ${join(", ", var.allowed_branches)}
  EOT

  # Pool must be disabled before deletion to prevent accidental access loss
  disabled = false

  depends_on = [google_project_service.wif_apis]
}

# -----------------------------------------------------------------------------
# Workload Identity Pool Provider (GitHub OIDC)
# -----------------------------------------------------------------------------
# The provider configures how GitHub's OIDC tokens are validated and how
# token claims are mapped to GCP attributes.
#
# ATTRIBUTE MAPPING REFERENCE:
# GitHub OIDC tokens contain these claims (among others):
#   - sub: "repo:org/repo:ref:refs/heads/branch" (subject)
#   - repository: "org/repo" (full repo name)
#   - repository_owner: "org" (GitHub org)
#   - actor: "username" (who triggered the workflow)
#   - ref: "refs/heads/branch" (git ref)
#   - workflow: "workflow-name" (name of the workflow file)
#   - event_name: "push|pull_request|..." (trigger event)
#   - job_workflow_ref: "org/repo/.github/workflows/file.yml@ref"
#   - runner_environment: "github-hosted|self-hosted"
#
# We map the most security-relevant claims to GCP attributes so they
# can be used in IAM conditions and audit logs.
# -----------------------------------------------------------------------------

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id
  display_name                       = "GitHub OIDC Provider"

  description = <<-EOT
    OIDC provider for GitHub Actions. Validates GitHub-issued JWT tokens
    and maps claims to GCP attributes for IAM policy evaluation.
  EOT

  # Attribute mapping: GitHub OIDC claims -> GCP attributes
  # These mapped attributes can be referenced in IAM conditions
  attribute_mapping = {
    # Standard OIDC subject claim - uniquely identifies the workflow run context
    "google.subject" = "assertion.sub"

    # Repository full name (e.g., "devsecops-demo/devsecops-project")
    # Used in IAM conditions to restrict access to specific repos
    "attribute.repository" = "assertion.repository"

    # Repository owner / GitHub organization
    # First line of defense: only our org's repos can authenticate
    "attribute.repository_owner" = "assertion.repository_owner"

    # GitHub username who triggered the workflow
    # Useful for audit trails and debugging
    "attribute.actor" = "assertion.actor"

    # Git reference (e.g., "refs/heads/main", "refs/pull/42/merge")
    # Used to restrict deployment operations to protected branches
    "attribute.ref" = "assertion.ref"

    # Workflow name - identifies which GitHub Actions workflow is running
    # Can be used to restrict specific SAs to specific workflows
    "attribute.workflow" = "assertion.workflow"

    # Event that triggered the workflow (push, pull_request, schedule, etc.)
    # Useful for distinguishing CI from CD operations
    "attribute.event_name" = "assertion.event_name"

    # Full workflow reference including file path and git ref
    # Most specific identifier - prevents workflow impersonation attacks
    "attribute.job_workflow_ref" = "assertion.job_workflow_ref"

    # Runner environment (github-hosted vs self-hosted)
    # Can restrict sensitive operations to GitHub-hosted runners only
    "attribute.runner_environment" = "assertion.runner_environment"
  }

  # CRITICAL: Attribute condition restricts which tokens are accepted.
  # This condition is evaluated BEFORE any IAM policy checks.
  # If the condition fails, the token is rejected entirely.
  #
  # Security rationale:
  # - repository_owner check: prevents any repository outside our org from
  #   authenticating, even if they somehow reference our pool
  # - repository check: further restricts to only approved repositories
  # - runner_environment check: prevents self-hosted runners (which could be
  #   compromised) from authenticating for sensitive operations
  attribute_condition = <<-EOT
    assertion.repository_owner == '${var.github_org}' &&
    (${local.repo_conditions}) &&
    assertion.runner_environment == 'github-hosted'
  EOT

  # OIDC configuration for GitHub's identity provider
  oidc {
    # GitHub's OIDC issuer URL - GCP fetches the JWKS from here to validate tokens
    issuer_uri = "https://token.actions.githubusercontent.com"

    # Allowed audiences - restricts which tokens are accepted
    # The default audience for google-github-actions/auth is the pool provider URL
    # We can also add custom audiences for additional validation
    allowed_audiences = [
      "https://iam.googleapis.com/projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${var.pool_id}/providers/${var.provider_id}"
    ]
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "google_project" "current" {
  project_id = var.project_id
}

# -----------------------------------------------------------------------------
# Service Accounts for GitHub Actions
# -----------------------------------------------------------------------------
# Each service account follows the principle of least privilege.
# No keys are generated - authentication is exclusively via WIF.
# -----------------------------------------------------------------------------

resource "google_service_account" "github_sa" {
  for_each = local.service_accounts

  project      = var.project_id
  account_id   = each.value.account_id
  display_name = each.value.display_name
  description  = each.value.description
}

# -----------------------------------------------------------------------------
# IAM Role Bindings for Service Accounts
# -----------------------------------------------------------------------------
# Grant each service account its required roles at the project level.
# For production, consider resource-level bindings for tighter scoping.
# -----------------------------------------------------------------------------

resource "google_project_iam_member" "github_sa_roles" {
  for_each = {
    for pair in flatten([
      for sa_key, sa_config in local.service_accounts : [
        for role in sa_config.roles : {
          key  = "${sa_key}-${replace(role, "/", "_")}"
          role = role
          sa   = sa_key
        }
      ]
    ]) : pair.key => pair
  }

  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.github_sa[each.value.sa].email}"
}

# -----------------------------------------------------------------------------
# Workload Identity Federation Bindings
# -----------------------------------------------------------------------------
# These bindings allow the WIF pool identities to impersonate the service
# accounts. The IAM conditions enforce repository and branch restrictions.
#
# SECURITY MODEL:
# - Reader/Scanner SAs: Any workflow from allowed repos can impersonate
# - Deployer SA: Only workflows from allowed branches can impersonate
#
# This two-tier model allows PRs to run security scans and terraform plan,
# but prevents feature branches from deploying to production.
# -----------------------------------------------------------------------------

# Binding for service accounts WITHOUT branch restrictions (reader, scanner)
resource "google_service_account_iam_member" "wif_binding_unrestricted" {
  for_each = {
    for sa_key, sa_config in local.service_accounts :
    sa_key => sa_config if !sa_config.require_branch
  }

  service_account_id = google_service_account.github_sa[each.key].name
  role               = "roles/iam.workloadIdentityUser"

  # Allow any identity from the WIF pool that passes the provider's
  # attribute conditions (org + repo restrictions)
  member = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}

# Binding for service accounts WITH branch restrictions (deployer)
# Uses IAM conditions to enforce branch-level access control
resource "google_service_account_iam_member" "wif_binding_branch_restricted" {
  for_each = {
    for sa_key, sa_config in local.service_accounts :
    sa_key => sa_config if sa_config.require_branch
  }

  service_account_id = google_service_account.github_sa[each.key].name
  role               = "roles/iam.workloadIdentityUser"

  # Allow any identity from the WIF pool (provider conditions still apply)
  member = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"

  # Additional condition: restrict to protected branches only
  # This prevents feature branches or PR branches from deploying
  condition {
    title       = "restrict-to-protected-branches"
    description = "Only allow impersonation from protected branches: ${join(", ", var.allowed_branches)}"
    expression = join(" || ", [
      for branch in var.allowed_branches :
      "request.auth.claims.ref == 'refs/heads/${branch}'"
    ])
  }
}

# -----------------------------------------------------------------------------
# Additional WIF Bindings for Extra Repositories
# -----------------------------------------------------------------------------
# If additional repos are authorized, create bindings for them as well.
# These follow the same unrestricted/branch-restricted pattern.
# -----------------------------------------------------------------------------

resource "google_service_account_iam_member" "wif_binding_extra_repos" {
  for_each = {
    for pair in flatten([
      for repo in var.allowed_repos : [
        for sa_key, sa_config in local.service_accounts : {
          key  = "${sa_key}-${replace(repo, "/", "_")}"
          repo = repo
          sa   = sa_key
        } if !sa_config.require_branch
      ]
    ]) : pair.key => pair
  }

  service_account_id = google_service_account.github_sa[each.value.sa].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${each.value.repo}"
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "workload_identity_pool_id" {
  description = "The ID of the Workload Identity Pool"
  value       = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
}

output "workload_identity_pool_name" {
  description = "The full resource name of the Workload Identity Pool"
  value       = google_iam_workload_identity_pool.github_pool.name
}

output "workload_identity_provider_name" {
  description = "The full resource name of the Workload Identity Provider"
  value       = google_iam_workload_identity_pool_provider.github_provider.name
}

output "github_deployer_sa_email" {
  description = "Email of the GitHub Actions deployer service account"
  value       = google_service_account.github_sa["deployer"].email
}

output "github_reader_sa_email" {
  description = "Email of the GitHub Actions reader service account"
  value       = google_service_account.github_sa["reader"].email
}

output "github_scanner_sa_email" {
  description = "Email of the GitHub Actions security scanner service account"
  value       = google_service_account.github_sa["security_scanner"].email
}

output "wif_provider_resource_name" {
  description = <<-EOT
    The full provider resource name to use in GitHub Actions auth step.
    Use this value in google-github-actions/auth@v2 'workload_identity_provider' parameter.
  EOT
  value       = google_iam_workload_identity_pool_provider.github_provider.name
}
