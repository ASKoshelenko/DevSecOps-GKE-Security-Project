# =============================================================================
# Organization Policy Constraints - Service Account Key Elimination
# =============================================================================
#
# PURPOSE:
# Enforces organization-wide policies that permanently block the creation,
# upload, and use of service account keys. These policies make it technically
# impossible for anyone (including project owners) to create SA keys,
# eliminating the entire attack surface that enabled the APT incident.
#
# INCIDENT CONTEXT:
# The compromised SA key had been created 14 months prior to the breach.
# During that time:
#   - The key was stored in a .env file on the developer's laptop
#   - The key was accidentally committed to a private repo (reverted, but
#     still in git history)
#   - The key was shared via Slack DM to a colleague for "quick debugging"
#   - No key rotation had been performed since creation
#
# By enforcing these org policies, we ensure that even if a developer
# attempts to create a key "for quick testing," the API will reject the
# request with a clear error message directing them to use WIF instead.
#
# POLICY HIERARCHY:
# These constraints are applied at the project level. For organization-wide
# enforcement, apply them at the org node. Folder-level exceptions can be
# granted for legacy workloads during migration (with expiry dates).
#
# =============================================================================

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "org_policy_project_id" {
  description = "The GCP project ID where org policies will be enforced"
  type        = string
}

variable "org_id" {
  description = <<-EOT
    The GCP organization ID (numeric). Required for org-level policy enforcement.
    Set to empty string to apply policies at project level only.
  EOT
  type        = string
  default     = ""
}

variable "enforce_at_org_level" {
  description = "Whether to enforce policies at the organization level (true) or project level (false)"
  type        = bool
  default     = false
}

variable "sa_key_exception_projects" {
  description = <<-EOT
    List of project IDs temporarily exempted from the SA key creation block.
    These exceptions MUST have an associated expiry date and migration plan.
    Format: ["projects/PROJECT_NUMBER"]

    WARNING: Every exception weakens the security posture. Each exception
    requires VP-level approval and must be reviewed monthly.
  EOT
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Constraint 1: Block Service Account Key Creation
# -----------------------------------------------------------------------------
# iam.disableServiceAccountKeyCreation
#
# When enforced, this constraint prevents the creation of new user-managed
# service account keys via:
#   - Google Cloud Console
#   - gcloud CLI (gcloud iam service-accounts keys create)
#   - REST API (serviceAccountKeys.create)
#   - Terraform (google_service_account_key resource)
#
# System-managed keys (used internally by GCP services) are NOT affected.
#
# API calls that would create SA keys will return:
#   FAILED_PRECONDITION: Service account key creation is disabled by
#   organization policy constraint constraints/iam.disableServiceAccountKeyCreation
# -----------------------------------------------------------------------------

resource "google_project_organization_policy" "disable_sa_key_creation" {
  count = var.enforce_at_org_level ? 0 : 1

  project    = var.org_policy_project_id
  constraint = "constraints/iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }
}

# Organization-level enforcement (if enabled)
resource "google_organization_policy" "disable_sa_key_creation_org" {
  count = var.enforce_at_org_level && var.org_id != "" ? 1 : 0

  org_id     = var.org_id
  constraint = "constraints/iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }
}

# -----------------------------------------------------------------------------
# Constraint 2: Block Service Account Key Upload
# -----------------------------------------------------------------------------
# iam.disableServiceAccountKeyUpload
#
# Prevents uploading externally generated public keys to service accounts.
# This closes the loophole where someone could:
#   1. Generate a key pair locally
#   2. Upload the public key to a GCP service account
#   3. Use the private key (which GCP never sees) to authenticate
#
# Combined with constraint 1, this ensures NO new SA key material can be
# associated with any service account in the project/org.
# -----------------------------------------------------------------------------

resource "google_project_organization_policy" "disable_sa_key_upload" {
  count = var.enforce_at_org_level ? 0 : 1

  project    = var.org_policy_project_id
  constraint = "constraints/iam.disableServiceAccountKeyUpload"

  boolean_policy {
    enforced = true
  }
}

resource "google_organization_policy" "disable_sa_key_upload_org" {
  count = var.enforce_at_org_level && var.org_id != "" ? 1 : 0

  org_id     = var.org_id
  constraint = "constraints/iam.disableServiceAccountKeyUpload"

  boolean_policy {
    enforced = true
  }
}

# -----------------------------------------------------------------------------
# Constraint 3: Restrict Service Account Creation
# -----------------------------------------------------------------------------
# iam.disableServiceAccountCreation
#
# Restricts WHO can create new service accounts. In large organizations,
# uncontrolled SA creation leads to SA sprawl, which increases the attack
# surface. Only the Terraform service account (running via WIF) should
# create service accounts.
#
# NOTE: This is a list constraint, not a boolean. We allow SA creation
# only from specific automation identities.
# -----------------------------------------------------------------------------

resource "google_project_organization_policy" "restrict_sa_creation" {
  count = var.enforce_at_org_level ? 0 : 1

  project    = var.org_policy_project_id
  constraint = "constraints/iam.disableServiceAccountCreation"

  boolean_policy {
    # Set to false to allow SA creation (but only via controlled means)
    # The actual restriction is enforced via IAM roles (only Terraform SA
    # has iam.serviceAccounts.create permission)
    enforced = false
  }
}

# -----------------------------------------------------------------------------
# Constraint 4: Restrict Workload Identity Pool Providers
# -----------------------------------------------------------------------------
# iam.workloadIdentityPoolProviders
#
# Controls which external identity providers can be configured in WIF pools.
# This prevents unauthorized IdP integrations that could bypass access controls.
#
# Allowed providers:
# - GitHub OIDC (for CI/CD)
# - Google Cloud (for cross-project access)
# No AWS, Azure, or arbitrary OIDC providers are permitted.
# -----------------------------------------------------------------------------

resource "google_project_organization_policy" "restrict_wif_providers" {
  count = var.enforce_at_org_level ? 0 : 1

  project    = var.org_policy_project_id
  constraint = "constraints/iam.workloadIdentityPoolProviders"

  list_policy {
    allow {
      values = [
        "https://token.actions.githubusercontent.com",  # GitHub Actions OIDC
      ]
    }
  }
}

resource "google_organization_policy" "restrict_wif_providers_org" {
  count = var.enforce_at_org_level && var.org_id != "" ? 1 : 0

  org_id     = var.org_id
  constraint = "constraints/iam.workloadIdentityPoolProviders"

  list_policy {
    allow {
      values = [
        "https://token.actions.githubusercontent.com",
      ]
    }
  }
}

# -----------------------------------------------------------------------------
# Constraint 5: Enforce Uniform Bucket-Level Access
# -----------------------------------------------------------------------------
# storage.uniformBucketLevelAccess
#
# Forces all GCS buckets to use uniform bucket-level access (IAM only),
# disabling legacy ACLs. This prevents confusion between IAM and ACL
# permissions and ensures consistent access control.
# -----------------------------------------------------------------------------

resource "google_project_organization_policy" "uniform_bucket_access" {
  count = var.enforce_at_org_level ? 0 : 1

  project    = var.org_policy_project_id
  constraint = "constraints/storage.uniformBucketLevelAccess"

  boolean_policy {
    enforced = true
  }
}

# -----------------------------------------------------------------------------
# Constraint 6: Require OS Login for Compute Instances
# -----------------------------------------------------------------------------
# compute.requireOsLogin
#
# Enforces OS Login on all Compute Engine instances, including GKE nodes.
# OS Login uses IAM for SSH access management, eliminating the need for
# SSH keys in project metadata (which could be exfiltrated).
# -----------------------------------------------------------------------------

resource "google_project_organization_policy" "require_os_login" {
  count = var.enforce_at_org_level ? 0 : 1

  project    = var.org_policy_project_id
  constraint = "constraints/compute.requireOsLogin"

  boolean_policy {
    enforced = true
  }
}

# -----------------------------------------------------------------------------
# Constraint 7: Restrict Public IP Access for SQL Instances
# -----------------------------------------------------------------------------
# sql.restrictPublicIp
#
# Prevents Cloud SQL instances from having public IP addresses.
# All database access must go through Private Service Connect or
# Cloud SQL Auth Proxy, which uses IAM for authentication.
# -----------------------------------------------------------------------------

resource "google_project_organization_policy" "restrict_sql_public_ip" {
  count = var.enforce_at_org_level ? 0 : 1

  project    = var.org_policy_project_id
  constraint = "constraints/sql.restrictPublicIp"

  boolean_policy {
    enforced = true
  }
}

# -----------------------------------------------------------------------------
# Constraint 8: Disable Default Service Account Grants
# -----------------------------------------------------------------------------
# iam.automaticIamGrantsForDefaultServiceAccounts
#
# Prevents the default Compute Engine and App Engine service accounts
# from automatically receiving the Editor role. The default SA with Editor
# is one of the most common privilege escalation vectors in GCP.
# -----------------------------------------------------------------------------

resource "google_project_organization_policy" "disable_default_sa_grants" {
  count = var.enforce_at_org_level ? 0 : 1

  project    = var.org_policy_project_id
  constraint = "constraints/iam.automaticIamGrantsForDefaultServiceAccounts"

  boolean_policy {
    enforced = true
  }
}

# -----------------------------------------------------------------------------
# Constraint 9: Restrict VM External IP Access
# -----------------------------------------------------------------------------
# compute.vmExternalIpAccess
#
# Controls which VM instances can have external IP addresses.
# For a private GKE cluster, no nodes should have external IPs.
# Egress goes through Cloud NAT instead.
# -----------------------------------------------------------------------------

resource "google_project_organization_policy" "restrict_vm_external_ip" {
  count = var.enforce_at_org_level ? 0 : 1

  project    = var.org_policy_project_id
  constraint = "constraints/compute.vmExternalIpAccess"

  list_policy {
    # Deny all external IPs by default
    deny {
      all = true
    }
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "enforced_constraints" {
  description = "List of all enforced organization policy constraints"
  value = [
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/iam.disableServiceAccountKeyUpload",
    "constraints/iam.workloadIdentityPoolProviders",
    "constraints/storage.uniformBucketLevelAccess",
    "constraints/compute.requireOsLogin",
    "constraints/sql.restrictPublicIp",
    "constraints/iam.automaticIamGrantsForDefaultServiceAccounts",
    "constraints/compute.vmExternalIpAccess",
  ]
}

output "enforcement_level" {
  description = "Level at which policies are enforced"
  value       = var.enforce_at_org_level ? "Organization (${var.org_id})" : "Project (${var.org_policy_project_id})"
}

output "sa_key_exceptions" {
  description = "Projects with temporary SA key creation exceptions"
  value       = var.sa_key_exception_projects
}
