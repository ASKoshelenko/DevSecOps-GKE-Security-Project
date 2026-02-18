# =============================================================================
# Terraform Backend Configuration
# =============================================================================
#
# State is stored in a GCS bucket. In the attack scenario, the attacker
# targets this backend to either:
#   1. Read the state (contains sensitive resource attributes)
#   2. Modify the state (inject backdoor resources)
#   3. Replace the backend entirely (redirect state to attacker's server)
#
# Security notes:
#   - The state bucket should have versioning enabled for recovery
#   - Object-level ACLs should be disabled (uniform bucket-level access)
#   - Access should be restricted to the CI service account only
#   - State encryption should use a CMEK (Customer-Managed Encryption Key)
#   - State bucket should have Object Lock for immutability (where supported)
# =============================================================================

terraform {
  backend "gcs" {
    # The bucket name is typically provided via -backend-config during init
    # to keep it environment-specific. Hardcoded here for demonstration.
    bucket = "my-production-project-tf-state"
    prefix = "terraform/state"

    # Note: Authentication is handled by the environment (GOOGLE_CREDENTIALS
    # or Application Default Credentials). In the CI pipeline, this comes
    # from the Workload Identity Federation token.
  }
}
