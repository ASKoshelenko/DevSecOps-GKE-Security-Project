# =============================================================================
# Terraform State Backend Configuration
# =============================================================================
# Uses Google Cloud Storage (GCS) for remote state storage.
#
# SECURITY CONSIDERATIONS:
# - The state bucket has versioning enabled to allow rollback
# - State files contain sensitive data; bucket access is restricted via IAM
# - A separate prefix per environment prevents state collisions
# - Encryption at rest is enabled by default on GCS
#
# SETUP:
# Before running terraform init, create the bucket:
#   gsutil mb -p <PROJECT_ID> -l <REGION> gs://<PROJECT_ID>-terraform-state
#   gsutil versioning set on gs://<PROJECT_ID>-terraform-state
# =============================================================================

terraform {
  backend "gcs" {
    bucket = "devsecops-demo-terraform-state"
    prefix = "terraform/state"
  }
}
