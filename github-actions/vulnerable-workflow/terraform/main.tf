# =============================================================================
# Terraform Configuration: GCS Bucket Managed by CI/CD Pipeline
# =============================================================================
#
# This is the legitimate Terraform configuration that the CI/CD pipeline
# manages. In the attack scenario, the attacker's PR modifies these files
# or adds new ones alongside them.
#
# Resources managed:
#   - GCS bucket for application data
#   - GCS bucket IAM binding
#   - Cloud Storage notification (Pub/Sub)
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# -----------------------------------------------------------------------------
# Primary Application Data Bucket
# -----------------------------------------------------------------------------

resource "google_storage_bucket" "app_data" {
  name          = "${var.project_id}-app-data"
  location      = var.region
  storage_class = "STANDARD"
  project       = var.project_id

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    environment = var.environment
    managed_by  = "terraform"
    team        = "platform"
  }
}

# -----------------------------------------------------------------------------
# Bucket IAM - Grant application service account access
# -----------------------------------------------------------------------------

resource "google_storage_bucket_iam_member" "app_data_writer" {
  bucket = google_storage_bucket.app_data.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.app_service_account}"
}

resource "google_storage_bucket_iam_member" "app_data_reader" {
  bucket = google_storage_bucket.app_data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.monitoring_service_account}"
}

# -----------------------------------------------------------------------------
# Pub/Sub Notification for Bucket Events
# -----------------------------------------------------------------------------

resource "google_pubsub_topic" "bucket_notifications" {
  name    = "app-data-bucket-notifications"
  project = var.project_id

  labels = {
    environment = var.environment
    managed_by  = "terraform"
  }
}

resource "google_storage_notification" "app_data_notification" {
  bucket         = google_storage_bucket.app_data.name
  payload_format = "JSON_API_V1"
  topic          = google_pubsub_topic.bucket_notifications.id
  event_types    = ["OBJECT_FINALIZE", "OBJECT_DELETE"]

  depends_on = [google_pubsub_topic_iam_member.gcs_publisher]
}

# Grant GCS service agent permission to publish to the topic
data "google_storage_project_service_account" "gcs_account" {
  project = var.project_id
}

resource "google_pubsub_topic_iam_member" "gcs_publisher" {
  topic   = google_pubsub_topic.bucket_notifications.id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${data.google_storage_project_service_account.gcs_account.email_address}"
  project = var.project_id
}
